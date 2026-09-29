package safety

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// scopeForServer builds an allowlist for a loopback test server. The single
// loopback address is authorised explicitly, exactly as the local testbed
// target will be -- not a whole private range.
func scopeForServer(t *testing.T, srv *httptest.Server, prefixes, methods []string) *Scope {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	s := &Scope{
		Targets: []Target{{
			Scheme: u.Scheme, Host: u.Hostname(), Port: port,
			PathPrefixes: prefixes, Methods: methods,
			AllowedAddresses: []string{"127.0.0.1/32"},
		}},
		MaxRedirects: 3,
	}
	s.Normalize()
	return s
}

func validAck(scope *Scope) *Authorization {
	return &Authorization{
		Operator:    "test-operator",
		Statement:   RequiredStatement,
		AckedAt:     time.Now(),
		ScopeDigest: scope.Digest(),
	}
}

func newTestClient(t *testing.T, scope *Scope, limits Limits) (*Client, *Governor) {
	t.Helper()
	gov, err := NewGovernor(context.Background(), limits, nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	t.Cleanup(gov.Stop)
	c, err := NewClient(ClientConfig{Scope: scope, Governor: gov, Authorization: validAck(scope)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, gov
}

func get(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

// A client cannot even be constructed without a valid acknowledgement, so no
// session can start without one.
func TestNewClientRefusesWithoutAuthorization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	scope := scopeForServer(t, srv, []string{"/"}, []string{"GET"})

	gov, err := NewGovernor(context.Background(), fastLimits(), nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	defer gov.Stop()

	if _, err := NewClient(ClientConfig{Scope: scope, Governor: gov}); !errors.Is(err, ErrNoAuthorization) {
		t.Fatalf("NewClient without ack = %v, want ErrNoAuthorization", err)
	}

	stale := validAck(scope)
	stale.AckedAt = time.Now().Add(-MaxAckAge - time.Hour)
	if _, err := NewClient(ClientConfig{Scope: scope, Governor: gov, Authorization: stale}); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("NewClient with stale ack = %v, want ErrAuthorizationInvalid", err)
	}

	mismatched := validAck(scope)
	mismatched.ScopeDigest = "sha256:something-else"
	if _, err := NewClient(ClientConfig{Scope: scope, Governor: gov, Authorization: mismatched}); !errors.Is(err, ErrAuthorizationScopeMismatch) {
		t.Fatalf("NewClient with mismatched ack = %v, want ErrAuthorizationScopeMismatch", err)
	}
}

func TestNewClientRefusesInvalidScope(t *testing.T) {
	gov, err := NewGovernor(context.Background(), fastLimits(), nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	defer gov.Stop()

	bad := &Scope{Targets: []Target{{Scheme: "http", Host: "*.local", Port: 80,
		PathPrefixes: []string{"/"}, Methods: []string{"GET"}}}}
	if _, err := NewClient(ClientConfig{Scope: bad, Governor: gov, Authorization: validAck(bad)}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewClient with wildcard host = %v, want ErrInvalidConfig", err)
	}
}

func TestClientAllowsInScopeAndRefusesOutOfScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/api"}, []string{"GET"})
	c, _ := newTestClient(t, scope, fastLimits())

	resp, err := c.Do(context.Background(), get(t, srv.URL+"/api/users"))
	if err != nil {
		t.Fatalf("in-scope request = %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(resp.Body) != "ok" {
		t.Fatalf("got status=%d body=%q", resp.StatusCode, resp.Body)
	}
	if resp.Latency <= 0 {
		t.Error("latency was not measured")
	}

	if _, err := c.Do(context.Background(), get(t, srv.URL+"/admin")); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("out-of-scope path = %v, want ErrOutOfScope", err)
	}
	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/users", strings.NewReader("{}"))
	if _, err := c.Do(context.Background(), post); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("out-of-scope method = %v, want ErrOutOfScope", err)
	}
}

// A refused request must not consume the request budget.
func TestOutOfScopeRequestDoesNotConsumeBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	scope := scopeForServer(t, srv, []string{"/api"}, []string{"GET"})
	c, gov := newTestClient(t, scope, fastLimits())

	for i := 0; i < 5; i++ {
		_, _ = c.Do(context.Background(), get(t, srv.URL+"/admin"))
	}
	if used := gov.Stats().RequestsUsed; used != 0 {
		t.Fatalf("RequestsUsed = %d after refused requests, want 0", used)
	}
}

func TestClientFollowsInScopeRedirectAndRefusesOutOfScopeRedirect(t *testing.T) {
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should never be reached"))
	}))
	defer external.Close()

	var target *httptest.Server
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/inside":
			http.Redirect(w, r, target.URL+"/api/landing", http.StatusFound)
		case "/api/landing":
			w.Write([]byte("landed"))
		case "/api/outside":
			http.Redirect(w, r, external.URL+"/", http.StatusFound)
		case "/api/escape":
			// Redirect to a path that is in the allowlist's host but not its prefixes.
			http.Redirect(w, r, target.URL+"/admin", http.StatusFound)
		}
	}))
	defer target.Close()

	scope := scopeForServer(t, target, []string{"/api"}, []string{"GET"})
	c, _ := newTestClient(t, scope, fastLimits())

	resp, err := c.Do(context.Background(), get(t, target.URL+"/api/inside"))
	if err != nil {
		t.Fatalf("in-scope redirect = %v, want it followed", err)
	}
	if string(resp.Body) != "landed" {
		t.Fatalf("body = %q, want %q", resp.Body, "landed")
	}

	if _, err := c.Do(context.Background(), get(t, target.URL+"/api/outside")); !errors.Is(err, ErrRedirectOutOfScope) {
		t.Fatalf("redirect to another host = %v, want ErrRedirectOutOfScope", err)
	}
	if _, err := c.Do(context.Background(), get(t, target.URL+"/api/escape")); !errors.Is(err, ErrRedirectOutOfScope) {
		t.Fatalf("redirect to an out-of-prefix path = %v, want ErrRedirectOutOfScope", err)
	}
}

func TestClientCapsRedirectChain(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/api/loop", http.StatusFound)
	}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/api"}, []string{"GET"})
	c, _ := newTestClient(t, scope, fastLimits())

	if _, err := c.Do(context.Background(), get(t, srv.URL+"/api/loop")); !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("redirect loop = %v, want ErrTooManyRedirects", err)
	}
}

func TestClientCapsResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 100_000)))
	}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/"}, []string{"GET"})
	limits := fastLimits()
	limits.MaxResponseBytes = 512
	c, _ := newTestClient(t, scope, limits)

	resp, err := c.Do(context.Background(), get(t, srv.URL+"/big"))
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	if !resp.Truncated {
		t.Error("Truncated = false, want true")
	}
	if len(resp.Body) != 512 {
		t.Fatalf("body length = %d, want 512", len(resp.Body))
	}
}

func TestClientEnforcesPerRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/"}, []string{"GET"})
	limits := fastLimits()
	limits.RequestTimeout = Duration(150 * time.Millisecond)
	c, _ := newTestClient(t, scope, limits)

	start := time.Now()
	_, err := c.Do(context.Background(), get(t, srv.URL+"/slow"))
	if err == nil {
		t.Fatal("slow request returned no error, want a timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("request took %v to time out, want ~150ms", elapsed)
	}
}

// The kill switch must cut requests that are already in flight.
func TestClientStopCutsInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(3 * time.Second)
	}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/"}, []string{"GET"})
	limits := fastLimits()
	limits.RequestTimeout = Duration(10 * time.Second)
	c, gov := newTestClient(t, scope, limits)

	result := make(chan error, 1)
	go func() {
		_, err := c.Do(context.Background(), get(t, srv.URL+"/hang"))
		result <- err
	}()

	<-started
	stopAt := time.Now()
	gov.Stop()

	select {
	case err := <-result:
		if !errors.Is(err, ErrSessionStopped) {
			t.Fatalf("in-flight request = %v, want ErrSessionStopped", err)
		}
		if elapsed := time.Since(stopAt); elapsed > time.Second {
			t.Fatalf("request took %v to abort after Stop(), want < 1s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request was not cut within 2s of Stop()")
	}
}

func TestClientEnforcesTotalBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/"}, []string{"GET"})
	limits := fastLimits()
	limits.MaxTotalRequests = 2
	c, _ := newTestClient(t, scope, limits)

	for i := 0; i < 2; i++ {
		if _, err := c.Do(context.Background(), get(t, srv.URL+"/x")); err != nil {
			t.Fatalf("request %d = %v", i, err)
		}
	}
	if _, err := c.Do(context.Background(), get(t, srv.URL+"/x")); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("request past budget = %v, want ErrBudgetExhausted", err)
	}
}
