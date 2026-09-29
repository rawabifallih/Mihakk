package safety

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// tlsScope builds an allowlist for an https test server on loopback.
func tlsScope(t *testing.T, srv *httptest.Server, prefixes, methods []string) *Scope {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	if u.Scheme != "https" {
		t.Fatalf("expected an https test server, got %s", u.Scheme)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	s := &Scope{
		Targets: []Target{{
			Scheme: "https", Host: u.Hostname(), Port: port,
			PathPrefixes: prefixes, Methods: methods,
			AllowedAddresses: []string{"127.0.0.1/32"},
		}},
		MaxRedirects: 3,
	}
	s.Normalize()
	return s
}

func poolFor(servers ...*httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	return pool
}

func newTLSClient(t *testing.T, scope *Scope, limits Limits, pool *x509.CertPool) (*Client, *Governor) {
	t.Helper()
	gov, err := NewGovernor(context.Background(), limits, nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	t.Cleanup(gov.Stop)
	c, err := NewClient(ClientConfig{
		Scope: scope, Governor: gov,
		Authorization: validAck(scope),
		TLSRootCAs:    pool,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, gov
}

// The guarded path works over TLS: address pinning, scope checks and limits
// all apply to an https target.
func TestHTTPSRequestThroughGuardedClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("handler received a non-TLS connection")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure ok"))
	}))
	defer srv.Close()

	scope := tlsScope(t, srv, []string{"/api"}, []string{"GET"})
	c, _ := newTLSClient(t, scope, fastLimits(), poolFor(srv))

	resp, err := c.Do(context.Background(), get(t, srv.URL+"/api/items"))
	if err != nil {
		t.Fatalf("https request = %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(resp.Body) != "secure ok" {
		t.Fatalf("got status=%d body=%q", resp.StatusCode, resp.Body)
	}
}

// Certificate verification is never disabled: without a trust anchor the
// handshake fails rather than silently proceeding.
func TestHTTPSVerificationIsNotSkippable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	scope := tlsScope(t, srv, []string{"/api"}, []string{"GET"})
	c, _ := newTestClient(t, scope, fastLimits()) // no TLSRootCAs

	_, err := c.Do(context.Background(), get(t, srv.URL+"/api/items"))
	if err == nil {
		t.Fatal("request to an untrusted certificate succeeded; verification must not be skipped")
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	if !errors.As(err, &unknownAuthority) && !errors.As(err, &hostnameErr) {
		t.Logf("note: failure was %v", err)
	}
}

func TestHTTPSScopeAndPathChecksApply(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	scope := tlsScope(t, srv, []string{"/api"}, []string{"GET"})
	c, _ := newTLSClient(t, scope, fastLimits(), poolFor(srv))

	if _, err := c.Do(context.Background(), get(t, srv.URL+"/admin")); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("out-of-scope https path = %v, want ErrOutOfScope", err)
	}
	// The same host over plain http is a different target and is not allowed.
	httpURL := "http://" + srv.Listener.Addr().String() + "/api/items"
	if _, err := c.Do(context.Background(), get(t, httpURL)); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("http against an https-only target = %v, want ErrOutOfScope", err)
	}
}

func TestHTTPSFollowsInScopeRedirect(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/start":
			http.Redirect(w, r, srv.URL+"/api/landing", http.StatusFound)
		case "/api/landing":
			w.Write([]byte("tls landed"))
		}
	}))
	defer srv.Close()

	scope := tlsScope(t, srv, []string{"/api"}, []string{"GET"})
	c, gov := newTLSClient(t, scope, fastLimits(), poolFor(srv))

	resp, err := c.Do(context.Background(), get(t, srv.URL+"/api/start"))
	if err != nil {
		t.Fatalf("https redirect = %v, want it followed", err)
	}
	if string(resp.Body) != "tls landed" {
		t.Fatalf("body = %q, want %q", resp.Body, "tls landed")
	}
	if used := gov.Stats().RequestsUsed; used != 2 {
		t.Fatalf("RequestsUsed = %d, want 2 (both https hops charged)", used)
	}
}

// A redirect that leaves the allowlist is refused over TLS too, and the other
// server is never contacted.
func TestHTTPSRefusesOutOfScopeRedirect(t *testing.T) {
	var externalHits atomic.Int32
	external := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalHits.Add(1)
	}))
	defer external.Close()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, external.URL+"/", http.StatusFound)
	}))
	defer srv.Close()

	scope := tlsScope(t, srv, []string{"/api"}, []string{"GET"})
	c, _ := newTLSClient(t, scope, fastLimits(), poolFor(srv, external))

	if _, err := c.Do(context.Background(), get(t, srv.URL+"/api/go")); !errors.Is(err, ErrRedirectOutOfScope) {
		t.Fatalf("https redirect off-allowlist = %v, want ErrRedirectOutOfScope", err)
	}
	if got := externalHits.Load(); got != 0 {
		t.Fatalf("the out-of-scope https host received %d requests, want 0", got)
	}
}

func TestHTTPSRedirectHopIsChargedAgainstBudget(t *testing.T) {
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/api/one" {
			http.Redirect(w, r, srv.URL+"/api/two", http.StatusFound)
			return
		}
		w.Write([]byte("second"))
	}))
	defer srv.Close()

	scope := tlsScope(t, srv, []string{"/api"}, []string{"GET"})
	limits := fastLimits()
	limits.MaxTotalRequests = 1
	c, _ := newTLSClient(t, scope, limits, poolFor(srv))

	_, err := c.Do(context.Background(), get(t, srv.URL+"/api/one"))
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("https redirect past a budget of 1 = %v, want ErrBudgetExhausted", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("target received %d https requests, want exactly 1", got)
	}
}

// The address allowlist governs https exactly as it governs http.
func TestHTTPSRefusesUnauthorisedAddress(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	scope := tlsScope(t, srv, []string{"/api"}, []string{"GET"})
	// Authorise a different loopback address than the one the server is on.
	scope.Targets[0].AllowedAddresses = []string{"127.0.0.9/32"}
	scope.Normalize()

	gov, err := NewGovernor(context.Background(), fastLimits(), nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	defer gov.Stop()
	c, err := NewClient(ClientConfig{
		Scope: scope, Governor: gov,
		Authorization: validAck(scope),
		TLSRootCAs:    poolFor(srv),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := c.Do(context.Background(), get(t, srv.URL+"/api/items")); !errors.Is(err, ErrDisallowedAddress) {
		t.Fatalf("https to an unauthorised address = %v, want ErrDisallowedAddress", err)
	}
}

func TestHTTPSRespectsRequestTimeout(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	scope := tlsScope(t, srv, []string{"/api"}, []string{"GET"})
	limits := fastLimits()
	limits.RequestTimeout = Duration(150 * time.Millisecond)
	c, _ := newTLSClient(t, scope, limits, poolFor(srv))

	start := time.Now()
	if _, err := c.Do(context.Background(), get(t, srv.URL+"/api/slow")); err == nil {
		t.Fatal("slow https request returned no error, want a timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("https request took %v to time out, want ~150ms", elapsed)
	}
}
