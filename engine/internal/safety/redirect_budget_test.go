package safety

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A redirect hop is a real request and must be charged like one. With a total
// budget of 1, the initial request is sent and the redirect is refused, so the
// target never receives a second request.
func TestRedirectHopIsChargedAgainstTotalBudget(t *testing.T) {
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/api/one" {
			http.Redirect(w, r, srv.URL+"/api/two", http.StatusFound)
			return
		}
		w.Write([]byte("second hop reached"))
	}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/api"}, []string{"GET"})
	limits := fastLimits()
	limits.MaxTotalRequests = 1
	c, gov := newTestClient(t, scope, limits)

	_, err := c.Do(context.Background(), get(t, srv.URL+"/api/one"))
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("redirect past a budget of 1 = %v, want ErrBudgetExhausted", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("target received %d requests, want exactly 1: the redirect was sent outside the budget", got)
	}
	if used := gov.Stats().RequestsUsed; used != 1 {
		t.Fatalf("RequestsUsed = %d, want 1", used)
	}
}

// With enough budget the redirect is followed, and both hops are counted.
func TestRedirectHopsAreCountedWhenBudgetAllows(t *testing.T) {
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/api/one" {
			http.Redirect(w, r, srv.URL+"/api/two", http.StatusFound)
			return
		}
		w.Write([]byte("landed"))
	}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/api"}, []string{"GET"})
	limits := fastLimits()
	limits.MaxTotalRequests = 2
	c, gov := newTestClient(t, scope, limits)

	resp, err := c.Do(context.Background(), get(t, srv.URL+"/api/one"))
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	if string(resp.Body) != "landed" {
		t.Fatalf("body = %q, want %q", resp.Body, "landed")
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("target received %d requests, want 2", got)
	}
	if used := gov.Stats().RequestsUsed; used != 2 {
		t.Fatalf("RequestsUsed = %d, want 2 (one per hop)", used)
	}
	// The budget is now spent; a further request must be refused.
	if _, err := c.Do(context.Background(), get(t, srv.URL+"/api/two")); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("request after the redirect chain = %v, want ErrBudgetExhausted", err)
	}
}

// Redirect hops are rate-limited too, so a redirect chain cannot burst past
// the configured requests-per-second.
func TestRedirectHopsAreRateLimited(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/one":
			http.Redirect(w, r, srv.URL+"/api/two", http.StatusFound)
		case "/api/two":
			http.Redirect(w, r, srv.URL+"/api/three", http.StatusFound)
		default:
			w.Write([]byte("done"))
		}
	}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/api"}, []string{"GET"})
	limits := fastLimits()
	limits.RequestsPerSecond = 20
	limits.Burst = 1
	c, _ := newTestClient(t, scope, limits)

	start := time.Now()
	if _, err := c.Do(context.Background(), get(t, srv.URL+"/api/one")); err != nil {
		t.Fatalf("Do() = %v", err)
	}
	// 3 round trips: 1 burst token plus 2 refills at 20/s = at least 100ms.
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("a 3-hop chain took %v, want >= 80ms: hops are not rate-limited", elapsed)
	}
}

// max_concurrency must not deadlock a redirect chain: the slot is released
// when each hop's body is closed, before the next hop is issued.
func TestRedirectChainDoesNotDeadlockAtConcurrencyOne(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/one" {
			http.Redirect(w, r, srv.URL+"/api/two", http.StatusFound)
			return
		}
		w.Write([]byte("landed"))
	}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/api"}, []string{"GET"})
	limits := fastLimits()
	limits.MaxConcurrency = 1
	c, _ := newTestClient(t, scope, limits)

	done := make(chan error, 1)
	go func() {
		_, err := c.Do(context.Background(), get(t, srv.URL+"/api/one"))
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Do() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("redirect chain deadlocked at max_concurrency=1")
	}
}

// An out-of-scope redirect must be refused before it is sent, so it never
// reaches the other host at all.
func TestOutOfScopeRedirectIsNotSent(t *testing.T) {
	var externalHits atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalHits.Add(1)
	}))
	defer external.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, external.URL+"/", http.StatusFound)
	}))
	defer srv.Close()

	scope := scopeForServer(t, srv, []string{"/api"}, []string{"GET"})
	c, _ := newTestClient(t, scope, fastLimits())

	if _, err := c.Do(context.Background(), get(t, srv.URL+"/api/go")); !errors.Is(err, ErrRedirectOutOfScope) {
		t.Fatalf("Do() = %v, want ErrRedirectOutOfScope", err)
	}
	if got := externalHits.Load(); got != 0 {
		t.Fatalf("the out-of-scope host received %d requests, want 0", got)
	}
}
