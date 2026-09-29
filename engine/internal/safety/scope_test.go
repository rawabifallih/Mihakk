package safety

import (
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
)

func testScope() *Scope {
	s := &Scope{
		Targets: []Target{{
			Scheme:       "http",
			Host:         "app.local",
			Port:         8080,
			PathPrefixes: []string{"/api", "/health"},
			Methods:      []string{"GET", "POST"},
		}},
		MaxRedirects: 3,
	}
	s.Normalize()
	return s
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestScopeAllowsInScopeRequests(t *testing.T) {
	s := testScope()
	for _, raw := range []string{
		"http://app.local:8080/api",
		"http://app.local:8080/api/users?q=1",
		"http://APP.LOCAL:8080/api/users",
		"http://app.local.:8080/health",
	} {
		if _, err := s.Check("GET", mustURL(t, raw)); err != nil {
			t.Errorf("Check(GET, %s) = %v, want allowed", raw, err)
		}
	}
}

func TestScopeRejectsOutOfScopeDestinations(t *testing.T) {
	s := testScope()
	cases := []struct{ name, method, raw string }{
		{"other host", "GET", "http://evil.local:8080/api"},
		{"other port", "GET", "http://app.local:9090/api"},
		{"other scheme", "GET", "https://app.local:8080/api"},
		{"method not allowed", "DELETE", "http://app.local:8080/api"},
		{"path outside prefix", "GET", "http://app.local:8080/admin"},
		{"prefix is not a substring match", "GET", "http://app.local:8080/apikeys"},
		{"dot-dot traversal escapes prefix", "GET", "http://app.local:8080/api/../admin"},
		{"encoded traversal escapes prefix", "GET", "http://app.local:8080/api/%2e%2e/admin"},
		{"credentials in url", "GET", "http://user:pw@app.local:8080/api"},
		{"no host", "GET", "/api/users"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Check(tc.method, mustURL(t, tc.raw)); !errors.Is(err, ErrOutOfScope) {
				t.Fatalf("Check(%s, %s) = %v, want ErrOutOfScope", tc.method, tc.raw, err)
			}
		})
	}
}

func TestScopeValidateRejectsUnenforceableConfigs(t *testing.T) {
	cases := []struct {
		name  string
		scope Scope
	}{
		{"no targets", Scope{}},
		{"wildcard host", Scope{Targets: []Target{{Scheme: "http", Host: "*.local", Port: 80, PathPrefixes: []string{"/"}, Methods: []string{"GET"}}}}},
		{"empty host", Scope{Targets: []Target{{Scheme: "http", Host: "", Port: 80, PathPrefixes: []string{"/"}, Methods: []string{"GET"}}}}},
		{"bad scheme", Scope{Targets: []Target{{Scheme: "ftp", Host: "a.local", Port: 21, PathPrefixes: []string{"/"}, Methods: []string{"GET"}}}}},
		{"no prefixes", Scope{Targets: []Target{{Scheme: "http", Host: "a.local", Port: 80, Methods: []string{"GET"}}}}},
		{"no methods", Scope{Targets: []Target{{Scheme: "http", Host: "a.local", Port: 80, PathPrefixes: []string{"/"}}}}},
		{"host with path", Scope{Targets: []Target{{Scheme: "http", Host: "a.local/x", Port: 80, PathPrefixes: []string{"/"}, Methods: []string{"GET"}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.scope
			s.Normalize()
			if err := s.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate() = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestScopeDigestIsOrderIndependentButContentSensitive(t *testing.T) {
	a := Scope{Targets: []Target{{
		Scheme: "http", Host: "app.local", Port: 8080,
		PathPrefixes: []string{"/health", "/api"}, Methods: []string{"POST", "GET"},
	}}, MaxRedirects: 3}
	b := Scope{Targets: []Target{{
		Scheme: "HTTP", Host: "APP.local", Port: 8080,
		PathPrefixes: []string{"/api/", "/health"}, Methods: []string{"get", "post"},
	}}, MaxRedirects: 3}

	if a.Digest() != b.Digest() {
		t.Fatalf("equivalent scopes produced different digests:\n a=%s\n b=%s", a.Digest(), b.Digest())
	}

	c := a
	c.Targets = append([]Target{}, a.Targets...)
	c.Targets[0].PathPrefixes = []string{"/api", "/health", "/admin"}
	if a.Digest() == c.Digest() {
		t.Fatal("widening the scope did not change the digest")
	}
}

func TestScopeRootPrefixMatchesEverything(t *testing.T) {
	s := &Scope{Targets: []Target{{
		Scheme: "http", Host: "app.local", Port: 80,
		PathPrefixes: []string{"/"}, Methods: []string{"GET"},
	}}}
	s.Normalize()
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if _, err := s.Check("GET", mustURL(t, "http://app.local/anything/deep")); err != nil {
		t.Fatalf("Check() = %v, want allowed", err)
	}
}

func TestScopeDefaultPortInference(t *testing.T) {
	s := &Scope{Targets: []Target{{
		Scheme: "https", Host: "app.local",
		PathPrefixes: []string{"/api"}, Methods: []string{"GET"},
	}}}
	s.Normalize()
	if got := s.Targets[0].Port; got != 443 {
		t.Fatalf("inferred port = %d, want 443", got)
	}
	if _, err := s.Check("GET", mustURL(t, "https://app.local/api/x")); err != nil {
		t.Fatalf("Check() = %v, want allowed", err)
	}
}

// Digest must not modify the scope it is asked about.
//
// It normalises before hashing, and it used to do so through a shallow copy
// that shared the Targets backing array: asking for the digest rewrote the
// caller's scope, and two goroutines asking at once raced.
func TestDigestDoesNotMutateTheScope(t *testing.T) {
	s := &Scope{Targets: []Target{{
		Scheme: "HTTP", Host: "APP.local", Port: 8080,
		PathPrefixes: []string{"/health", "/api/"}, Methods: []string{"post", "get"},
		AllowedAddresses: []string{"127.0.0.1"},
	}}}

	before := fmt.Sprintf("%+v", *s)
	_ = s.Digest()
	if after := fmt.Sprintf("%+v", *s); after != before {
		t.Fatalf("Digest changed the scope:\n before: %s\n after:  %s", before, after)
	}
}

func TestDigestIsSafeForConcurrentUse(t *testing.T) {
	s := testScope()
	want := s.Digest()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := s.Digest(); got != want {
				t.Errorf("concurrent Digest = %s, want %s", got, want)
			}
		}()
	}
	wg.Wait()
}
