package safety

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRedactHeadersRemovesCredentialsKeepsContext(t *testing.T) {
	r := NewRedactor("x-internal-trace")
	h := http.Header{}
	h.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij")
	h.Set("Cookie", "session=deadbeefdeadbeef")
	h.Set("X-Api-Key", "super-secret-value")
	h.Set("X-Internal-Trace", "trace-secret")
	h.Set("User-Agent", "mihakk/0.1")
	h.Set("Content-Type", "application/json")

	out := r.Headers(h)

	for _, name := range []string{"Authorization", "Cookie", "X-Api-Key", "X-Internal-Trace"} {
		if got := out.Get(name); got != Placeholder {
			t.Errorf("%s = %q, want %q", name, got, Placeholder)
		}
	}
	if got := out.Get("User-Agent"); got != "mihakk/0.1" {
		t.Errorf("User-Agent = %q, want it preserved", got)
	}
	if got := out.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want it preserved", got)
	}
	// The header names survive so a reviewer can see what was sent.
	if _, ok := out["Authorization"]; !ok {
		t.Error("Authorization header name was dropped entirely; it should remain with a redacted value")
	}
	// The input must not be mutated.
	if h.Get("Authorization") == Placeholder {
		t.Error("Headers() mutated the caller's header set")
	}
}

func TestRedactURLQueryAndUserinfo(t *testing.T) {
	r := NewRedactor()
	u, err := url.Parse("https://app.local/api/items?page=2&access_token=abc123xyz&q=hello")
	if err != nil {
		t.Fatal(err)
	}
	got := r.URL(u)
	if strings.Contains(got, "abc123xyz") {
		t.Errorf("URL() = %q, still contains the token", got)
	}
	if !strings.Contains(got, "page=2") || !strings.Contains(got, "q=hello") {
		t.Errorf("URL() = %q, dropped benign parameters", got)
	}

	u2, _ := url.Parse("https://admin:hunter2@app.local/api")
	got2 := r.URL(u2)
	if strings.Contains(got2, "hunter2") {
		t.Errorf("URL() = %q, still contains userinfo credentials", got2)
	}
}

func TestRedactBodyWalksJSONByFieldName(t *testing.T) {
	r := NewRedactor()
	in := []byte(`{
		"user":"rawabi",
		"password":"hunter2",
		"nested":{"api_key":"k-123456","keep":"visible"},
		"list":[{"secret":"s1"},{"ok":"fine"}]
	}`)

	out := r.Body(in)
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("redacted body is not valid JSON: %v (%s)", err, out)
	}
	if got["password"] != Placeholder {
		t.Errorf("password = %v, want redacted", got["password"])
	}
	if got["user"] != "rawabi" {
		t.Errorf("user = %v, want preserved", got["user"])
	}
	nested := got["nested"].(map[string]any)
	if nested["api_key"] != Placeholder {
		t.Errorf("nested.api_key = %v, want redacted", nested["api_key"])
	}
	if nested["keep"] != "visible" {
		t.Errorf("nested.keep = %v, want preserved", nested["keep"])
	}
	list := got["list"].([]any)
	if list[0].(map[string]any)["secret"] != Placeholder {
		t.Errorf("list[0].secret = %v, want redacted", list[0])
	}
	if list[1].(map[string]any)["ok"] != "fine" {
		t.Errorf("list[1].ok = %v, want preserved", list[1])
	}
	if strings.Contains(string(out), "hunter2") || strings.Contains(string(out), "k-123456") {
		t.Errorf("redacted body still contains secrets: %s", out)
	}
}

func TestRedactCredentialShapedValuesInFreeText(t *testing.T) {
	r := NewRedactor()
	cases := map[string]string{
		"jwt":               "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpM",
		"bearer":            "Authorization: Bearer abcdefghijklmnop",
		"aws key":           "found AKIAIOSFODNN7EXAMPLE in the log",
		"github pat":        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"generic api token": "sk-abcdefghijklmnopqrstuvwxyz",
		"private key":       "-----BEGIN RSA PRIVATE KEY-----",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got := r.String(in)
			if !strings.Contains(got, Placeholder) {
				t.Fatalf("String(%q) = %q, want a redacted marker", in, got)
			}
		})
	}

	// Ordinary text must survive untouched, or reports become unreadable.
	plain := "GET /api/users returned 500 after 1200ms"
	if got := r.String(plain); got != plain {
		t.Fatalf("String(%q) = %q, want it unchanged", plain, got)
	}
}

func TestRedactNonJSONBodyFallsBackToPatterns(t *testing.T) {
	r := NewRedactor()
	in := []byte("error: request failed\nAuthorization: Bearer abcdefghijklmnop\n")
	out := r.Body(in)
	if strings.Contains(string(out), "abcdefghijklmnop") {
		t.Fatalf("Body() = %q, still contains the token", out)
	}
	if !strings.Contains(string(out), "error: request failed") {
		t.Fatalf("Body() = %q, dropped the useful context", out)
	}
}

func TestIsSensitiveNameNormalizesSeparators(t *testing.T) {
	r := NewRedactor()
	for _, name := range []string{"API_KEY", "api-key", "Api_Key", "X-API-KEY"} {
		if !r.IsSensitiveName(name) {
			t.Errorf("IsSensitiveName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"content-type", "user-agent", "page", "limit"} {
		if r.IsSensitiveName(name) {
			t.Errorf("IsSensitiveName(%q) = true, want false", name)
		}
	}
}
