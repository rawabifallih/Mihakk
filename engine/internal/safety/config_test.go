package safety

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const testbedScopeJSON = `"scope":{
    "targets":[{
      "scheme":"http","host":"testbed","port":8000,
      "path_prefixes":["/api"],"methods":["GET","POST"],
      "allowed_addresses":["127.0.0.1/32"]
    }],
    "max_redirects":2
  }`

func validConfigJSON(ackedAt time.Time) string {
	return `{
  ` + testbedScopeJSON + `,
  "limits":{
    "requests_per_second":5,"burst":2,"max_total_requests":100,"max_concurrency":2,
    "max_session_duration":"2m","request_timeout":"5s","max_response_bytes":1048576
  },
  "authorization":{
    "operator":"rawabi",
    "statement":"` + RequiredStatement + `",
    "acked_at":"` + ackedAt.UTC().Format(time.RFC3339) + `",
    "scope_digest":"SCOPE_DIGEST"
  }
}`
}

// digestOfTestbedScope mirrors the scope literal above.
func digestOfTestbedScope() string {
	s := Scope{Targets: []Target{{
		Scheme: "http", Host: "testbed", Port: 8000,
		PathPrefixes: []string{"/api"}, Methods: []string{"GET", "POST"},
		AllowedAddresses: []string{"127.0.0.1/32"},
	}}, MaxRedirects: 2}
	s.Normalize()
	return s.Digest()
}

func TestLoadSessionConfigAcceptsValidFile(t *testing.T) {
	now := time.Now()
	body := validConfigJSON(now.Add(-time.Minute))
	body = replaceAll(body, "SCOPE_DIGEST", digestOfTestbedScope())
	path := writeConfig(t, body)

	cfg, err := LoadSessionConfig(path, now)
	if err != nil {
		t.Fatalf("LoadSessionConfig: %v", err)
	}
	if cfg.ConfigVersion != ConfigVersion {
		t.Errorf("ConfigVersion = %q, want %q", cfg.ConfigVersion, ConfigVersion)
	}
	if cfg.Limits.MaxSessionDuration.Duration() != 2*time.Minute {
		t.Errorf("MaxSessionDuration = %v, want 2m", cfg.Limits.MaxSessionDuration.Duration())
	}
	if cfg.Scope.Targets[0].Host != "testbed" {
		t.Errorf("host = %q", cfg.Scope.Targets[0].Host)
	}
}

func TestLoadSessionConfigRefusesMissingAuthorization(t *testing.T) {
	now := time.Now()
	body := `{` + testbedScopeJSON + `}`
	path := writeConfig(t, body)

	_, err := LoadSessionConfig(path, now)
	if !errors.Is(err, ErrNoAuthorization) {
		t.Fatalf("LoadSessionConfig without authorization = %v, want ErrNoAuthorization", err)
	}
}

func TestLoadSessionConfigRefusesUnknownFields(t *testing.T) {
	now := time.Now()
	body := `{` + testbedScopeJSON + `,"unexpected_field":true}`
	path := writeConfig(t, body)

	if _, err := LoadSessionConfig(path, now); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("LoadSessionConfig with unknown field = %v, want ErrInvalidConfig", err)
	}
}

func TestPrepareAppliesConservativeDefaultLimits(t *testing.T) {
	now := time.Now()
	scope := Scope{Targets: []Target{{
		Scheme: "http", Host: "testbed", Port: 8000,
		PathPrefixes: []string{"/api"}, Methods: []string{"GET"},
		AllowedAddresses: []string{"127.0.0.1/32"},
	}}}
	scope.Normalize()

	cfg := SessionConfig{
		Scope: scope,
		Authorization: &Authorization{
			Operator: "rawabi", Statement: RequiredStatement,
			AckedAt: now, ScopeDigest: scope.Digest(),
		},
	}
	if err := cfg.Prepare(now); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if cfg.Limits != DefaultLimits() {
		t.Fatalf("Limits = %+v, want DefaultLimits()", cfg.Limits)
	}
}

// The reproduction digest must not move just because authorisation was
// re-acknowledged, otherwise every saved case would look "drifted" tomorrow.
func TestConfigDigestIgnoresAuthorizationButTracksLimits(t *testing.T) {
	now := time.Now()
	scope := Scope{Targets: []Target{{
		Scheme: "http", Host: "testbed", Port: 8000,
		PathPrefixes: []string{"/api"}, Methods: []string{"GET"},
		AllowedAddresses: []string{"127.0.0.1/32"},
	}}}
	scope.Normalize()

	base := SessionConfig{
		ConfigVersion: ConfigVersion,
		Scope:         scope,
		Limits:        DefaultLimits(),
		Authorization: &Authorization{
			Operator: "rawabi", Statement: RequiredStatement,
			AckedAt: now, ScopeDigest: scope.Digest(),
		},
	}
	reacked := base
	reacked.Authorization = &Authorization{
		Operator: "someone-else", Statement: RequiredStatement,
		AckedAt: now.Add(time.Hour), ScopeDigest: scope.Digest(),
	}
	if base.Digest() != reacked.Digest() {
		t.Fatal("re-acknowledging authorisation changed the reproduction digest")
	}

	changed := base
	changed.Limits.MaxResponseBytes = 1
	if base.Digest() == changed.Digest() {
		t.Fatal("changing limits did not change the reproduction digest")
	}

	widened := base
	widened.Scope = Scope{Targets: []Target{{
		Scheme: "http", Host: "testbed", Port: 8000,
		PathPrefixes: []string{"/"}, Methods: []string{"GET"},
		AllowedAddresses: []string{"127.0.0.1/32"},
	}}}
	widened.Scope.Normalize()
	if base.Digest() == widened.Digest() {
		t.Fatal("widening the scope did not change the reproduction digest")
	}
}

func replaceAll(s, old, new string) string {
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
