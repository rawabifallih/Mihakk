package runner

// Where does the recorded scope come from?
//
// "The stored scope matches the configuration" is the easy claim, and it is not
// the one that matters. What governs the traffic is the scope inside the guarded
// client, and that is what a record, an audit entry and a report must describe.
// The two can differ, so a test that builds a client from a configuration and then
// compares the record against that same configuration cannot tell which one was
// the source: both answers look identical.
//
// So these tests make them differ on purpose. The client is built from one scope
// and the runner is handed a configuration carrying another, and the record must
// follow the client. Every scope-facing field is checked, not only Scope itself:
// a digest derived from the configuration while Scope came from the client would
// leave one record describing two different scopes.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"mihakk/internal/audit"
	"mihakk/internal/corpus"
	"mihakk/internal/detect"
	"mihakk/internal/mutate"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

// twoScopes returns a scope authorising the live target, and a second, different
// scope that is valid on its own but authorises a path prefix the first does not.
func twoScopes(t *testing.T, target *httptest.Server) (enforced, other safety.Scope) {
	t.Helper()
	u, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()

	enforced = safety.Scope{
		Targets: []safety.Target{{
			Scheme: "http", Host: host, Port: port,
			PathPrefixes:     []string{"/api"},
			Methods:          []string{"GET"},
			AllowedAddresses: []string{"127.0.0.1/32"},
		}},
		MaxRedirects: 2,
	}
	other = safety.Scope{
		Targets: []safety.Target{{
			Scheme: "http", Host: host, Port: port,
			PathPrefixes:     []string{"/somewhere-else"},
			Methods:          []string{"GET", "POST"},
			AllowedAddresses: []string{"127.0.0.1/32"},
		}},
		MaxRedirects: 7,
	}
	enforced.Normalize()
	other.Normalize()
	return enforced, other
}

func TestTheRecordedScopeComesFromTheEnforcingClient(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer target.Close()

	enforced, other := twoScopes(t, target)

	// The configuration the runner is given carries `other`. Its acknowledgement
	// is bound to `other`, so it is a perfectly valid configuration in itself.
	cfg := &safety.SessionConfig{
		ConfigVersion: safety.ConfigVersion,
		Scope:         other,
		Limits:        testLimits(),
		Authorization: &safety.Authorization{
			Operator: "provenance-test", Statement: safety.RequiredStatement,
			AckedAt: time.Now(), ScopeDigest: other.Digest(),
		},
	}

	// The client, however, is built from `enforced` -- so this is the allowlist
	// the traffic is actually checked against.
	gov, err := safety.NewGovernor(context.Background(), cfg.Limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gov.Stop()

	client, err := safety.NewClient(safety.ClientConfig{
		Scope:    &enforced,
		Governor: gov,
		Authorization: &safety.Authorization{
			Operator: "provenance-test", Statement: safety.RequiredStatement,
			AckedAt: time.Now(), ScopeDigest: enforced.Digest(),
		},
		Redactor: safety.NewRedactor(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	sess, dataDir := runOneSession(t, cfg, client, gov, target)

	// --- the snapshot itself ---
	if sess.Scope == nil {
		t.Fatal("the session record carries no scope snapshot")
	}
	if !reflect.DeepEqual(*sess.Scope, client.Scope()) {
		t.Errorf("the stored scope is not the client's:\nstored %+v\nclient %+v",
			*sess.Scope, client.Scope())
	}
	if reflect.DeepEqual(*sess.Scope, cfg.Scope) {
		t.Error("the stored scope is the configuration's, not the enforcing client's")
	}

	// --- and everything derived from it, which is the part that was asked for ---
	enforcedNow := client.Scope()
	if got, want := sess.ScopeDigest, enforcedNow.Digest(); got != want {
		t.Errorf("ScopeDigest came from somewhere other than the snapshot:\ngot  %s\nwant %s", got, want)
	}
	if sess.ScopeDigest == cfg.Scope.Digest() {
		t.Error("ScopeDigest was derived from the configuration's scope")
	}
	if got, want := sess.Targets, targetsFromScope(&enforcedNow); !reflect.DeepEqual(got, want) {
		t.Errorf("Targets came from somewhere other than the snapshot:\ngot  %v\nwant %v", got, want)
	}

	// --- the record is internally consistent: a separate claim ---
	if got := sess.Scope.Digest(); got != sess.ScopeDigest {
		t.Errorf("the stored scope does not hash to the stored digest:\nrecomputed %s\nstored     %s",
			got, sess.ScopeDigest)
	}

	// --- and the audit entry describes the same scope ---
	assertAuditScope(t, sess, dataDir)
}

// A change to the caller's configuration after the client exists must reach
// neither what is enforced nor what is recorded.
func TestMutatingTheConfigAfterwardsChangesNeitherEnforcementNorRecord(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer target.Close()

	enforced, _ := twoScopes(t, target)

	cfg := &safety.SessionConfig{
		ConfigVersion: safety.ConfigVersion,
		Scope:         enforced,
		Limits:        testLimits(),
		Authorization: &safety.Authorization{
			Operator: "mutation-test", Statement: safety.RequiredStatement,
			AckedAt: time.Now(), ScopeDigest: enforced.Digest(),
		},
	}

	gov, err := safety.NewGovernor(context.Background(), cfg.Limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gov.Stop()

	client, err := safety.NewClient(safety.ClientConfig{
		Scope: &cfg.Scope, Governor: gov,
		Authorization: cfg.Authorization, Redactor: safety.NewRedactor(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	before := client.Scope()

	// Widen the caller's copy after the fact: a second target, a looser method
	// list, more redirects.
	cfg.Scope.MaxRedirects = 9
	cfg.Scope.Targets[0].PathPrefixes = []string{"/"}
	cfg.Scope.Targets = append(cfg.Scope.Targets, safety.Target{
		Scheme: "http", Host: "elsewhere.invalid", Port: 80,
		PathPrefixes: []string{"/"}, Methods: []string{"GET"},
	})

	if after := client.Scope(); !reflect.DeepEqual(before, after) {
		t.Errorf("mutating the caller's config changed what the client enforces:\nbefore %+v\nafter  %+v",
			before, after)
	}

	sess, dataDir := runOneSession(t, cfg, client, gov, target)
	if sess.Scope == nil {
		t.Fatal("no scope snapshot")
	}
	if !reflect.DeepEqual(*sess.Scope, before) {
		t.Errorf("the record followed the mutated config:\nstored %+v\nwant   %+v", *sess.Scope, before)
	}
	if len(sess.Targets) != 1 {
		t.Errorf("Targets followed the mutated config: %v", sess.Targets)
	}
	if sess.ScopeDigest != before.Digest() {
		t.Error("ScopeDigest followed the mutated config")
	}
	assertAuditScope(t, sess, dataDir)
}

// --- helpers ---------------------------------------------------------------

func testLimits() safety.Limits {
	return safety.Limits{
		RequestsPerSecond: 500, Burst: 100, MaxTotalRequests: 200,
		MaxConcurrency: 2, MaxSessionDuration: safety.Duration(time.Minute),
		RequestTimeout: safety.Duration(5 * time.Second), MaxResponseBytes: 1 << 20,
	}
}

// runOneSession runs a short session and returns the stored record.
func runOneSession(t *testing.T, cfg *safety.SessionConfig, client *safety.Client,
	gov *safety.Governor, target *httptest.Server) (*store.Session, string) {
	t.Helper()

	dataDir := t.TempDir()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	auditLog, err := audit.Open(filepath.Join(dataDir, "audit.jsonl"), safety.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}

	raw := `{"corpus_version":"1","samples":[{"id":"items","method":"GET",` +
		`"url":"` + target.URL + `/api/items?page=1","headers":{"Accept":["application/json"]}}]}`
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 2
	plan, err := mutate.NewPlan(c, mutCfg, "test", []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}

	r, err := New(Options{
		SessionID: "provenance", EngineVersion: "test", Seed: []byte{1, 2, 3, 4},
		Client: client, Governor: gov, Plan: plan, Corpus: c, Config: cfg,
		Detector: detect.New(detect.DefaultConfig()),
		Store:    st, Audit: auditLog, Redactor: safety.NewRedactor(),
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sess, err := st.LoadSession("provenance")
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	return sess, dataDir
}

// assertAuditScope checks the audit log describes the same scope as the record.
// The audit entry derives from the session record, so this guards the derivation
// staying that way rather than growing a second source of its own.
func assertAuditScope(t *testing.T, sess *store.Session, dataDir string) {
	t.Helper()
	entries, err := audit.Read(filepath.Join(dataDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Type != audit.SessionStarted {
			continue
		}
		found = true
		if e.ScopeDigest != sess.ScopeDigest {
			t.Errorf("the audit entry's scope digest differs from the record's:\naudit  %s\nrecord %s",
				e.ScopeDigest, sess.ScopeDigest)
		}
		if !reflect.DeepEqual(e.Targets, sess.Targets) {
			t.Errorf("the audit entry's targets differ from the record's:\naudit  %v\nrecord %v",
				e.Targets, sess.Targets)
		}
	}
	if !found {
		t.Error("no session-started entry in the audit log")
	}
}
