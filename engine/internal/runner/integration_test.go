package runner

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mihakk/internal/audit"
	"mihakk/internal/corpus"
	"mihakk/internal/detect"
	"mihakk/internal/mutate"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

const testEngineVersion = "0.4.0-test"

// Every target in this file is an httptest server on loopback. Nothing here
// contacts a public address, and the scope allowlists only ever name the
// specific loopback address the test server was given.

// fakeTestbed mirrors the planted behaviours of the real testbed, so the
// detection logic can be exercised without Docker. The end-to-end run against
// the actual testbed lives in scripts/test-integration-testbed.sh.
type fakeTestbed struct {
	*httptest.Server
	Requests  atomic.Int64
	SlowCalls atomic.Int64
}

const fakeSlowDelay = 400 * time.Millisecond

func newFakeTestbed(t *testing.T) *fakeTestbed {
	t.Helper()
	tb := &fakeTestbed{}
	tb.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tb.Requests.Add(1)
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/items":
			// Stable: always fast, always 200, body size independent of input.
			writeJSON(w, 200, map[string]any{
				"page": 1, "limit": 20, "count": 20,
				"items": strings.Repeat("x", 800),
			})

		case "/api/orders":
			var body map[string]any
			dec := json.NewDecoder(r.Body)
			if err := dec.Decode(&body); err != nil {
				writeJSON(w, 400, map[string]any{"error": "bad_request", "detail": "invalid json"})
				return
			}
			qty, present := body["qty"]
			if !present {
				qty = 1
			}
			switch v := qty.(type) {
			case float64, bool:
				writeJSON(w, 201, map[string]any{"status": "created"})
			case string:
				if _, err := strconv.ParseFloat(v, 64); err != nil {
					// A merely invalid string is a clean client error.
					writeJSON(w, 400, map[string]any{"error": "bad_request", "detail": "qty must be a number"})
					return
				}
				writeJSON(w, 201, map[string]any{"status": "created"})
			default:
				// PLANTED: a wrong *type* reaches an unhandled path.
				writeJSON(w, 500, map[string]any{
					"error": "internal_error", "type": "TypeError",
					"detail": "int() argument must be a string or a number",
				})
			}

		case "/api/search":
			term := r.URL.Query().Get("term")
			if term == "" {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if s, ok := body["term"].(string); ok {
					term = s
				}
			}
			if strings.Contains(term, "%") || strings.Contains(term, "*") || strings.TrimSpace(term) == "" {
				// PLANTED: a fixed delay, never a function of the input.
				tb.SlowCalls.Add(1)
				time.Sleep(fakeSlowDelay)
			}
			writeJSON(w, 200, map[string]any{"matches": 0})

		default:
			writeJSON(w, 404, map[string]any{"error": "not_found"})
		}
	}))
	t.Cleanup(tb.Close)
	return tb
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// scopeFor authorises exactly one loopback server: its host, its port, and
// the single address it listens on.
func scopeFor(t *testing.T, servers ...*httptest.Server) *safety.Scope {
	t.Helper()
	s := &safety.Scope{MaxRedirects: 2}
	for _, srv := range servers {
		u, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			t.Fatal(err)
		}
		s.Targets = append(s.Targets, safety.Target{
			Scheme: u.Scheme, Host: u.Hostname(), Port: port,
			PathPrefixes:     []string{"/api"},
			Methods:          []string{"GET", "POST"},
			AllowedAddresses: []string{"127.0.0.1/32"},
		})
	}
	s.Normalize()
	if err := s.Validate(); err != nil {
		t.Fatalf("scope invalid: %v", err)
	}
	return s
}

func configFor(t *testing.T, scope *safety.Scope, limits safety.Limits) *safety.SessionConfig {
	t.Helper()
	cfg := &safety.SessionConfig{
		ConfigVersion: safety.ConfigVersion,
		Scope:         *scope,
		Limits:        limits,
		Authorization: &safety.Authorization{
			Operator:    "integration-test",
			Statement:   safety.RequiredStatement,
			AckedAt:     time.Now(),
			ScopeDigest: scope.Digest(),
		},
	}
	if err := cfg.Prepare(time.Now()); err != nil {
		t.Fatalf("config invalid: %v", err)
	}
	return cfg
}

func generousLimits() safety.Limits {
	return safety.Limits{
		RequestsPerSecond:  500,
		Burst:              100,
		MaxTotalRequests:   5000,
		MaxConcurrency:     4,
		MaxSessionDuration: safety.Duration(2 * time.Minute),
		RequestTimeout:     safety.Duration(5 * time.Second),
		MaxResponseBytes:   1 << 20,
	}
}

// corpusFor builds a corpus aimed at one server.
func corpusFor(t *testing.T, srv *httptest.Server) *corpus.Corpus {
	t.Helper()
	raw := fmt.Sprintf(`{
  "corpus_version": "1",
  "samples": [
    {"id": "items", "method": "GET", "url": "%s/api/items?page=1&limit=20&q=shoes",
     "headers": {"Accept": ["application/json"]}},
    {"id": "orders", "method": "POST", "url": "%s/api/orders",
     "headers": {"Content-Type": ["application/json"], "Accept": ["application/json"]},
     "body": "{\"sku\":\"A-001\",\"qty\":2}"},
    {"id": "search", "method": "GET", "url": "%s/api/search?term=shoes",
     "headers": {"Accept": ["application/json"]}}
  ]
}`, srv.URL, srv.URL, srv.URL)
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parsing corpus: %v", err)
	}
	return c
}

type harness struct {
	cfg      *safety.SessionConfig
	corpus   *corpus.Corpus
	client   *safety.Client
	governor *safety.Governor
	store    *store.Store
	audit    *audit.Log
	plan     *mutate.Plan
	seed     []byte
	dataDir  string
}

func newHarness(t *testing.T, srv *httptest.Server, limits safety.Limits, mutCfg mutate.Config, seedHex string) *harness {
	t.Helper()

	scope := scopeFor(t, srv)
	cfg := configFor(t, scope, limits)
	c := corpusFor(t, srv)

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := mutate.NewPlan(c, mutCfg, testEngineVersion, seed)
	if err != nil {
		t.Fatalf("building plan: %v", err)
	}

	gov, err := safety.NewGovernor(context.Background(), cfg.Limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gov.Stop)

	redactor := cfg.NewRedactor()
	client, err := safety.NewClient(safety.ClientConfig{
		Scope: &cfg.Scope, Governor: gov,
		Authorization: cfg.Authorization, Redactor: redactor,
	})
	if err != nil {
		t.Fatalf("building guarded client: %v", err)
	}

	dataDir := t.TempDir()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.Open(filepath.Join(dataDir, "audit.jsonl"), redactor)
	if err != nil {
		t.Fatal(err)
	}

	return &harness{
		cfg: cfg, corpus: c, client: client, governor: gov,
		store: st, audit: auditLog, plan: plan, seed: seed, dataDir: dataDir,
	}
}

func (h *harness) runner(t *testing.T, sessionID string, opts func(*Options)) *Runner {
	t.Helper()
	o := Options{
		SessionID: sessionID, EngineVersion: testEngineVersion, Seed: h.seed,
		Client: h.client, Governor: h.governor, Plan: h.plan,
		Corpus: h.corpus, Config: h.cfg,
		Detector: detect.New(detect.DefaultConfig()),
		Store:    h.store, Audit: h.audit, Redactor: h.cfg.NewRedactor(),
	}
	if opts != nil {
		opts(&o)
	}
	r, err := New(o)
	if err != nil {
		t.Fatalf("building runner: %v", err)
	}
	return r
}

// --- The safety criterion --------------------------------------------------

// An unauthorised target must receive nothing, whatever the mutations try.
func TestUnauthorisedTargetReceivesNoRequests(t *testing.T) {
	authorised := newFakeTestbed(t)

	var strangerHits atomic.Int64
	stranger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strangerHits.Add(1)
		w.WriteHeader(200)
	}))
	defer stranger.Close()

	strangerURL, _ := url.Parse(stranger.URL)

	// A corpus that openly tries to leave: a sample aimed at the stranger, a
	// sample on a path outside the allowed prefix, and one whose Host header
	// points elsewhere.
	raw := fmt.Sprintf(`{
  "corpus_version": "1",
  "samples": [
    {"id": "legit", "method": "GET", "url": "%s/api/items?page=1",
     "headers": {"Accept": ["application/json"]}},
    {"id": "other-host", "method": "GET", "url": "%s/api/items?page=1",
     "headers": {"Accept": ["application/json"]}},
    {"id": "outside-prefix", "method": "GET", "url": "%s/admin/secrets?page=1",
     "headers": {"Accept": ["application/json"]}},
    {"id": "spoofed-host-header", "method": "GET", "url": "%s/api/items?page=1",
     "headers": {"Accept": ["application/json"], "Host": ["%s"]}}
  ]
}`, authorised.URL, stranger.URL, authorised.URL, authorised.URL, strangerURL.Host)

	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parsing corpus: %v", err)
	}

	scope := scopeFor(t, authorised.Server)
	cfg := configFor(t, scope, generousLimits())

	seed, _ := hex.DecodeString("a1b2c3d4")
	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 6
	plan, err := mutate.NewPlan(c, mutCfg, testEngineVersion, seed)
	if err != nil {
		t.Fatalf("building plan: %v", err)
	}

	gov, err := safety.NewGovernor(context.Background(), cfg.Limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gov.Stop()

	client, err := safety.NewClient(safety.ClientConfig{
		Scope: &cfg.Scope, Governor: gov, Authorization: cfg.Authorization,
	})
	if err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	st, _ := store.Open(dataDir)
	auditLog, _ := audit.Open(filepath.Join(dataDir, "audit.jsonl"), safety.NewRedactor())

	r, err := New(Options{
		SessionID: "escape", EngineVersion: testEngineVersion, Seed: seed,
		Client: client, Governor: gov, Plan: plan, Corpus: c, Config: cfg,
		Store: st, Audit: auditLog,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if got := strangerHits.Load(); got != 0 {
		t.Fatalf("the unauthorised target received %d request(s); it must receive none", got)
	}
	if result.Refused == 0 {
		t.Fatal("no request was refused, so the out-of-scope samples were never attempted")
	}
	if authorised.Requests.Load() == 0 {
		t.Fatal("the authorised target received nothing; the test proves nothing about refusals")
	}
	t.Logf("authorised target: %d requests; unauthorised: %d; refused: %d",
		authorised.Requests.Load(), strangerHits.Load(), result.Refused)

	// Every refusal must be in the audit log, with the destination it was
	// refused for.
	events, err := audit.Read(auditLog.Path())
	if err != nil {
		t.Fatal(err)
	}
	refusals := 0
	for _, e := range events {
		if e.Type == audit.RequestRefused {
			refusals++
			if e.Outcome != "not_sent" {
				t.Errorf("a refusal was audited with outcome %q, want not_sent", e.Outcome)
			}
		}
	}
	if refusals == 0 {
		t.Fatal("refusals were not written to the audit log")
	}
}

// A redirect towards an unauthorised host must not be followed.
func TestRedirectToUnauthorisedHostIsNotFollowed(t *testing.T) {
	var strangerHits atomic.Int64
	stranger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strangerHits.Add(1)
	}))
	defer stranger.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, stranger.URL+"/api/items", http.StatusFound)
	}))
	defer target.Close()

	scope := scopeFor(t, target)
	cfg := configFor(t, scope, generousLimits())
	gov, _ := safety.NewGovernor(context.Background(), cfg.Limits, nil)
	defer gov.Stop()
	client, err := safety.NewClient(safety.ClientConfig{
		Scope: &cfg.Scope, Governor: gov, Authorization: cfg.Authorization,
	})
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("GET", target.URL+"/api/items", nil)
	if _, err := client.Do(context.Background(), req); err == nil {
		t.Fatal("the redirect off the allowlist was followed")
	}
	if got := strangerHits.Load(); got != 0 {
		t.Fatalf("the unauthorised host received %d request(s) via a redirect", got)
	}
}

// --- Detection -------------------------------------------------------------

// A fixed seed and config must surface both planted behaviours and leave the
// stable endpoint alone.
func TestRunDetectsPlantedBehavioursAndLeavesTheStablePathAlone(t *testing.T) {
	tb := newFakeTestbed(t)

	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 24 // cover the whole mutator set

	h := newHarness(t, tb.Server, generousLimits(), mutCfg, "5eed4a11")
	r := h.runner(t, "detect", nil)

	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	t.Logf("executed=%d saved=%d refused=%d", result.Executed, result.Saved, result.Refused)

	byType := map[detect.IndicatorType]int{}
	stablePathFindings := 0
	for _, c := range result.Cases {
		for _, ind := range c.Indicators {
			byType[ind.Type]++
		}
		if strings.Contains(c.RequestSummary.URL, "/api/items") {
			stablePathFindings++
			t.Errorf("the stable path produced an indicator: %s -> %v",
				c.RequestSummary.URL, c.Indicators)
		}
	}

	if byType[detect.HTTP5xx] == 0 {
		t.Error("the planted 5xx was not detected")
	}
	if byType[detect.LatencyAnomaly] == 0 {
		t.Error("the planted slow path was not detected")
	}
	if stablePathFindings > 0 {
		t.Errorf("%d false positives on the stable path", stablePathFindings)
	}
	t.Logf("indicators by type: %v", byType)

	// Each saved case must carry what a person needs to act on it.
	for _, c := range result.Cases {
		if c.Status != store.StatusNeedsVerification {
			t.Errorf("case %s has status %q; the engine must never claim more", c.CaseID, c.Status)
		}
		if len(c.Indicators) == 0 {
			t.Errorf("case %s was saved with no indicator", c.CaseID)
		}
		for _, ind := range c.Indicators {
			if ind.Type == "" {
				t.Errorf("case %s has an indicator with no type", c.CaseID)
			}
			if len(ind.Reason) < 10 {
				t.Errorf("case %s indicator %s has no usable reason: %q", c.CaseID, ind.Type, ind.Reason)
			}
		}
		rep := c.Reproduction
		if rep.MasterSeed == "" || rep.CorpusDigest == "" || rep.ConfigDigest == "" || rep.EngineVersion == "" {
			t.Errorf("case %s cannot be regenerated: %+v", c.CaseID, rep)
		}
		if !c.RequestSummary.Redacted {
			t.Errorf("case %s stored an unredacted request summary", c.CaseID)
		}
	}
}

// --- Limits ----------------------------------------------------------------

func TestRunHonoursTheTotalRequestBudget(t *testing.T) {
	tb := newFakeTestbed(t)

	limits := generousLimits()
	limits.MaxTotalRequests = 12

	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 20

	h := newHarness(t, tb.Server, limits, mutCfg, "b0000001")
	r := h.runner(t, "budget", nil)

	if _, err := r.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := tb.Requests.Load(); got > int64(limits.MaxTotalRequests) {
		t.Fatalf("the target received %d requests; the budget was %d", got, limits.MaxTotalRequests)
	}
	t.Logf("target received %d of a %d budget", tb.Requests.Load(), limits.MaxTotalRequests)
}

func TestRunHonoursTheRateLimit(t *testing.T) {
	tb := newFakeTestbed(t)

	limits := generousLimits()
	limits.RequestsPerSecond = 20
	limits.Burst = 1
	limits.MaxTotalRequests = 12

	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 20

	h := newHarness(t, tb.Server, limits, mutCfg, "4a7e0001")
	r := h.runner(t, "rate", nil)

	start := time.Now()
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	elapsed := time.Since(start)

	sent := tb.Requests.Load()
	if sent < 2 {
		t.Fatalf("only %d requests were sent; the timing says nothing", sent)
	}
	// One burst token, then one refill per 1/rate seconds. Assert a lower
	// bound only: upper bounds on shared machines are how tests flake.
	minimum := time.Duration(float64(sent-1)/limits.RequestsPerSecond*float64(time.Second)) * 8 / 10
	if elapsed < minimum {
		t.Fatalf("%d requests at %.0f/s took %v, want at least %v",
			sent, limits.RequestsPerSecond, elapsed, minimum)
	}
	t.Logf("%d requests in %v at a %.0f/s limit", sent, elapsed, limits.RequestsPerSecond)
}

func TestRunHonoursTheConcurrencyLimit(t *testing.T) {
	var inFlight, peak atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := inFlight.Add(1)
		for {
			old := peak.Load()
			if current <= old || peak.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		inFlight.Add(-1)
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	defer srv.Close()

	limits := generousLimits()
	limits.MaxConcurrency = 2
	limits.MaxTotalRequests = 40

	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 20

	h := newHarness(t, srv, limits, mutCfg, "c0c0c001")
	r := h.runner(t, "concurrency", func(o *Options) { o.Workers = 8 })

	if _, err := r.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := peak.Load(); got > int64(limits.MaxConcurrency) {
		t.Fatalf("peak concurrency at the target was %d; the limit was %d", got, limits.MaxConcurrency)
	}
	t.Logf("peak concurrency %d, limit %d", peak.Load(), limits.MaxConcurrency)
}

func TestRunHonoursTheSessionDuration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	defer srv.Close()

	limits := generousLimits()
	limits.MaxSessionDuration = safety.Duration(300 * time.Millisecond)
	limits.MaxTotalRequests = 10000

	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 40

	h := newHarness(t, srv, limits, mutCfg, "d0d0d001")
	r := h.runner(t, "duration", nil)

	start := time.Now()
	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("the run took %v despite a 300ms session limit", elapsed)
	}
	if !result.Stopped {
		t.Fatal("the session was not marked stopped after exceeding its duration")
	}
	t.Logf("session ended after %v: %v", elapsed, result.StopCause)
}

// The kill switch must cut a run that is already under way.
func TestStopDuringARunIsImmediate(t *testing.T) {
	released := make(chan struct{})
	var served atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		select {
		case <-released:
		case <-time.After(5 * time.Second):
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	defer srv.Close()
	defer close(released)

	limits := generousLimits()
	limits.RequestTimeout = safety.Duration(10 * time.Second)
	limits.MaxTotalRequests = 1000

	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 20

	h := newHarness(t, srv, limits, mutCfg, "50000001")
	r := h.runner(t, "stop", nil)

	done := make(chan *Result, 1)
	go func() {
		result, err := r.Run(context.Background())
		if err != nil {
			t.Errorf("run: %v", err)
		}
		done <- result
	}()

	// Wait until requests are genuinely in flight, then pull the switch.
	deadline := time.After(3 * time.Second)
	for served.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("no request reached the target")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	stoppedAt := time.Now()
	h.governor.Stop()

	select {
	case result := <-done:
		elapsed := time.Since(stoppedAt)
		if elapsed > 2*time.Second {
			t.Fatalf("the run took %v to stop; in-flight requests were not cut", elapsed)
		}
		if !result.Stopped {
			t.Fatal("the session was not marked stopped")
		}
		if result.Session.Status != store.SessionStopped {
			t.Fatalf("session status is %q, want %q", result.Session.Status, store.SessionStopped)
		}
		t.Logf("run stopped %v after the kill switch", elapsed)
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not stop within 5s of the kill switch")
	}
}

// --- Audit and redaction ---------------------------------------------------

func TestAuditRecordsTheSessionAndRedactsSecrets(t *testing.T) {
	tb := newFakeTestbed(t)

	scope := scopeFor(t, tb.Server)
	cfg := configFor(t, scope, generousLimits())

	// A corpus whose samples carry credentials.
	raw := fmt.Sprintf(`{
  "corpus_version": "1",
  "samples": [
    {"id": "with-secrets", "method": "POST", "url": "%s/api/orders?access_token=tok-abcdefghijklmnop",
     "headers": {
       "Content-Type": ["application/json"],
       "Authorization": ["Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SUPERSECRETSIGNATURE"],
       "Cookie": ["session=deadbeefdeadbeefdeadbeef"],
       "X-Api-Key": ["key-abcdef123456"]
     },
     "body": "{\"sku\":\"A-1\",\"qty\":null,\"password\":\"hunter2-secret\"}"}
  ]
}`, tb.URL)

	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	seed, _ := hex.DecodeString("aaaa0001")
	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 10
	plan, err := mutate.NewPlan(c, mutCfg, testEngineVersion, seed)
	if err != nil {
		t.Fatal(err)
	}

	gov, _ := safety.NewGovernor(context.Background(), cfg.Limits, nil)
	defer gov.Stop()
	redactor := cfg.NewRedactor()
	client, err := safety.NewClient(safety.ClientConfig{
		Scope: &cfg.Scope, Governor: gov, Authorization: cfg.Authorization, Redactor: redactor,
	})
	if err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	st, _ := store.Open(dataDir)
	auditPath := filepath.Join(dataDir, "audit.jsonl")
	auditLog, _ := audit.Open(auditPath, redactor)

	r, err := New(Options{
		SessionID: "audited", EngineVersion: testEngineVersion, Seed: seed,
		Client: client, Governor: gov, Plan: plan, Corpus: c, Config: cfg,
		Store: st, Audit: auditLog, Redactor: redactor,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	events, err := audit.Read(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	var started, stopped *audit.Event
	for i := range events {
		switch events[i].Type {
		case audit.SessionStarted:
			started = &events[i]
		case audit.SessionStopped:
			stopped = &events[i]
		}
	}
	if started == nil {
		t.Fatal("the audit log has no session_started event")
	}
	if stopped == nil {
		t.Fatal("the audit log has no session_stopped event")
	}

	// Who, when, on what authority, against what, under which limits.
	if started.Operator != "integration-test" {
		t.Errorf("operator = %q", started.Operator)
	}
	if started.Statement != safety.RequiredStatement {
		t.Errorf("the acknowledgement statement was not recorded verbatim: %q", started.Statement)
	}
	if started.AckedAt == nil || started.AckedAt.IsZero() {
		t.Error("the acknowledgement time was not recorded")
	}
	if started.ScopeDigest == "" || started.ScopeDigest != cfg.Scope.Digest() {
		t.Errorf("scope digest = %q", started.ScopeDigest)
	}
	if started.Limits == nil || started.Limits.MaxTotalRequests != cfg.Limits.MaxTotalRequests {
		t.Error("the limits in force were not recorded")
	}
	if len(started.Targets) == 0 {
		t.Error("the targets were not recorded")
	}
	if started.Seed == "" {
		t.Error("the seed was not recorded, so the run cannot be reconstructed")
	}
	if stopped.At.Before(started.At) {
		t.Error("the stop time precedes the start time")
	}

	// No secret may appear anywhere in the audit log or the saved cases.
	secrets := []string{
		"SUPERSECRETSIGNATURE", "deadbeefdeadbeefdeadbeef",
		"key-abcdef123456", "hunter2-secret", "tok-abcdefghijklmnop",
	}

	auditRaw := readFile(t, auditPath)
	for _, secret := range secrets {
		if strings.Contains(auditRaw, secret) {
			t.Errorf("the audit log contains the secret %q", secret)
		}
	}

	caseRaw := readFile(t, filepath.Join(dataDir, "sessions", "audited", "cases.jsonl"))
	for _, secret := range secrets {
		if strings.Contains(caseRaw, secret) {
			t.Errorf("a saved case contains the secret %q", secret)
		}
	}
	if result.Saved > 0 && !strings.Contains(caseRaw, safety.Placeholder) {
		t.Error("no redaction marker appears in the saved cases; redaction may not have run at all")
	}

	// The header names survive so a reviewer can see what was sent.
	for _, c := range result.Cases {
		if _, ok := c.RequestSummary.Headers["Authorization"]; !ok {
			t.Error("the Authorization header name was dropped entirely rather than redacted")
		} else if c.RequestSummary.Headers["Authorization"][0] != safety.Placeholder {
			t.Errorf("Authorization = %q, want the placeholder",
				c.RequestSummary.Headers["Authorization"][0])
		}
	}
	t.Logf("%d audit events, %d saved cases, no secrets in either", len(events), result.Saved)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := readFileBytes(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(raw)
}
