package runner

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

// runAndPickCase runs against the fake testbed and returns one saved case of
// the requested indicator type, plus the harness that produced it.
func runAndPickCase(t *testing.T, tb *fakeTestbed, want detect.IndicatorType) (*harness, *store.Case) {
	t.Helper()

	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 24
	h := newHarness(t, tb.Server, generousLimits(), mutCfg, "5eed4a11")

	r := h.runner(t, "repro", nil)
	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, c := range result.Cases {
		for _, ind := range c.Indicators {
			if ind.Type == want {
				return h, c
			}
		}
	}
	t.Fatalf("no case of type %s was produced to reproduce", want)
	return nil, nil
}

func (h *harness) reproduceOptions(caseID string) ReproduceOptions {
	return ReproduceOptions{
		CaseID: caseID, EngineVersion: testEngineVersion,
		Client: h.client, Governor: h.governor,
		Config: h.cfg, Corpus: h.corpus,
		Detector: detect.New(detect.DefaultConfig()),
		Store:    h.store, Audit: h.audit, Redactor: h.cfg.NewRedactor(),
	}
}

func TestReproduceReportsTheIndicatorReappearing(t *testing.T) {
	tb := newFakeTestbed(t)
	h, saved := runAndPickCase(t, tb, detect.HTTP5xx)

	result, err := Reproduce(context.Background(), h.reproduceOptions(saved.CaseID))
	if err != nil {
		t.Fatalf("reproduce: %v", err)
	}

	if !result.AuthorizationRevalidated {
		t.Error("reproduce did not record that authorisation was re-validated")
	}
	if result.ScopeDigest != h.cfg.Scope.Digest() {
		t.Errorf("scope digest = %q, want the current scope's", result.ScopeDigest)
	}
	if result.Fidelity != Exact {
		t.Errorf("fidelity = %q, want exact (nothing changed between the two runs)", result.Fidelity)
	}
	if result.IndicatorReappeared == nil {
		t.Fatal("indicator_reappeared is unknown; the request was not sent")
	}
	if !*result.IndicatorReappeared {
		t.Errorf("the deterministic 5xx did not reappear: %s", result.ComparisonNote)
	}

	// The wording must not promote an indicator into a finding. Note that
	// "not a confirmed vulnerability" is exactly the phrasing we want, so the
	// check looks for affirmative claims rather than the bare word.
	lowered := strings.ToLower(result.ComparisonNote)
	for _, overclaim := range []string{
		"vulnerability confirmed", "is a confirmed vulnerability",
		"exploitable", "proves", "confirms a vulnerability",
	} {
		if strings.Contains(lowered, overclaim) {
			t.Errorf("the comparison note overclaims (%q): %q", overclaim, result.ComparisonNote)
		}
	}
	if !strings.Contains(lowered, "not a confirmed vulnerability") {
		t.Errorf("a reappearing indicator should still be labelled as needing verification: %q",
			result.ComparisonNote)
	}
	t.Logf("note: %s", result.ComparisonNote)
}

// A target that stops misbehaving must produce a plain "no", not an error and
// not a claim that the original observation was wrong.
func TestReproduceReportsTheIndicatorNotReappearing(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/orders" && failing.Load() {
			writeJSON(w, 500, map[string]any{"error": "internal_error", "type": "TypeError"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	defer srv.Close()

	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 12
	h := newHarness(t, srv, generousLimits(), mutCfg, "5eed0002")

	r := h.runner(t, "flaky", nil)
	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	var target *store.Case
	for _, c := range result.Cases {
		for _, ind := range c.Indicators {
			if ind.Type == detect.HTTP5xx {
				target = c
			}
		}
	}
	if target == nil {
		t.Fatal("no 5xx case was produced")
	}

	// The application is fixed between the two runs.
	failing.Store(false)

	rep, err := Reproduce(context.Background(), h.reproduceOptions(target.CaseID))
	if err != nil {
		t.Fatalf("reproduce: %v", err)
	}
	if rep.IndicatorReappeared == nil {
		t.Fatal("indicator_reappeared is unknown; the request should have been sent")
	}
	if *rep.IndicatorReappeared {
		t.Error("the indicator reappeared although the target was fixed")
	}
	lowered := strings.ToLower(rep.ComparisonNote)
	if !strings.Contains(lowered, "does not show the first observation was wrong") {
		t.Errorf("a non-reappearing indicator must not be read as a refutation: %q", rep.ComparisonNote)
	}
	t.Logf("note: %s", rep.ComparisonNote)
}

// Reproduction must be subject to the current limits, not exempt from them.
func TestReproduceIsSubjectToTheRequestBudget(t *testing.T) {
	tb := newFakeTestbed(t)
	h, saved := runAndPickCase(t, tb, detect.HTTP5xx)

	// A fresh governor with a budget of one request, plus a client bound to it.
	tightLimits := generousLimits()
	tightLimits.MaxTotalRequests = 1
	gov, err := safety.NewGovernor(context.Background(), tightLimits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gov.Stop()

	client, err := safety.NewClient(safety.ClientConfig{
		Scope: &h.cfg.Scope, Governor: gov, Authorization: h.cfg.Authorization,
	})
	if err != nil {
		t.Fatal(err)
	}

	opts := h.reproduceOptions(saved.CaseID)
	opts.Client = client
	opts.Governor = gov

	// The first reproduce spends the single request.
	if _, err := Reproduce(context.Background(), opts); err != nil {
		t.Fatalf("first reproduce: %v", err)
	}

	// The second must be refused, and must say so rather than guessing.
	second, err := Reproduce(context.Background(), opts)
	if err != nil {
		t.Fatalf("second reproduce: %v", err)
	}
	if second.IndicatorReappeared != nil {
		t.Errorf("indicator_reappeared = %v; nothing was sent, so it must be unknown",
			*second.IndicatorReappeared)
	}
	if !strings.Contains(second.ComparisonNote, "never sent") {
		t.Errorf("the note should say nothing was sent: %q", second.ComparisonNote)
	}
	t.Logf("note: %s", second.ComparisonNote)
}

// Reproduction must be refused outright when the scope no longer covers the
// target, exactly as a fresh run would be.
func TestReproduceRefusesAnOutOfScopeTarget(t *testing.T) {
	tb := newFakeTestbed(t)
	h, saved := runAndPickCase(t, tb, detect.HTTP5xx)

	// A scope that authorises a different port entirely.
	narrowed := h.cfg.Scope
	narrowed.Targets = append([]safety.Target(nil), narrowed.Targets...)
	narrowed.Targets[0].Port = narrowed.Targets[0].Port + 1
	narrowed.Normalize()

	cfg := configFor(t, &narrowed, generousLimits())
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

	before := tb.Requests.Load()

	opts := h.reproduceOptions(saved.CaseID)
	opts.Client = client
	opts.Governor = gov
	opts.Config = cfg

	result, err := Reproduce(context.Background(), opts)
	if err != nil {
		t.Fatalf("reproduce: %v", err)
	}
	if result.IndicatorReappeared != nil {
		t.Error("an out-of-scope reproduce reported an outcome; nothing should have been sent")
	}
	if got := tb.Requests.Load(); got != before {
		t.Fatalf("the target received %d more request(s) despite being out of scope", got-before)
	}
	t.Logf("note: %s", result.ComparisonNote)
}

// A later redirect refusal must not erase the request that reached the original
// target. Reproduce still cannot compare an indicator without a final response,
// but its note and audit must say an attempt happened.
func TestReproduceReportsAnAnsweredHopBeforeALaterRedirectRefusal(t *testing.T) {
	var redirecting atomic.Bool
	var outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideHits.Add(1)
		writeJSON(w, 200, map[string]any{"outside": true})
	}))
	defer outside.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirecting.Load() {
			http.Redirect(w, r, outside.URL+"/api/outside", http.StatusFound)
			return
		}
		writeJSON(w, 500, map[string]any{"error": "internal_error", "type": "TypeError"})
	}))
	defer target.Close()

	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 12
	h := newHarness(t, target, generousLimits(), mutCfg, "5eed0003")
	r := h.runner(t, "redirect-repro", nil)
	run, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var saved *store.Case
	for _, c := range run.Cases {
		for _, indicator := range c.Indicators {
			if indicator.Type == detect.HTTP5xx {
				saved = c
				break
			}
		}
		if saved != nil {
			break
		}
	}
	if saved == nil {
		t.Fatal("no 5xx case was produced")
	}

	redirecting.Store(true)
	result, err := Reproduce(context.Background(), h.reproduceOptions(saved.CaseID))
	if err != nil {
		t.Fatal(err)
	}
	if result.IndicatorReappeared != nil {
		t.Fatal("a replay with no final response reported an indicator verdict")
	}
	if !strings.Contains(result.ComparisonNote, "made 1 HTTP attempt") ||
		strings.Contains(result.ComparisonNote, "never sent") {
		t.Errorf("the comparison note erased or misstated the answered hop: %q", result.ComparisonNote)
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("the out-of-scope redirect received %d request(s)", outsideHits.Load())
	}

	events, err := audit.Read(h.audit.Path())
	if err != nil {
		t.Fatal(err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == audit.ReproduceFinished {
			if events[i].Outcome != "refused_after_attempt" {
				t.Errorf("reproduce audit outcome %q; want refused_after_attempt", events[i].Outcome)
			}
			return
		}
	}
	t.Fatal("no reproduce-finished audit event")
}

// A stale acknowledgement must stop a reproduce before anything is built.
func TestReproduceRefusesAStaleAuthorization(t *testing.T) {
	tb := newFakeTestbed(t)
	scope := scopeFor(t, tb.Server)

	stale := &safety.SessionConfig{
		ConfigVersion: safety.ConfigVersion,
		Scope:         *scope,
		Limits:        generousLimits(),
		Authorization: &safety.Authorization{
			Operator:    "integration-test",
			Statement:   safety.RequiredStatement,
			AckedAt:     time.Now().Add(-safety.MaxAckAge - time.Hour),
			ScopeDigest: scope.Digest(),
		},
	}
	if err := stale.Prepare(time.Now()); err == nil {
		t.Fatal("a stale acknowledgement was accepted by Prepare")
	}

	gov, err := safety.NewGovernor(context.Background(), generousLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gov.Stop()

	// And the client cannot be built either, so no reproduce path exists.
	if _, err := safety.NewClient(safety.ClientConfig{
		Scope: scope, Governor: gov, Authorization: stale.Authorization,
	}); err == nil {
		t.Fatal("a guarded client was built from a stale acknowledgement")
	}
}

// A changed corpus must be reported as drift, not passed off as an exact
// replay of the original request.
func TestReproduceReportsDriftWhenInputsChange(t *testing.T) {
	tb := newFakeTestbed(t)
	h, saved := runAndPickCase(t, tb, detect.HTTP5xx)

	// Same shape, different sample content.
	drifted := corpusFor(t, tb.Server)
	drifted.Samples[0].URL = strings.Replace(drifted.Samples[0].URL, "page=1", "page=2", 1)
	drifted.Normalize()

	opts := h.reproduceOptions(saved.CaseID)
	opts.Corpus = drifted

	result, err := Reproduce(context.Background(), opts)
	if err != nil {
		t.Fatalf("reproduce: %v", err)
	}
	if result.Fidelity != Drifted {
		t.Fatalf("fidelity = %q, want drifted", result.Fidelity)
	}
	if len(result.Drift) == 0 {
		t.Fatal("drift was reported without saying what changed")
	}
	found := false
	for _, d := range result.Drift {
		if d.Input == "corpus_digest" {
			found = true
			if d.Recorded == d.Current {
				t.Error("the corpus drift entry records identical digests")
			}
			if d.Effect == "" {
				t.Error("the drift entry does not explain what it means")
			}
		}
	}
	if !found {
		t.Errorf("the changed corpus was not named in the drift: %+v", result.Drift)
	}
	if !strings.Contains(result.ComparisonNote, "drifted") &&
		!strings.Contains(result.ComparisonNote, "approximation") {
		t.Errorf("the note does not warn that this is not the original request: %q",
			result.ComparisonNote)
	}
	t.Logf("drift: %+v", result.Drift)
}

// A reproduce must leave a trace of its own.
func TestReproduceIsAudited(t *testing.T) {
	tb := newFakeTestbed(t)
	h, saved := runAndPickCase(t, tb, detect.HTTP5xx)

	before, err := audit.Read(h.audit.Path())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Reproduce(context.Background(), h.reproduceOptions(saved.CaseID)); err != nil {
		t.Fatalf("reproduce: %v", err)
	}

	after, err := audit.Read(h.audit.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(after) <= len(before) {
		t.Fatal("reproduce wrote nothing to the audit log")
	}

	var started, finished bool
	for _, e := range after[len(before):] {
		switch e.Type {
		case audit.ReproduceStarted:
			started = true
			if e.Operator == "" || e.Statement != safety.RequiredStatement {
				t.Error("the reproduce start event does not record who authorised it")
			}
			if e.CaseID != saved.CaseID {
				t.Errorf("case id = %q, want %q", e.CaseID, saved.CaseID)
			}
		case audit.ReproduceFinished:
			finished = true
			if e.Outcome == "" {
				t.Error("the reproduce finish event records no outcome")
			}
		}
	}
	if !started || !finished {
		t.Errorf("reproduce audit incomplete: started=%t finished=%t", started, finished)
	}
}

// The reproduce path must go through the guarded client like everything else.
func TestReproduceRequiresAGuardedClient(t *testing.T) {
	dataDir := t.TempDir()
	st, _ := store.Open(dataDir)
	auditLog, _ := audit.Open(filepath.Join(dataDir, "audit.jsonl"), safety.NewRedactor())
	c, _ := corpus.Parse([]byte(`{"corpus_version":"1","samples":[
	  {"id":"x","method":"GET","url":"http://127.0.0.1:1/api/a?q=1"}]}`))

	seed, _ := hex.DecodeString("00112233")
	_ = seed

	_, err := Reproduce(context.Background(), ReproduceOptions{
		CaseID: "nope-000001", Store: st, Audit: auditLog, Corpus: c,
	})
	if err == nil {
		t.Fatal("reproduce ran without a guarded client")
	}
	if !strings.Contains(err.Error(), "guarded client") {
		t.Errorf("error = %v, want it to name the missing guarded client", err)
	}
}
