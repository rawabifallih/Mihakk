package runner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"mihakk/internal/audit"
	"mihakk/internal/detect"
	"mihakk/internal/mutate"
	"mihakk/internal/store"
)

// Losing a result is not a detail. A run that observed six indicators and
// stored four has not succeeded, and must not say it did: whoever reads the
// case file afterwards has no way to know something is missing unless the run
// says so.

var errDiskFull = errors.New("simulated: no space left on device")

// failingStore fails every AppendCase after the first `allow` calls.
type failingStore struct {
	mu      sync.Mutex
	inner   Store
	allow   int
	seen    int
	failAll bool
}

func (f *failingStore) SaveSession(s *store.Session) error { return f.inner.SaveSession(s) }

func (f *failingStore) AppendCase(c *store.Case) error {
	f.mu.Lock()
	f.seen++
	shouldFail := f.failAll || f.seen > f.allow
	f.mu.Unlock()
	if shouldFail {
		return errDiskFull
	}
	return f.inner.AppendCase(c)
}

// failingSessionStore fails only the final SaveSession.
type failingSessionStore struct {
	mu    sync.Mutex
	inner Store
	calls int
}

func (f *failingSessionStore) SaveSession(s *store.Session) error {
	f.mu.Lock()
	f.calls++
	shouldFail := f.calls > 1 // the first save, before the run, succeeds
	f.mu.Unlock()
	if shouldFail {
		return errDiskFull
	}
	return f.inner.SaveSession(s)
}

func (f *failingSessionStore) AppendCase(c *store.Case) error { return f.inner.AppendCase(c) }

// failingAudit fails every write after the first `allow` calls.
type failingAudit struct {
	mu    sync.Mutex
	inner AuditSink
	allow int
	seen  int
}

func (f *failingAudit) Path() string { return f.inner.Path() }

func (f *failingAudit) Write(e audit.Event) error {
	f.mu.Lock()
	f.seen++
	shouldFail := f.seen > f.allow
	f.mu.Unlock()
	if shouldFail {
		return errDiskFull
	}
	return f.inner.Write(e)
}

func detectingHarness(t *testing.T) (*harness, *fakeTestbed) {
	t.Helper()
	tb := newFakeTestbed(t)
	mutCfg := mutate.DefaultConfig()
	mutCfg.MutationsPerTarget = 24
	return newHarness(t, tb.Server, generousLimits(), mutCfg, "5eed4a11"), tb
}

func TestAFailedCaseSaveMakesTheSessionIncomplete(t *testing.T) {
	h, _ := detectingHarness(t)

	// Let the first two cases through, then lose every one after.
	broken := &failingStore{inner: h.store, allow: 2}
	r := h.runner(t, "lossy", func(o *Options) { o.Store = broken })

	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if result.Detected <= result.Saved {
		t.Fatalf("the test did not actually lose anything: detected=%d saved=%d",
			result.Detected, result.Saved)
	}
	if !result.Incomplete {
		t.Fatal("the run reported a complete result set despite failing to save cases")
	}
	if result.UnsavedCases == 0 {
		t.Error("the unsaved cases were not counted")
	}
	if result.UnsavedCases != result.Detected-result.Saved {
		t.Errorf("unsaved=%d but detected-saved=%d", result.UnsavedCases, result.Detected-result.Saved)
	}
	if !errors.Is(result.FirstStoreError, errDiskFull) {
		t.Errorf("the cause was not kept: %v", result.FirstStoreError)
	}

	// The session on disk must not claim completion.
	if result.Session.Status != store.SessionIncomplete {
		t.Fatalf("session status = %q, want %q", result.Session.Status, store.SessionIncomplete)
	}
	reloaded, err := h.store.LoadSession("lossy")
	if err != nil {
		t.Fatalf("loading the session back: %v", err)
	}
	if reloaded.Status != store.SessionIncomplete {
		t.Errorf("the stored session says %q", reloaded.Status)
	}
	if reloaded.UnsavedCases != result.UnsavedCases {
		t.Errorf("the stored session records %d unsaved cases, want %d",
			reloaded.UnsavedCases, result.UnsavedCases)
	}
	if reloaded.IncompleteReason == "" {
		t.Error("the stored session does not say why it is incomplete")
	}
	if !strings.Contains(reloaded.IncompleteReason, "subset") {
		t.Errorf("the reason does not warn that results are partial: %q", reloaded.IncompleteReason)
	}
	t.Logf("detected=%d saved=%d unsaved=%d status=%s",
		result.Detected, result.Saved, result.UnsavedCases, reloaded.Status)
}

func TestLosingEveryCaseIsStillReportedAsIncomplete(t *testing.T) {
	h, _ := detectingHarness(t)

	broken := &failingStore{inner: h.store, failAll: true}
	r := h.runner(t, "allgone", func(o *Options) { o.Store = broken })

	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Saved != 0 {
		t.Fatalf("saved = %d, want 0", result.Saved)
	}
	if result.Detected == 0 {
		t.Fatal("nothing was detected, so the test says nothing")
	}
	if !result.Incomplete {
		t.Fatal("a run that stored nothing reported a complete result set")
	}
	// An empty case file must not be readable as "nothing was found".
	if result.Session.Status == store.SessionCompleted {
		t.Error("a run that saved none of its findings was marked completed")
	}
	t.Logf("detected=%d saved=0 status=%s", result.Detected, result.Session.Status)
}

func TestAFailedAuditWriteMakesTheSessionIncomplete(t *testing.T) {
	h, _ := detectingHarness(t)

	// The session_started event succeeds; everything after it fails.
	broken := &failingAudit{inner: h.audit, allow: 1}
	r := h.runner(t, "noaudit", func(o *Options) { o.Audit = broken })

	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.AuditFailures == 0 {
		t.Fatal("a failed audit write was not counted")
	}
	if !result.Incomplete {
		t.Fatal("a run with an incomplete audit log reported success")
	}
	if !errors.Is(result.FirstAuditError, errDiskFull) {
		t.Errorf("the cause was not kept: %v", result.FirstAuditError)
	}
	if result.Session.Status != store.SessionIncomplete {
		t.Errorf("session status = %q, want %q", result.Session.Status, store.SessionIncomplete)
	}
	if !strings.Contains(result.IncompleteReason, "audit log") {
		t.Errorf("the reason does not mention the audit log: %q", result.IncompleteReason)
	}
	t.Logf("audit failures=%d reason=%s", result.AuditFailures, result.IncompleteReason)
}

// A refusal that cannot be audited is also a gap in the record.
func TestAFailedRefusalAuditIsCounted(t *testing.T) {
	h, _ := detectingHarness(t)

	// Only the session_started event gets through; every later write fails,
	// including the ones recording refusals.
	broken := &failingAudit{inner: h.audit, allow: 1}
	r := h.runner(t, "refusals", func(o *Options) { o.Audit = broken })

	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.AuditFailures == 0 {
		t.Skip("no audit writes failed in this run; nothing to assert")
	}
	if !result.Incomplete {
		t.Fatal("audit failures did not mark the run incomplete")
	}
}

// If the session record itself cannot be written, the run must report an
// error, not hand back a summary nobody can verify.
func TestAFailedSessionSaveIsAnError(t *testing.T) {
	h, _ := detectingHarness(t)

	broken := &failingSessionStore{inner: h.store}
	r := h.runner(t, "nosession", func(o *Options) { o.Store = broken })

	_, err := r.Run(context.Background())
	if err == nil {
		t.Fatal("a run whose session record could not be written returned no error")
	}
	if !errors.Is(err, errDiskFull) {
		t.Errorf("the cause was not propagated: %v", err)
	}
	if !strings.Contains(err.Error(), "complete") {
		t.Errorf("the error does not warn about completeness: %v", err)
	}
	t.Logf("error: %v", err)
}

// A clean run must still say it is complete, or the checks above prove
// nothing about the distinction.
func TestACleanRunIsNotMarkedIncomplete(t *testing.T) {
	h, _ := detectingHarness(t)
	r := h.runner(t, "clean", nil)

	result, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Incomplete {
		t.Fatalf("a clean run was marked incomplete: %s", result.IncompleteReason)
	}
	if result.UnsavedCases != 0 || result.AuditFailures != 0 {
		t.Errorf("a clean run counted failures: unsaved=%d audit=%d",
			result.UnsavedCases, result.AuditFailures)
	}
	if result.Detected != result.Saved {
		t.Errorf("detected=%d but saved=%d with no failures", result.Detected, result.Saved)
	}
	if result.Session.Status != store.SessionCompleted {
		t.Errorf("session status = %q, want %q", result.Session.Status, store.SessionCompleted)
	}
}

// Reproduce must report an audit it could not write, rather than presenting a
// result as if it had been recorded.
func TestReproduceReportsAFailedAuditWrite(t *testing.T) {
	tb := newFakeTestbed(t)
	h, saved := runAndPickCase(t, tb, detect.HTTP5xx)

	opts := h.reproduceOptions(saved.CaseID)
	opts.Audit = &failingAudit{inner: h.audit, allow: 0}

	result, err := Reproduce(context.Background(), opts)
	if err != nil {
		t.Fatalf("reproduce: %v", err)
	}
	if result.AuditFailures == 0 {
		t.Fatal("a failed audit write during reproduce was not reported")
	}
	if len(result.Warnings) == 0 {
		t.Fatal("no warning accompanies the audit failure")
	}
	if !strings.Contains(strings.Join(result.Warnings, " "), "audit log") {
		t.Errorf("the warning does not explain what is missing: %v", result.Warnings)
	}
	t.Logf("warnings: %v", result.Warnings)
}
