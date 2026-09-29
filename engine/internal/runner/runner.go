// Package runner executes a mutation plan against an authorised target.
//
// Everything this package sends goes through safety.Client. It holds no HTTP
// client of its own, constructs no transport, and opens no socket: the guarded
// client is the single way out of the process, so the scope check, the address
// pinning, the rate limit, the budget and the kill switch cannot be sidestepped
// by anything here, including a mutation that tries to rewrite its destination.
// enforcement_test.go asserts that structurally, on the source.
package runner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mihakk/internal/audit"
	"mihakk/internal/corpus"
	"mihakk/internal/detect"
	"mihakk/internal/events"
	"mihakk/internal/mutate"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

// Store is what the runner needs from a case store. It is an interface so a
// failing one can be substituted in tests: a write failure that is only
// reachable by breaking the filesystem is a write failure that never gets
// tested.
type Store interface {
	SaveSession(*store.Session) error
	AppendCase(*store.Case) error
}

// CaseFinder is what reproduce needs.
type CaseFinder interface {
	FindCase(caseID string) (*store.Case, *store.Session, error)
}

// AuditSink is the append-only audit log.
type AuditSink interface {
	Write(audit.Event) error
	Path() string
}

// BaselineRepeats is how many times each unmutated sample is sent before
// fuzzing starts. Three is enough for a median and a spread without spending
// a meaningful share of the request budget.
const BaselineRepeats = 3

// Options configures one run.
type Options struct {
	SessionID     string
	EngineVersion string
	Seed          []byte

	Client   *safety.Client
	Governor *safety.Governor
	Plan     *mutate.Plan
	Corpus   *corpus.Corpus
	Config   *safety.SessionConfig

	Detector *detect.Detector
	Store    Store
	Audit    AuditSink
	Redactor *safety.Redactor

	// MaxCases caps how many plan entries to execute. Zero runs the whole
	// plan, subject to the governor's own budget.
	MaxCases int

	// Workers is the generator-side concurrency. The governor enforces the
	// real ceiling; this only decides how many goroutines ask.
	Workers int

	// OnProgress, if set, is called as cases complete.
	OnProgress func(Progress)

	// OnEvent, if set, receives the run's event stream. The sequence number
	// is assigned by whatever consumes this, not here: numbering belongs with
	// the buffer that has to keep the sequence contiguous.
	OnEvent func(events.Event) int64

	Now func() time.Time
}

// Progress is a point-in-time view of the run.
type Progress struct {
	Executed  int
	Attempted int
	Saved     int
	Refused   int
	Planned   int
}

// baselineCounts is what became of the baseline. Attempted and refused may
// overlap when an earlier redirect hop was attempted before a later hop was
// locally refused; answered means the chain reached a final response. Written
// once, before the workers start, and only read after.
type baselineCounts struct {
	attempted, refused, answered int
}

// Result summarises a finished run.
type Result struct {
	Session  *store.Session
	Cases    []*store.Case
	Executed int
	Saved    int
	Refused  int
	Stopped  bool

	// What became of the requests beyond the case counts; see store.Accounting.
	Accounting store.Accounting
	StopCause  error

	// Detected is how many indicator-bearing cases were observed. It differs
	// from Saved when writing one failed, and that difference is the whole
	// point: a run that found six things and stored four has not succeeded.
	Detected int

	// UnsavedCases and AuditFailures count what was observed but not written
	// down. Incomplete is true when either is non-zero, and IncompleteReason
	// says what went wrong and what it means.
	UnsavedCases     int
	AuditFailures    int
	Incomplete       bool
	IncompleteReason string

	// FirstStoreError and FirstAuditError are kept so the cause is reportable
	// rather than merely counted.
	FirstStoreError error
	FirstAuditError error
}

// writeFailures counts and remembers failures to persist what was observed.
type writeFailures struct {
	mu         sync.Mutex
	stores     int
	audits     int
	firstStore error
	firstAudit error
}

func (w *writeFailures) store(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stores++
	if w.firstStore == nil {
		w.firstStore = err
	}
}

func (w *writeFailures) audit(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.audits++
	if w.firstAudit == nil {
		w.firstAudit = err
	}
}

func (w *writeFailures) snapshot() (stores, audits int, firstStore, firstAudit error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stores, w.audits, w.firstStore, w.firstAudit
}

// Runner executes a plan.
type Runner struct {
	opts     Options
	now      func() time.Time
	failures *writeFailures
	baseline baselineCounts
	// Case attempts and final responses. Fields rather than more reportProgress
	// arguments because every call site already has them in reach.
	attempted, answered atomic.Int64
}

// New validates the options and returns a runner.
func New(opts Options) (*Runner, error) {
	switch {
	case opts.Client == nil:
		return nil, errors.New("mihakk: runner needs a guarded client")
	case opts.Governor == nil:
		return nil, errors.New("mihakk: runner needs a governor")
	case opts.Plan == nil:
		return nil, errors.New("mihakk: runner needs a mutation plan")
	case opts.Corpus == nil:
		return nil, errors.New("mihakk: runner needs a corpus")
	case opts.Config == nil:
		return nil, errors.New("mihakk: runner needs a session config")
	case opts.Store == nil:
		return nil, errors.New("mihakk: runner needs a store")
	case opts.SessionID == "":
		return nil, errors.New("mihakk: runner needs a session id")
	}
	if opts.Detector == nil {
		opts.Detector = detect.New(detect.DefaultConfig())
	}
	if opts.Redactor == nil {
		opts.Redactor = safety.NewRedactor()
	}
	if opts.Workers < 1 {
		opts.Workers = opts.Governor.Limits().MaxConcurrency
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	// A mutation can leave a body that is no longer valid JSON -- a bit flip,
	// a truncation -- and a redactor that works by field name has nothing to
	// match on any more. The values themselves are known from the corpus, so
	// they are registered as literals and removed wherever they appear, in
	// whatever the mutation turned the request into.
	seedRedactorFromCorpus(opts.Redactor, opts.Corpus)

	return &Runner{opts: opts, now: now, failures: &writeFailures{}}, nil
}

// seedRedactorFromCorpus registers the literal value of every sensitive
// header, query parameter and JSON field found in the samples.
func seedRedactorFromCorpus(red *safety.Redactor, c *corpus.Corpus) {
	if red == nil || c == nil {
		return
	}
	for i := range c.Samples {
		sample := &c.Samples[i]

		for _, name := range sample.HeaderNames() {
			if !red.IsSensitiveName(name) {
				continue
			}
			for _, v := range sample.Headers[name] {
				red.AddLiteral(v)
			}
		}

		if u, err := sample.ParsedURL(); err == nil {
			for key, values := range u.Query() {
				if !red.IsSensitiveName(key) {
					continue
				}
				for _, v := range values {
					red.AddLiteral(v)
				}
			}
		}

		body, err := sample.DecodedBody()
		if err != nil || len(body) == 0 {
			continue
		}
		var doc any
		if json.Unmarshal(body, &doc) == nil {
			collectSensitiveLiterals(red, doc)
		}
	}
}

func collectSensitiveLiterals(red *safety.Redactor, node any) {
	switch t := node.(type) {
	case map[string]any:
		for key, value := range t {
			if red.IsSensitiveName(key) {
				if s, ok := value.(string); ok {
					red.AddLiteral(s)
					continue
				}
			}
			collectSensitiveLiterals(red, value)
		}
	case []any:
		for _, item := range t {
			collectSensitiveLiterals(red, item)
		}
	}
}

// Run gathers a baseline, executes the plan, and stores every case that
// raised an indicator.
func (r *Runner) Run(ctx context.Context) (*Result, error) {
	o := r.opts

	// One snapshot, taken from the client that enforces it, and everything
	// scope-facing in the record derives from that snapshot: the digest, the
	// readable target list, and through them the audit event and any later report.
	// Deriving the digest from o.Config while the client enforced something else
	// would let two parts of the same record describe different scopes.
	enforced := o.Client.Scope()

	sess := &store.Session{
		SessionID:      o.SessionID,
		EngineVersion:  o.EngineVersion,
		StartedAt:      r.now().UTC(),
		Operator:       o.Config.Authorization.Operator,
		Scope:          &enforced,
		ScopeDigest:    enforced.Digest(),
		ConfigDigest:   o.Plan.ConfigDigest(),
		CorpusDigest:   o.Plan.CorpusDigest(),
		MasterSeed:     hex.EncodeToString(o.Seed),
		Targets:        targetsFromScope(&enforced),
		PlannedCases:   r.plannedCases(),
		Baselines:      map[string]*detect.Baseline{},
		MutationConfig: o.Plan.Config(),
	}

	r.emit(events.Event{
		Type: events.Started,
		Progress: &events.ProgressInfo{
			Planned:        sess.PlannedCases,
			RequestsBudget: o.Governor.Limits().MaxTotalRequests,
		},
	})

	if err := r.auditSessionStarted(sess); err != nil {
		return nil, err
	}
	if err := o.Store.SaveSession(sess); err != nil {
		return nil, err
	}

	// 1. Baseline. Unmutated samples, through the same guarded client, so
	//    they are rate-limited and counted like everything else.
	baselines := r.collectBaselines(ctx)
	sess.Baselines = baselines
	// Reported now, not with the first case: a run whose every case is then
	// refused would otherwise never say what its baseline did.
	var zero atomic.Int64
	r.reportProgress(&zero, &zero, &zero, r.plannedCases())

	// 2. The plan itself.
	result := r.executePlan(ctx, sess, baselines)

	sess.EndedAt = timePtr(r.now().UTC())
	sess.ExecutedCases = result.Executed
	sess.SavedCases = result.Saved
	sess.RefusedCases = result.Refused
	stats := o.Governor.Stats()
	result.Accounting = store.Accounting{
		CasesAttempted:    int(r.attempted.Load()),
		CasesAnswered:     int(r.answered.Load()),
		BaselineAttempted: r.baseline.attempted,
		BaselineRefused:   r.baseline.refused,
		BaselineAnswered:  r.baseline.answered,
		HTTPAnswered:      stats.HTTPAnswered,
		HTTPUnanswered:    stats.HTTPUnanswered,
		HTTPRefused:       stats.HTTPRefused,
	}
	accounting := result.Accounting
	sess.Accounting = &accounting
	sess.Status = store.SessionCompleted
	if cause := o.Governor.StopCause(); cause != nil {
		sess.Status = store.SessionStopped
		sess.StopReason = cause.Error()
		result.Stopped = true
		result.StopCause = cause
	}

	// Record the stop before folding in the failure counts, so a failure to
	// write *this* event is itself counted.
	if err := r.auditSessionStopped(sess); err != nil {
		r.failures.audit(err)
	}

	stores, audits, firstStore, firstAudit := r.failures.snapshot()
	result.UnsavedCases = stores
	result.AuditFailures = audits
	result.FirstStoreError = firstStore
	result.FirstAuditError = firstAudit

	if stores > 0 || audits > 0 {
		result.Incomplete = true
		result.IncompleteReason = incompleteReason(stores, audits, firstStore, firstAudit)

		// A consumer watching only the stream must learn about this too.
		r.emit(events.Event{
			Type: events.Warning,
			Warning: &events.WarningInfo{
				Code:          "results_not_persisted",
				Message:       result.IncompleteReason,
				EventsDropped: int64(stores),
			},
		})

		sess.UnsavedCases = stores
		sess.AuditFailures = audits
		sess.IncompleteReason = result.IncompleteReason
		// Not "completed": the stored results are a subset of what was seen.
		if sess.Status == store.SessionCompleted {
			sess.Status = store.SessionIncomplete
		}
	}

	if err := o.Store.SaveSession(sess); err != nil {
		return nil, fmt.Errorf("mihakk: the run finished but its session record could not be written, "+
			"so nothing about it can be trusted as complete: %w", err)
	}

	result.Session = sess
	return result, nil
}

// incompleteReason states plainly what was lost and what that means.
func incompleteReason(stores, audits int, firstStore, firstAudit error) string {
	var parts []string
	if stores > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d observed indicator(s) could not be written to the case store (first error: %v); "+
				"the saved results are a subset of what was found", stores, firstStore))
	}
	if audits > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d audit event(s) could not be recorded (first error: %v); "+
				"the audit log does not fully describe this run", audits, firstAudit))
	}
	return strings.Join(parts, "; ")
}

func (r *Runner) plannedCases() int {
	total := r.opts.Plan.Total()
	if r.opts.MaxCases > 0 && r.opts.MaxCases < total {
		return r.opts.MaxCases
	}
	return total
}

// baselineKey groups observations by what is being measured: one endpoint,
// one method.
func baselineKey(method, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return method + " " + rawURL
	}
	return method + " " + u.Host + u.Path
}

// collectBaselines sends each unmutated sample a few times to learn what
// normal looks like.
func (r *Runner) collectBaselines(ctx context.Context) map[string]*detect.Baseline {
	out := map[string]*detect.Baseline{}
	observations := map[string][]detect.Observation{}

	for i := range r.opts.Corpus.Samples {
		sample := &r.opts.Corpus.Samples[i]
		key := baselineKey(sample.Method, sample.URL)

		for n := 0; n < BaselineRepeats; n++ {
			if r.opts.Governor.StopCause() != nil {
				break
			}
			req, err := buildRequest(sample.Method, sample.URL, sample.Headers, bodyOf(sample))
			if err != nil {
				continue
			}
			obs, accounting := r.send(ctx, req)
			// Attempted is independent of the terminal outcome. A redirect can
			// receive one response, then end when a later hop is refused.
			if accounting.Attempted() {
				r.baseline.attempted++
			}
			if accounting.FinalResponseObserved {
				r.baseline.answered++
			}
			if obs.Err != nil && isSafetyRefusal(obs.Err) {
				r.baseline.refused++
			}
			observations[key] = append(observations[key], obs)
		}
	}

	for key, obs := range observations {
		out[key] = detect.BuildBaseline(key, obs)
	}
	return out
}

// executePlan runs the mutation cases through a worker pool.
func (r *Runner) executePlan(ctx context.Context, sess *store.Session, baselines map[string]*detect.Baseline) *Result {
	o := r.opts
	total := r.plannedCases()

	var executed, saved, refused, detected atomic.Int64
	var mu sync.Mutex
	var cases []*store.Case

	indices := make(chan int)
	var wg sync.WaitGroup

	// When a worker hits a terminal condition -- the budget is spent, the
	// session was stopped -- every worker returns. Without a way to tell the
	// feeder, it then blocks sending into a channel nobody reads, and the run
	// hangs until the session duration expires. Closing this is what turns
	// "the budget ran out" into an immediate finish.
	var haltOnce sync.Once
	halted := make(chan struct{})
	halt := func() { haltOnce.Do(func() { close(halted) }) }

	for w := 0; w < o.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer halt()
			for index := range indices {
				if o.Governor.StopCause() != nil || ctx.Err() != nil {
					return
				}

				generated, err := o.Plan.Case(index)
				if err != nil {
					// A case the generator cannot produce is skipped rather
					// than aborting the run; later phases surface these.
					refused.Add(1)
					r.reportProgress(&executed, &saved, &refused, total)
					continue
				}

				req, err := buildRequest(generated.Request.Method, generated.Request.URL,
					generated.Request.Headers, generated.Request.Body)
				if err != nil {
					refused.Add(1)
					r.reportProgress(&executed, &saved, &refused, total)
					continue
				}

				obs, accounting := r.send(ctx, req)
				if accounting.Attempted() {
					r.attempted.Add(1)
				}
				if accounting.FinalResponseObserved {
					r.answered.Add(1)
				}

				// A local refusal is not a result about the refused hop. Earlier
				// redirect hops, if any, remain visible in the HTTP accounting.
				if obs.Err != nil && isSafetyRefusal(obs.Err) {
					refused.Add(1)
					r.auditRefusal(sess.SessionID, generated, obs.Err, accounting)
					// Reported like any other case. Progress used to be sent only
					// after a case that left, so a run whose every case was refused
					// never said so: its stream held "started" and "done" and
					// nothing between, and every reader took the silence for zero.
					r.reportProgress(&executed, &saved, &refused, total)
					if errors.Is(obs.Err, safety.ErrBudgetExhausted) ||
						errors.Is(obs.Err, safety.ErrSessionStopped) ||
						errors.Is(obs.Err, safety.ErrSessionExpired) {
						return
					}
					continue
				}

				executed.Add(1)
				baseline := baselines[baselineKey(generated.Request.Method, generated.Request.URL)]
				indicators := o.Detector.Evaluate(obs, baseline)
				if len(indicators) == 0 {
					r.reportProgress(&executed, &saved, &refused, total)
					continue
				}

				detected.Add(1)
				c := r.buildCase(sess, generated, obs, indicators)
				if err := o.Store.AppendCase(c); err != nil {
					// The indicator was real; only the record of it was lost.
					// Counting it here is what stops the run reporting a clean
					// finish over a result set that is missing entries.
					r.failures.store(err)
				} else {
					saved.Add(1)
					mu.Lock()
					cases = append(cases, c)
					mu.Unlock()
					r.emitFinding(c)
				}
				r.reportProgress(&executed, &saved, &refused, total)
			}
		}()
	}

feed:
	for i := 0; i < total; i++ {
		select {
		case indices <- i:
		case <-halted:
			break feed
		case <-ctx.Done():
			break feed
		case <-o.Governor.Context().Done():
			break feed
		}
	}
	close(indices)
	wg.Wait()

	return &Result{
		Cases:    cases,
		Executed: int(executed.Load()),
		Saved:    int(saved.Load()),
		Refused:  int(refused.Load()),
		Detected: int(detected.Load()),
	}
}

func (r *Runner) reportProgress(executed, saved, refused *atomic.Int64, planned int) {
	p := Progress{
		Executed:  int(executed.Load()),
		Attempted: int(r.attempted.Load()),
		Saved:     int(saved.Load()),
		Refused:   int(refused.Load()),
		Planned:   planned,
	}
	if r.opts.OnProgress != nil {
		r.opts.OnProgress(p)
	}
	if r.opts.OnEvent != nil {
		stats := r.opts.Governor.Stats()
		r.emit(events.Event{
			Type: events.Progress,
			Progress: &events.ProgressInfo{
				RequestsUsed:      stats.RequestsUsed,
				RequestsBudget:    stats.RequestsBudget,
				Executed:          p.Executed,
				Saved:             p.Saved,
				Refused:           p.Refused,
				Planned:           p.Planned,
				Attempted:         p.Attempted,
				Answered:          int(r.answered.Load()),
				BaselineAttempted: r.baseline.attempted,
				BaselineRefused:   r.baseline.refused,
				BaselineAnswered:  r.baseline.answered,
				HTTPAnswered:      stats.HTTPAnswered,
				HTTPUnanswered:    stats.HTTPUnanswered,
				HTTPRefused:       stats.HTTPRefused,
				ElapsedMS:         stats.Elapsed.Milliseconds(),
			},
		})
	}
}

// emit sends one event, if anything is listening.
func (r *Runner) emit(e events.Event) {
	if r.opts.OnEvent == nil {
		return
	}
	r.opts.OnEvent(e)
}

// emitFinding streams a saved case. The case is already redacted: the same
// record that goes to disk goes on the wire, so there is no second path that
// could carry a secret the first one removed.
func (r *Runner) emitFinding(c *store.Case) {
	if r.opts.OnEvent == nil {
		return
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return
	}
	r.emit(events.Event{Type: events.Finding, Finding: payload})
}

// send performs one request through the guarded client and turns the outcome
// into an observation. This is the only place in the package that transmits.
func (r *Runner) send(ctx context.Context, req *http.Request) (detect.Observation, safety.RequestAccounting) {
	started := r.now()
	resp, err := r.opts.Client.Do(ctx, req)
	var accounting safety.RequestAccounting
	if resp != nil {
		accounting = resp.Accounting
	}
	if err != nil {
		return detect.Observation{
			Err:      err,
			TimedOut: isTimeout(err),
			Latency:  r.now().Sub(started),
		}, accounting
	}
	return detect.Observation{
		StatusCode: resp.StatusCode,
		Latency:    resp.Latency,
		Body:       resp.Body,
		BodyBytes:  len(resp.Body),
		Truncated:  resp.Truncated,
	}, accounting
}

// buildCase assembles the stored record: a regeneration recipe plus a
// redacted summary for a human.
func (r *Runner) buildCase(sess *store.Session, generated *mutate.Case,
	obs detect.Observation, indicators []detect.Indicator) *store.Case {

	red := r.opts.Redactor
	headers := http.Header{}
	for name, values := range generated.Request.Headers {
		for _, v := range values {
			headers.Add(name, v)
		}
	}
	parsedURL, _ := url.Parse(generated.Request.URL)

	c := &store.Case{
		CaseID:     store.CaseID(sess.SessionID, generated.Index),
		SessionID:  sess.SessionID,
		ObservedAt: r.now().UTC(),
		Status:     store.StatusNeedsVerification,
		Reproduction: store.Reproduction{
			EngineVersion: sess.EngineVersion,
			MasterSeed:    sess.MasterSeed,
			CaseIndex:     generated.Index,
			CorpusDigest:  sess.CorpusDigest,
			ConfigDigest:  sess.ConfigDigest,
			Target: fmt.Sprintf("%s %s/%s (%s)", generated.SampleID,
				generated.TargetKind, generated.TargetName, generated.Mutator),
		},
		RequestSummary: store.RequestSummary{
			Method:  generated.Request.Method,
			URL:     red.URL(parsedURL),
			Headers: red.Headers(headers),
			// Redact first, then truncate. Truncating first can cut a JSON
			// body mid-document, which makes it unparseable, which drops the
			// redactor onto its pattern-matching fallback and past any secret
			// that is not credential-shaped.
			BodyPreview: string(previewOf(red.Body(generated.Request.Body), 512)),
			BodyBytes:   len(generated.Request.Body),
			Redacted:    true,
		},
		Indicators: indicators,
	}

	if obs.Err != nil {
		msg := red.String(obs.Err.Error())
		c.ResponseSummary = store.ResponseSummary{Error: &msg}
	} else {
		status := obs.StatusCode
		latency := float64(obs.Latency) / float64(time.Millisecond)
		bytesRead := obs.BodyBytes
		c.ResponseSummary = store.ResponseSummary{
			StatusCode: &status,
			LatencyMS:  &latency,
			BodyBytes:  &bytesRead,
			Truncated:  obs.Truncated,
		}
	}
	return c
}

func (r *Runner) auditSessionStarted(sess *store.Session) error {
	if r.opts.Audit == nil {
		return nil
	}
	ack := r.opts.Config.Authorization
	limits := r.opts.Governor.Limits()
	return r.opts.Audit.Write(audit.Event{
		Type:          audit.SessionStarted,
		SessionID:     sess.SessionID,
		Operator:      ack.Operator,
		Statement:     ack.Statement,
		AckedAt:       &ack.AckedAt,
		ScopeDigest:   sess.ScopeDigest,
		EngineVersion: sess.EngineVersion,
		ConfigDigest:  sess.ConfigDigest,
		CorpusDigest:  sess.CorpusDigest,
		Seed:          sess.MasterSeed,
		Targets:       sess.Targets,
		Limits:        &limits,
		Stats:         map[string]any{"planned_cases": sess.PlannedCases},
	})
}

func (r *Runner) auditSessionStopped(sess *store.Session) error {
	if r.opts.Audit == nil {
		return nil
	}
	return r.opts.Audit.Write(audit.Event{
		Type:          audit.SessionStopped,
		SessionID:     sess.SessionID,
		Operator:      sess.Operator,
		ScopeDigest:   sess.ScopeDigest,
		EngineVersion: sess.EngineVersion,
		Outcome:       sess.Status,
		Reason:        sess.StopReason,
		Stats: map[string]any{
			"executed_cases": sess.ExecutedCases,
			"saved_cases":    sess.SavedCases,
			"refused_cases":  sess.RefusedCases,
			"planned_cases":  sess.PlannedCases,
			"accounting":     sess.Accounting,
		},
	})
}

func (r *Runner) auditRefusal(sessionID string, generated *mutate.Case, err error,
	accounting safety.RequestAccounting) {
	if r.opts.Audit == nil {
		return
	}
	parsed, _ := url.Parse(generated.Request.URL)
	outcome := "not_sent"
	detail := ""
	if accounting.Attempted() {
		outcome = "refused_after_attempt"
		detail = fmt.Sprintf("%d HTTP request(s) were attempted before a later hop was refused",
			accounting.HTTPAnswered+accounting.HTTPUnanswered)
	}
	r.failures.audit(r.opts.Audit.Write(audit.Event{
		Type:      audit.RequestRefused,
		SessionID: sessionID,
		CaseID:    store.CaseID(sessionID, generated.Index),
		Outcome:   outcome,
		Reason:    err.Error(),
		Detail:    detail,
		Targets:   []string{r.opts.Redactor.URL(parsed)},
	}))
}

// isSafetyRefusal reports whether the request was stopped by the safety layer
// rather than by the target.
func isSafetyRefusal(err error) bool {
	for _, sentinel := range []error{
		safety.ErrOutOfScope, safety.ErrRedirectOutOfScope, safety.ErrTooManyRedirects,
		safety.ErrDisallowedAddress, safety.ErrAddressNotPinned,
		safety.ErrBudgetExhausted, safety.ErrSessionStopped, safety.ErrSessionExpired,
		safety.ErrNoAuthorization, safety.ErrAuthorizationInvalid,
		safety.ErrAuthorizationScopeMismatch, safety.ErrInvalidConfig,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var timeouter interface{ Timeout() bool }
	if errors.As(err, &timeouter) {
		return timeouter.Timeout()
	}
	return false
}

// validHeaderValue mirrors what net/http will accept. A mutation can produce
// a header value containing, say, an escape character: net/http rejects the
// request outright, nothing is sent, and the failure has nothing to do with
// the target. Catching it here means such a case is counted as not sent
// rather than surfacing as a connection_error indicator against an endpoint
// that never saw it.
func validHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b == '\t' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func buildRequest(method, rawURL string, headers map[string][]string, body []byte) (*http.Request, error) {
	var reader *bytes.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		return nil, err
	}
	for name, values := range headers {
		for _, v := range values {
			if !validHeaderValue(v) {
				return nil, fmt.Errorf("mihakk: the generated header %s contains a byte "+
					"net/http will not transmit, so this case cannot be sent", name)
			}
			req.Header.Add(name, v)
		}
	}
	return req, nil
}

func bodyOf(s *corpus.Sample) []byte {
	b, err := s.DecodedBody()
	if err != nil {
		return nil
	}
	return b
}

func previewOf(body []byte, max int) []byte {
	if len(body) <= max {
		return body
	}
	return body[:max]
}

// targetsFromScope builds the readable target list from a scope, so the list and
// the digest recorded beside it always describe the same thing.
func targetsFromScope(scope *safety.Scope) []string {
	var out []string
	for _, t := range scope.Targets {
		out = append(out, fmt.Sprintf("%s://%s", t.Scheme, t.Authority()))
	}
	return out
}

func timePtr(t time.Time) *time.Time { return &t }
