package safety

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Duration is a time.Duration that marshals as a Go duration string ("500ms",
// "30s", "10m"). It is part of the JSON contract shared with the Python
// orchestrator, so the wire form stays human-readable and unambiguous.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case string:
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", value, err)
		}
		*d = Duration(parsed)
		return nil
	case float64:
		// Bare numbers are seconds.
		*d = Duration(time.Duration(value * float64(time.Second)))
		return nil
	default:
		return fmt.Errorf("invalid duration value %v", v)
	}
}

// Limits are the resource ceilings for one session. Every field is mandatory
// and must be positive: there is deliberately no "unlimited" setting, so a
// misconfigured session cannot hammer a target indefinitely.
type Limits struct {
	RequestsPerSecond  float64  `json:"requests_per_second"`
	Burst              int      `json:"burst"`
	MaxTotalRequests   int64    `json:"max_total_requests"`
	MaxConcurrency     int      `json:"max_concurrency"`
	MaxSessionDuration Duration `json:"max_session_duration"`
	RequestTimeout     Duration `json:"request_timeout"`
	MaxResponseBytes   int64    `json:"max_response_bytes"`
}

// DefaultLimits are intentionally conservative. A session that does not state
// its own limits gets these, not something permissive.
func DefaultLimits() Limits {
	return Limits{
		RequestsPerSecond:  10,
		Burst:              5,
		MaxTotalRequests:   2000,
		MaxConcurrency:     4,
		MaxSessionDuration: Duration(10 * time.Minute),
		RequestTimeout:     Duration(10 * time.Second),
		MaxResponseBytes:   2 << 20, // 2 MiB
	}
}

func (l Limits) Validate() error {
	if l.RequestsPerSecond <= 0 {
		return fmt.Errorf("%w: requests_per_second must be > 0", ErrInvalidConfig)
	}
	if l.Burst < 1 {
		return fmt.Errorf("%w: burst must be >= 1", ErrInvalidConfig)
	}
	if l.MaxTotalRequests <= 0 {
		return fmt.Errorf("%w: max_total_requests must be > 0", ErrInvalidConfig)
	}
	if l.MaxConcurrency < 1 {
		return fmt.Errorf("%w: max_concurrency must be >= 1", ErrInvalidConfig)
	}
	if l.MaxSessionDuration <= 0 {
		return fmt.Errorf("%w: max_session_duration must be > 0", ErrInvalidConfig)
	}
	if l.RequestTimeout <= 0 {
		return fmt.Errorf("%w: request_timeout must be > 0", ErrInvalidConfig)
	}
	if l.MaxResponseBytes <= 0 {
		return fmt.Errorf("%w: max_response_bytes must be > 0", ErrInvalidConfig)
	}
	return nil
}

// tokenBucket is a small rate limiter. Implemented here rather than pulled in
// as a dependency so the engine builds and tests with zero network access.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newTokenBucket(rate float64, burst int, now func() time.Time) *tokenBucket {
	if now == nil {
		now = time.Now
	}
	return &tokenBucket{
		rate:   rate,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   now(),
		now:    now,
	}
}

// wait blocks until a token is available or ctx is done.
func (b *tokenBucket) wait(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		b.mu.Lock()
		now := b.now()
		if elapsed := now.Sub(b.last); elapsed > 0 {
			b.tokens += elapsed.Seconds() * b.rate
			if b.tokens > b.burst {
				b.tokens = b.burst
			}
			b.last = now
		}
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		deficit := 1 - b.tokens
		b.mu.Unlock()

		delay := time.Duration(deficit / b.rate * float64(time.Second))
		if delay < time.Millisecond {
			delay = time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// GovernorStats is a point-in-time view used by the audit log and progress
// events.
type GovernorStats struct {
	RequestsUsed   int64         `json:"requests_used"`
	RequestsBudget int64         `json:"requests_budget"`
	InFlight       int           `json:"in_flight"`
	Elapsed        time.Duration `json:"-"`
	Stopped        bool          `json:"stopped"`

	// What became of each HTTP request charged to the budget (one per redirect
	// hop). They add up to RequestsUsed once nothing is in flight:
	//   Answered    a response was received from the target
	//   Unanswered  attempted, no response (refused connection, reset, timeout)
	//   Refused     the dialer refused the address; nothing was sent
	HTTPAnswered   int64 `json:"http_answered"`
	HTTPUnanswered int64 `json:"http_unanswered"`
	HTTPRefused    int64 `json:"http_refused"`
}

// Governor enforces every per-session limit and owns the kill switch. All
// request work must run under Context() so that Stop cuts it immediately.
type Governor struct {
	limits   Limits
	bucket   *tokenBucket
	sem      chan struct{}
	used     atomic.Int64
	inFlight atomic.Int64

	hopAnswered, hopUnanswered, hopRefused atomic.Int64
	startedAt                              time.Time
	nowFn                                  func() time.Time

	ctx      context.Context
	cancel   context.CancelCauseFunc
	stopOnce sync.Once
}

// NewGovernor validates the limits and starts the session clock.
func NewGovernor(parent context.Context, limits Limits, now func() time.Time) (*Governor, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	ctx, cancel := context.WithCancelCause(parent)
	g := &Governor{
		limits:    limits,
		bucket:    newTokenBucket(limits.RequestsPerSecond, limits.Burst, now),
		sem:       make(chan struct{}, limits.MaxConcurrency),
		startedAt: now(),
		nowFn:     now,
		ctx:       ctx,
		cancel:    cancel,
	}
	// Session duration ceiling, enforced by a watchdog that owns its own timer.
	// Storing the timer on the Governor would race: with a short duration the
	// callback can fire before the assignment completes.
	go func() {
		t := time.NewTimer(limits.MaxSessionDuration.Duration())
		defer t.Stop()
		select {
		case <-t.C:
			g.stop(ErrSessionExpired)
		case <-ctx.Done():
			// Session already finished; the watchdog exits with it.
		}
	}()
	return g, nil
}

// Context is cancelled when the session stops or expires. Every outbound
// request must derive from it.
func (g *Governor) Context() context.Context { return g.ctx }

// Limits returns the enforced limits.
func (g *Governor) Limits() Limits { return g.limits }

// Acquire blocks until the request is allowed to proceed, then returns a
// release function. Order: concurrency slot, then rate token, then budget.
func (g *Governor) Acquire(ctx context.Context) (release func(), err error) {
	if err := g.ctx.Err(); err != nil {
		return nil, stopCause(g.ctx)
	}
	if ctx == nil {
		ctx = g.ctx
	}

	select {
	case g.sem <- struct{}{}:
	case <-g.ctx.Done():
		return nil, stopCause(g.ctx)
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	releaseSlot := func() { <-g.sem }

	waitCtx, stopWait := mergeDone(ctx, g.ctx)
	err = g.bucket.wait(waitCtx)
	stopWait()
	if err != nil {
		releaseSlot()
		if g.ctx.Err() != nil {
			return nil, stopCause(g.ctx)
		}
		return nil, err
	}

	// Reserve one unit of the total budget.
	for {
		used := g.used.Load()
		if used >= g.limits.MaxTotalRequests {
			releaseSlot()
			return nil, ErrBudgetExhausted
		}
		if g.used.CompareAndSwap(used, used+1) {
			break
		}
	}

	g.inFlight.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			g.inFlight.Add(-1)
			releaseSlot()
		})
	}, nil
}

// Stop is the kill switch. It is safe to call repeatedly and from any
// goroutine; in-flight requests are cancelled through Context().
func (g *Governor) Stop() { g.stop(ErrSessionStopped) }

func (g *Governor) stop(cause error) {
	g.stopOnce.Do(func() { g.cancel(cause) })
}

// StopCause reports why the session ended, or nil if it is still running.
func (g *Governor) StopCause() error { return stopCause(g.ctx) }

func (g *Governor) Stats() GovernorStats {
	return GovernorStats{
		RequestsUsed:   g.used.Load(),
		RequestsBudget: g.limits.MaxTotalRequests,
		InFlight:       int(g.inFlight.Load()),
		Elapsed:        g.nowFn().Sub(g.startedAt),
		Stopped:        g.ctx.Err() != nil,
		HTTPAnswered:   g.hopAnswered.Load(),
		HTTPUnanswered: g.hopUnanswered.Load(),
		HTTPRefused:    g.hopRefused.Load(),
	}
}

func stopCause(ctx context.Context) error {
	if ctx.Err() == nil {
		return nil
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return ErrSessionStopped
}

// mergeDone returns a context cancelled when either input is done, plus a
// cancel func the caller must always invoke: without it the watcher goroutine
// would live until the session context ends, leaking one goroutine per request.
func mergeDone(a, b context.Context) (context.Context, context.CancelFunc) {
	if a == b {
		return a, func() {}
	}
	ctx, cancel := context.WithCancel(a)
	stop := make(chan struct{})
	go func() {
		select {
		case <-b.Done():
			cancel()
		case <-stop:
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() { close(stop) })
		cancel()
	}
}

// ReadCapped reads at most max bytes. A larger body is truncated rather than
// treated as an error: an oversized response is a legitimate observation, but
// the engine must never buffer it in full.
func ReadCapped(r io.Reader, max int64) (body []byte, truncated bool, err error) {
	if max <= 0 {
		return nil, false, fmt.Errorf("%w: max_response_bytes must be > 0", ErrInvalidConfig)
	}
	// Read one extra byte so we can tell "exactly at the cap" from "over it".
	buf, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > max {
		return buf[:max], true, nil
	}
	return buf, false, nil
}
