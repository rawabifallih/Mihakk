package safety

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func fastLimits() Limits {
	return Limits{
		RequestsPerSecond:  1000,
		Burst:              1000,
		MaxTotalRequests:   1000,
		MaxConcurrency:     8,
		MaxSessionDuration: Duration(time.Minute),
		RequestTimeout:     Duration(time.Second),
		MaxResponseBytes:   1 << 20,
	}
}

func TestLimitsRejectNonPositiveValues(t *testing.T) {
	// There is deliberately no "unlimited" setting: every ceiling must be set.
	base := fastLimits()
	mutators := map[string]func(*Limits){
		"requests_per_second": func(l *Limits) { l.RequestsPerSecond = 0 },
		"burst":               func(l *Limits) { l.Burst = 0 },
		"max_total_requests":  func(l *Limits) { l.MaxTotalRequests = 0 },
		"max_concurrency":     func(l *Limits) { l.MaxConcurrency = 0 },
		"max_session_dur":     func(l *Limits) { l.MaxSessionDuration = 0 },
		"request_timeout":     func(l *Limits) { l.RequestTimeout = 0 },
		"max_response_bytes":  func(l *Limits) { l.MaxResponseBytes = 0 },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			l := base
			mutate(&l)
			if err := l.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate() = %v, want ErrInvalidConfig", err)
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Validate() on good limits = %v", err)
	}
}

func TestGovernorEnforcesRequestRate(t *testing.T) {
	l := fastLimits()
	l.RequestsPerSecond = 20
	l.Burst = 1
	g, err := NewGovernor(context.Background(), l, nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	defer g.Stop()

	start := time.Now()
	for i := 0; i < 4; i++ {
		release, err := g.Acquire(context.Background())
		if err != nil {
			t.Fatalf("Acquire %d: %v", i, err)
		}
		release()
	}
	// 1 burst token then 3 refills at 20/s = at least 150ms. Assert a lower
	// bound only; upper bounds on a shared CI machine are how tests flake.
	if elapsed := time.Since(start); elapsed < 120*time.Millisecond {
		t.Fatalf("4 acquires at 20/s took %v, want >= 120ms", elapsed)
	}
}

func TestGovernorEnforcesConcurrency(t *testing.T) {
	l := fastLimits()
	l.MaxConcurrency = 2
	g, err := NewGovernor(context.Background(), l, nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	defer g.Stop()

	var mu sync.Mutex
	current, peak := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := g.Acquire(context.Background())
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			mu.Lock()
			current++
			if current > peak {
				peak = current
			}
			mu.Unlock()

			time.Sleep(10 * time.Millisecond)

			mu.Lock()
			current--
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()

	if peak > l.MaxConcurrency {
		t.Fatalf("peak concurrency = %d, want <= %d", peak, l.MaxConcurrency)
	}
	if peak < 2 {
		t.Fatalf("peak concurrency = %d, expected the pool to actually run in parallel", peak)
	}
}

func TestGovernorEnforcesTotalBudget(t *testing.T) {
	l := fastLimits()
	l.MaxTotalRequests = 3
	g, err := NewGovernor(context.Background(), l, nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	defer g.Stop()

	for i := 0; i < 3; i++ {
		release, err := g.Acquire(context.Background())
		if err != nil {
			t.Fatalf("Acquire %d: %v", i, err)
		}
		release()
	}
	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("Acquire past budget = %v, want ErrBudgetExhausted", err)
	}
	if got := g.Stats().RequestsUsed; got != 3 {
		t.Fatalf("RequestsUsed = %d, want 3", got)
	}
}

// TestGovernorStopIsImmediate is the kill switch: callers already blocked on a
// concurrency slot or a rate token must come back promptly once Stop is called.
func TestGovernorStopIsImmediate(t *testing.T) {
	l := fastLimits()
	l.MaxConcurrency = 1
	l.RequestsPerSecond = 0.5 // slow enough that waiters are genuinely parked
	l.Burst = 1
	g, err := NewGovernor(context.Background(), l, nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}

	held, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}

	const waiters = 5
	errs := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			release, err := g.Acquire(context.Background())
			if release != nil {
				release()
			}
			errs <- err
		}()
	}

	time.Sleep(20 * time.Millisecond) // let them park
	stopAt := time.Now()
	g.Stop()
	held()

	for i := 0; i < waiters; i++ {
		select {
		case err := <-errs:
			if !errors.Is(err, ErrSessionStopped) {
				t.Fatalf("waiter %d = %v, want ErrSessionStopped", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("waiter %d did not return within 1s of Stop()", i)
		}
	}
	if elapsed := time.Since(stopAt); elapsed > time.Second {
		t.Fatalf("Stop() took %v to release all waiters, want < 1s", elapsed)
	}
	if !errors.Is(g.StopCause(), ErrSessionStopped) {
		t.Fatalf("StopCause() = %v, want ErrSessionStopped", g.StopCause())
	}
	if !g.Stats().Stopped {
		t.Fatal("Stats().Stopped = false after Stop()")
	}
}

func TestGovernorStopIsIdempotent(t *testing.T) {
	g, err := NewGovernor(context.Background(), fastLimits(), nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	g.Stop()
	g.Stop()
	g.Stop()
	if !errors.Is(g.StopCause(), ErrSessionStopped) {
		t.Fatalf("StopCause() = %v", g.StopCause())
	}
}

func TestGovernorEnforcesSessionDuration(t *testing.T) {
	l := fastLimits()
	l.MaxSessionDuration = Duration(40 * time.Millisecond)
	g, err := NewGovernor(context.Background(), l, nil)
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}
	defer g.Stop()

	deadline := time.After(2 * time.Second)
	for {
		if _, err := g.Acquire(context.Background()); err != nil {
			if !errors.Is(err, ErrSessionExpired) {
				t.Fatalf("Acquire after expiry = %v, want ErrSessionExpired", err)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("session never expired")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReadCappedTruncatesOversizedBodies(t *testing.T) {
	body := strings.Repeat("a", 5000)

	got, truncated, err := ReadCapped(strings.NewReader(body), 1000)
	if err != nil {
		t.Fatalf("ReadCapped: %v", err)
	}
	if !truncated {
		t.Fatal("truncated = false, want true")
	}
	if len(got) != 1000 {
		t.Fatalf("len = %d, want 1000", len(got))
	}

	got, truncated, err = ReadCapped(strings.NewReader("short"), 1000)
	if err != nil {
		t.Fatalf("ReadCapped: %v", err)
	}
	if truncated || string(got) != "short" {
		t.Fatalf("got (%q, %v), want (\"short\", false)", got, truncated)
	}

	// Exactly at the cap must not be reported as truncated.
	exact := strings.Repeat("b", 100)
	got, truncated, err = ReadCapped(strings.NewReader(exact), 100)
	if err != nil {
		t.Fatalf("ReadCapped: %v", err)
	}
	if truncated || len(got) != 100 {
		t.Fatalf("exact-fit body reported as (len=%d, truncated=%v)", len(got), truncated)
	}
}

func TestDurationJSONRoundTrip(t *testing.T) {
	var l Limits
	raw := `{"requests_per_second":5,"burst":2,"max_total_requests":10,"max_concurrency":2,
	         "max_session_duration":"90s","request_timeout":3,"max_response_bytes":1024}`
	if err := json.Unmarshal([]byte(raw), &l); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if l.MaxSessionDuration.Duration() != 90*time.Second {
		t.Fatalf("max_session_duration = %v, want 90s", l.MaxSessionDuration.Duration())
	}
	if l.RequestTimeout.Duration() != 3*time.Second {
		t.Fatalf("request_timeout = %v, want 3s (bare numbers are seconds)", l.RequestTimeout.Duration())
	}
	out, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(out), `"max_session_duration":"1m30s"`) {
		t.Fatalf("marshalled form = %s, want a duration string", out)
	}
}
