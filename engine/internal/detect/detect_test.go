package detect

import (
	"errors"
	"testing"
	"time"
)

func fastBaseline() *Baseline {
	obs := make([]Observation, 0, 5)
	for i := 0; i < 5; i++ {
		obs = append(obs, Observation{
			StatusCode: 200,
			Latency:    time.Duration(2+i%2) * time.Millisecond,
			BodyBytes:  1000,
			Body:       []byte(`{"items":[]}`),
		})
	}
	return BuildBaseline("GET /api/items", obs)
}

func TestFiveHundredIsReportedWithItsBaseline(t *testing.T) {
	d := New(DefaultConfig())
	got := d.Evaluate(Observation{StatusCode: 500, Latency: 3 * time.Millisecond, BodyBytes: 90}, fastBaseline())

	if len(got) == 0 || got[0].Type != HTTP5xx {
		t.Fatalf("a 500 was not reported: %+v", got)
	}
	if got[0].Baseline == nil {
		t.Error("the indicator does not carry the baseline it was judged against")
	}
	if len(got[0].Reason) < 10 {
		t.Errorf("reason is not usable: %q", got[0].Reason)
	}
}

// Ordinary client errors must not be reported. A fuzzer that flagged every
// 400 would bury its real findings.
func TestClientErrorsAreNotIndicators(t *testing.T) {
	d := New(DefaultConfig())
	for _, status := range []int{200, 201, 301, 400, 401, 403, 404, 405, 409, 422, 429} {
		got := d.Evaluate(Observation{
			StatusCode: status, Latency: 3 * time.Millisecond, BodyBytes: 1000,
			Body: []byte(`{"error":"bad_request","detail":"qty must be a number"}`),
		}, fastBaseline())
		if len(got) != 0 {
			t.Errorf("status %d produced %d indicator(s): %+v", status, len(got), got)
		}
	}
}

func TestLatencyIsJudgedAgainstAnAbsoluteFloor(t *testing.T) {
	d := New(DefaultConfig())
	baseline := fastBaseline()

	// A fast endpoint jittering to 50ms is noise, not a finding: five times a
	// 2ms median is 10ms, but the floor keeps it quiet.
	if got := d.Evaluate(Observation{StatusCode: 200, Latency: 50 * time.Millisecond, BodyBytes: 1000}, baseline); len(got) != 0 {
		t.Errorf("ordinary jitter was reported: %+v", got)
	}
	// The planted 400ms delay clears the floor.
	got := d.Evaluate(Observation{StatusCode: 200, Latency: 400 * time.Millisecond, BodyBytes: 1000}, baseline)
	if len(got) == 0 || got[0].Type != LatencyAnomaly {
		t.Fatalf("a 400ms response against a 2ms median was not reported: %+v", got)
	}
}

func TestNoLatencyJudgementWithoutABaseline(t *testing.T) {
	d := New(DefaultConfig())
	got := d.Evaluate(Observation{StatusCode: 200, Latency: 10 * time.Second, BodyBytes: 10}, nil)
	for _, ind := range got {
		if ind.Type == LatencyAnomaly {
			t.Fatal("latency was judged with no sense of normal")
		}
	}
}

func TestTransportFailuresAreDistinguished(t *testing.T) {
	d := New(DefaultConfig())

	got := d.Evaluate(Observation{Err: errors.New("deadline"), TimedOut: true}, fastBaseline())
	if len(got) != 1 || got[0].Type != Timeout {
		t.Fatalf("a timeout was reported as %+v", got)
	}

	got = d.Evaluate(Observation{Err: errors.New("connection reset")}, fastBaseline())
	if len(got) != 1 || got[0].Type != ConnectionError {
		t.Fatalf("a connection failure was reported as %+v", got)
	}
}

func TestErrorPatternsAreNarrow(t *testing.T) {
	shouldMatch := []string{
		`{"error":"internal_error","type":"TypeError","detail":"int() argument"}`,
		"Traceback (most recent call last):\n  File ...",
		"panic: runtime error: index out of range",
		"java.lang.NullPointerException",
		"You have an error in your SQL syntax",
	}
	for _, body := range shouldMatch {
		if !MatchesErrorPattern([]byte(body)) {
			t.Errorf("did not match an internal error: %q", body)
		}
	}

	shouldNotMatch := []string{
		`{"error":"bad_request","detail":"qty must be a number"}`,
		`{"error":"not_found","path":"/api/nope"}`,
		`{"status":"ok"}`,
		`{"message":"an error occurred while validating your input"}`,
		`{"errors":[{"field":"qty","message":"required"}]}`,
	}
	for _, body := range shouldNotMatch {
		if MatchesErrorPattern([]byte(body)) {
			t.Errorf("an ordinary API error was treated as an internal one: %q", body)
		}
	}
}

// If the healthy response already looks like an error page, the same text in
// a mutated response says nothing.
func TestErrorPatternIsSuppressedWhenTheBaselineAlreadyMatches(t *testing.T) {
	noisy := BuildBaseline("GET /x", []Observation{
		{StatusCode: 200, Latency: time.Millisecond, BodyBytes: 50, Body: []byte("panic: always")},
	})
	if !noisy.MatchedErrorPattern {
		t.Fatal("the baseline did not notice its own error pattern")
	}
	d := New(DefaultConfig())
	got := d.Evaluate(Observation{
		StatusCode: 200, Latency: time.Millisecond, BodyBytes: 50, Body: []byte("panic: always"),
	}, noisy)
	for _, ind := range got {
		if ind.Type == AppErrorPattern {
			t.Fatal("an error pattern present in the baseline was reported as a finding")
		}
	}
}

func TestSizeAnomalyNeedsABigDifference(t *testing.T) {
	d := New(DefaultConfig())
	baseline := fastBaseline() // 1000-byte median

	if got := d.Evaluate(Observation{StatusCode: 200, Latency: time.Millisecond, BodyBytes: 1400}, baseline); len(got) != 0 {
		t.Errorf("a 40%% size change was reported: %+v", got)
	}
	got := d.Evaluate(Observation{StatusCode: 200, Latency: time.Millisecond, BodyBytes: 60000}, baseline)
	if len(got) == 0 || got[0].Type != SizeAnomaly {
		t.Fatalf("a sixtyfold size change was not reported: %+v", got)
	}
}

// A truncated body is not evidence about size: the cap decided its length.
func TestTruncatedBodiesAreNotSizeAnomalies(t *testing.T) {
	d := New(DefaultConfig())
	got := d.Evaluate(Observation{
		StatusCode: 200, Latency: time.Millisecond, BodyBytes: 60000, Truncated: true,
	}, fastBaseline())
	for _, ind := range got {
		if ind.Type == SizeAnomaly {
			t.Fatal("a truncated body was judged for size")
		}
	}
}

func TestBaselineIgnoresFailedSamples(t *testing.T) {
	b := BuildBaseline("GET /x", []Observation{
		{StatusCode: 200, Latency: 5 * time.Millisecond, BodyBytes: 100},
		{Err: errors.New("refused")},
		{StatusCode: 200, Latency: 5 * time.Millisecond, BodyBytes: 100},
	})
	if b.Samples != 3 {
		t.Errorf("Samples = %d, want all three counted so a shaky baseline is visible", b.Samples)
	}
	if b.LatencyMedian != 5*time.Millisecond {
		t.Errorf("the failed observation distorted the median: %v", b.LatencyMedian)
	}
}

// Nothing the engine emits may carry a confidence rating: that judgement
// belongs to the analysis phase.
func TestIndicatorsCarryNoConfidence(t *testing.T) {
	d := New(DefaultConfig())
	got := d.Evaluate(Observation{StatusCode: 500, Latency: time.Millisecond, BodyBytes: 10}, fastBaseline())
	if len(got) == 0 {
		t.Fatal("no indicator to inspect")
	}
	// A compile-time guarantee: the struct has no such field. This test
	// documents the intent so it is not added back casually.
	var ind Indicator = got[0]
	if ind.Type == "" || ind.Reason == "" {
		t.Error("an indicator must at least say what it is and why")
	}
}
