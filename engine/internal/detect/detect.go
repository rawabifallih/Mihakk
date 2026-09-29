// Package detect turns one observed response into zero or more indicators.
//
// An indicator is something worth a human's attention, not a finding. The
// engine records what it saw and why it stood out; deciding how much to trust
// it, grouping it with its duplicates and ranking it belong to the analysis
// phase. Nothing here claims a vulnerability, and nothing here assigns a
// confidence level.
//
// Every judgement is made against a baseline gathered from the unmutated
// samples. Without one, "slow" and "big" have no meaning, and a detector with
// no sense of normal reports mostly noise.
package detect

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"time"
)

// IndicatorType names what was observed. These match the enum in
// schemas/case.schema.json.
type IndicatorType string

const (
	HTTP5xx         IndicatorType = "http_5xx"
	Timeout         IndicatorType = "timeout"
	ConnectionError IndicatorType = "connection_error"
	AppErrorPattern IndicatorType = "app_error_pattern"
	LatencyAnomaly  IndicatorType = "latency_anomaly"
	SizeAnomaly     IndicatorType = "size_anomaly"
)

// Indicator is one observation worth reporting.
//
// There is deliberately no Confidence field. The engine's job is to record
// the observation and the comparison that produced it; rating it is the
// analysis phase's job, and a number invented here would only be guessed at.
type Indicator struct {
	Type IndicatorType `json:"type"`

	// Reason explains, in plain language, what was seen and what it was
	// compared against, so a reader can judge it without rerunning anything.
	Reason string `json:"reason"`

	// Baseline is the comparison the reason refers to, when there was one.
	Baseline *BaselineSummary `json:"baseline,omitempty"`
}

// BaselineSummary is the normal behaviour an indicator departed from.
type BaselineSummary struct {
	Samples       int     `json:"samples"`
	LatencyMedMS  float64 `json:"latency_median_ms"`
	LatencyMADMS  float64 `json:"latency_mad_ms"`
	BodyMedBytes  int     `json:"body_median_bytes"`
	StatusesSeen  []int   `json:"statuses_seen"`
	MatchedErrors bool    `json:"baseline_matched_error_pattern"`
}

// Observation is what came back from one request.
type Observation struct {
	StatusCode int
	Latency    time.Duration
	Body       []byte
	BodyBytes  int
	Truncated  bool

	// Err is set when the request never produced a response.
	Err error
	// TimedOut distinguishes a deadline from other transport failures.
	TimedOut bool
}

// Baseline is the normal behaviour of one endpoint, measured from unmutated
// samples before any fuzzing starts.
type Baseline struct {
	Key     string `json:"key"`
	Samples int    `json:"samples"`

	LatencyMedian time.Duration `json:"-"`
	LatencyMAD    time.Duration `json:"-"`
	BodyMedian    int           `json:"body_median_bytes"`
	Statuses      []int         `json:"statuses"`

	// MatchedErrorPattern records whether the healthy response already looks
	// like an error page. If it does, the same text in a mutated response
	// says nothing, so the detector stays quiet rather than flagging every
	// single request.
	MatchedErrorPattern bool `json:"baseline_matched_error_pattern"`

	LatencyMedianMS float64 `json:"latency_median_ms"`
	LatencyMADMS    float64 `json:"latency_mad_ms"`
}

// UnmarshalJSON restores the duration fields from their millisecond form.
//
// LatencyMedian and LatencyMAD are not serialised directly -- a raw
// time.Duration on disk is an unreadable integer of nanoseconds -- so they are
// written as milliseconds and rebuilt here. Without this, a baseline loaded
// from a stored session came back with a zero median, and the latency
// detector, which skips a baseline it cannot measure, went quiet during
// reproduce for no visible reason.
func (b *Baseline) UnmarshalJSON(raw []byte) error {
	type alias Baseline // avoid recursing into this method
	var decoded alias
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*b = Baseline(decoded)
	b.LatencyMedian = time.Duration(b.LatencyMedianMS * float64(time.Millisecond))
	b.LatencyMAD = time.Duration(b.LatencyMADMS * float64(time.Millisecond))
	return nil
}

func (b *Baseline) summary() *BaselineSummary {
	if b == nil {
		return nil
	}
	return &BaselineSummary{
		Samples:       b.Samples,
		LatencyMedMS:  msOf(b.LatencyMedian),
		LatencyMADMS:  msOf(b.LatencyMAD),
		BodyMedBytes:  b.BodyMedian,
		StatusesSeen:  b.Statuses,
		MatchedErrors: b.MatchedErrorPattern,
	}
}

// BuildBaseline summarises repeated observations of one unmutated sample.
func BuildBaseline(key string, observations []Observation) *Baseline {
	b := &Baseline{Key: key, Samples: len(observations)}
	if len(observations) == 0 {
		return b
	}

	latencies := make([]float64, 0, len(observations))
	sizes := make([]int, 0, len(observations))
	statusSet := map[int]bool{}

	for _, o := range observations {
		if o.Err != nil {
			// A sample that already fails is not usable as "normal"; it is
			// still counted so the caller can see the baseline is shaky.
			continue
		}
		latencies = append(latencies, float64(o.Latency))
		sizes = append(sizes, o.BodyBytes)
		statusSet[o.StatusCode] = true
		if MatchesErrorPattern(o.Body) {
			b.MatchedErrorPattern = true
		}
	}

	for s := range statusSet {
		b.Statuses = append(b.Statuses, s)
	}
	sort.Ints(b.Statuses)

	if len(latencies) > 0 {
		median := medianFloat(latencies)
		b.LatencyMedian = time.Duration(median)
		deviations := make([]float64, len(latencies))
		for i, v := range latencies {
			deviations[i] = math.Abs(v - median)
		}
		b.LatencyMAD = time.Duration(medianFloat(deviations))
	}
	if len(sizes) > 0 {
		asFloat := make([]float64, len(sizes))
		for i, v := range sizes {
			asFloat[i] = float64(v)
		}
		b.BodyMedian = int(medianFloat(asFloat))
	}

	b.LatencyMedianMS = msOf(b.LatencyMedian)
	b.LatencyMADMS = msOf(b.LatencyMAD)
	return b
}

// Config sets how far from normal is far enough to report.
type Config struct {
	// LatencyFloor is an absolute minimum before any latency is reported. On
	// an endpoint answering in two milliseconds, a multiple of the median is
	// a handful of milliseconds, which ordinary scheduling noise clears
	// constantly. The floor is what stops that becoming a flood.
	LatencyFloor time.Duration `json:"latency_floor"`
	// LatencyFactor: report above median * factor.
	LatencyFactor float64 `json:"latency_factor"`
	// LatencyMADs: report above median + MADs * MAD.
	LatencyMADs float64 `json:"latency_mads"`

	// SizeFactor and SizeFloorBytes work the same way for response size.
	SizeFactor     float64 `json:"size_factor"`
	SizeFloorBytes int     `json:"size_floor_bytes"`
}

// DefaultConfig is deliberately conservative: it would rather miss a marginal
// anomaly than bury a real one under noise.
func DefaultConfig() Config {
	return Config{
		LatencyFloor:   250 * time.Millisecond,
		LatencyFactor:  5,
		LatencyMADs:    8,
		SizeFactor:     10,
		SizeFloorBytes: 4096,
	}
}

// errorPatterns are shapes that specifically suggest an unhandled internal
// error. They are deliberately narrow: a body containing the word "error" is
// an ordinary API response, and matching it would flag every validation
// failure in the application.
var errorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)traceback \(most recent call last\)`),
	regexp.MustCompile(`(?i)\bpanic:\s`),
	regexp.MustCompile(`(?i)\bexception in thread\b`),
	regexp.MustCompile(`(?i)\bstack ?trace\b`),
	regexp.MustCompile(`\bat [\w.$]+\([\w]+\.(java|kt|scala):\d+\)`),
	regexp.MustCompile(`(?i)\b(sql syntax|sqlstate|ora-\d{5}|psql:|mysql_fetch)\b`),
	regexp.MustCompile(`(?i)\bsegmentation fault\b`),
	regexp.MustCompile(`(?i)\bfatal error\b`),
	regexp.MustCompile(`(?i)<b>(warning|fatal error|notice)</b>:.*on line`),
	// Runtime exception type names surfacing in a response body.
	regexp.MustCompile(`\b(TypeError|ValueError|KeyError|IndexError|AttributeError|` +
		`RuntimeError|ZeroDivisionError|NullPointerException|ClassCastException|` +
		`IllegalStateException|IndexOutOfBoundsException)\b`),
}

// MatchesErrorPattern reports whether a body looks like an unhandled error.
func MatchesErrorPattern(body []byte) bool {
	return errorPatternName(body) != ""
}

func errorPatternName(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	for _, p := range errorPatterns {
		if m := p.Find(body); m != nil {
			return string(m)
		}
	}
	return ""
}

// Detector evaluates observations against baselines.
type Detector struct {
	cfg Config
}

func New(cfg Config) *Detector { return &Detector{cfg: cfg} }

// Evaluate returns every indicator raised by one observation.
//
// baseline may be nil, in which case only the judgements that need no
// comparison are made: a transport failure and a 5xx mean the same thing with
// or without a sense of normal, while "slow" and "large" do not.
func (d *Detector) Evaluate(o Observation, baseline *Baseline) []Indicator {
	var out []Indicator

	if o.Err != nil {
		if o.TimedOut {
			return append(out, Indicator{
				Type: Timeout,
				Reason: fmt.Sprintf("the request did not complete within the per-request timeout (%s elapsed)",
					o.Latency.Round(time.Millisecond)),
				Baseline: baseline.summary(),
			})
		}
		return append(out, Indicator{
			Type:     ConnectionError,
			Reason:   fmt.Sprintf("the request failed before a response was received: %v", o.Err),
			Baseline: baseline.summary(),
		})
	}

	if o.StatusCode >= 500 {
		reason := fmt.Sprintf("the server answered %d", o.StatusCode)
		if baseline != nil && len(baseline.Statuses) > 0 {
			reason += fmt.Sprintf("; the unmutated sample answered %v", baseline.Statuses)
		}
		out = append(out, Indicator{Type: HTTP5xx, Reason: reason, Baseline: baseline.summary()})
	}

	// An error signature only means something if the healthy response did not
	// already carry one.
	if match := errorPatternName(o.Body); match != "" {
		if baseline == nil || !baseline.MatchedErrorPattern {
			out = append(out, Indicator{
				Type: AppErrorPattern,
				Reason: fmt.Sprintf("the response body contains %q, which the unmutated sample's response did not",
					truncate(match, 80)),
				Baseline: baseline.summary(),
			})
		}
	}

	if baseline != nil && baseline.Samples > 0 && baseline.LatencyMedian > 0 {
		if threshold := d.latencyThreshold(baseline); o.Latency > threshold {
			out = append(out, Indicator{
				Type: LatencyAnomaly,
				Reason: fmt.Sprintf("the response took %s; the unmutated sample's median was %s (threshold %s)",
					o.Latency.Round(time.Millisecond),
					baseline.LatencyMedian.Round(time.Millisecond),
					threshold.Round(time.Millisecond)),
				Baseline: baseline.summary(),
			})
		}
	}

	if baseline != nil && baseline.Samples > 0 && baseline.BodyMedian > 0 && !o.Truncated {
		delta := abs(o.BodyBytes - baseline.BodyMedian)
		threshold := d.sizeThreshold(baseline)
		if delta > threshold {
			out = append(out, Indicator{
				Type: SizeAnomaly,
				Reason: fmt.Sprintf("the response body was %d bytes; the unmutated sample's median was %d (threshold %d bytes of difference)",
					o.BodyBytes, baseline.BodyMedian, threshold),
				Baseline: baseline.summary(),
			})
		}
	}

	return out
}

// latencyThreshold takes the largest of the three bounds, so a fast endpoint
// is governed by the absolute floor and a slow one by its own spread.
func (d *Detector) latencyThreshold(b *Baseline) time.Duration {
	byFactor := time.Duration(float64(b.LatencyMedian) * d.cfg.LatencyFactor)
	bySpread := b.LatencyMedian + time.Duration(float64(b.LatencyMAD)*d.cfg.LatencyMADs)
	threshold := d.cfg.LatencyFloor
	if byFactor > threshold {
		threshold = byFactor
	}
	if bySpread > threshold {
		threshold = bySpread
	}
	return threshold
}

func (d *Detector) sizeThreshold(b *Baseline) int {
	byFactor := int(float64(b.BodyMedian) * d.cfg.SizeFactor)
	if byFactor > d.cfg.SizeFloorBytes {
		return byFactor
	}
	return d.cfg.SizeFloorBytes
}

func medianFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func msOf(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
