package mutate

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"mihakk/internal/corpus"
	"mihakk/internal/safety"
)

// Acceptance criterion 4, part 1: every generated input respects the
// configured size caps.
func TestEveryCaseRespectsSizeLimits(t *testing.T) {
	configs := []struct {
		name string
		cfg  Config
	}{
		{"defaults", DefaultConfig()},
		{"tight but feasible", func() Config {
			c := DefaultConfig()
			c.MaxValueBytes = 16
			c.MaxBodyBytes = 128
			c.MaxURLBytes = 128
			return c
		}()},
		{"generous", func() Config {
			c := DefaultConfig()
			c.MaxValueBytes = 4096
			c.MaxBodyBytes = 16384
			c.MaxURLBytes = 8192
			return c
		}()},
	}

	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPlan(testCorpus(t), tc.cfg, testEngineVersion, []byte("seed-bounds"))
			if err != nil {
				t.Fatalf("NewPlan: %v", err)
			}
			for i := 0; i < p.Total(); i++ {
				c, err := p.Case(i)
				if err != nil {
					t.Fatalf("Case(%d): %v", i, err)
				}
				if got := len(c.Request.Body); got > tc.cfg.MaxBodyBytes {
					t.Fatalf("case %d (%s/%s): body is %d bytes, cap is %d",
						i, c.TargetKind, c.Mutator, got, tc.cfg.MaxBodyBytes)
				}
				if got := len(c.Request.URL); got > tc.cfg.MaxURLBytes {
					t.Fatalf("case %d (%s/%s): url is %d bytes, cap is %d",
						i, c.TargetKind, c.Mutator, got, tc.cfg.MaxURLBytes)
				}
				// MaxValueBytes governs the value a mutation produced. Other
				// headers must come through byte-identical to the sample.
				sample, err := testCorpus(t).Find(c.SampleID)
				if err != nil {
					t.Fatalf("case %d: %v", i, err)
				}
				for name, values := range c.Request.Headers {
					mutated := c.TargetKind == TargetHeader && name == c.TargetName
					for vi, v := range values {
						if mutated && vi == 0 {
							if len(v) > tc.cfg.MaxValueBytes {
								t.Fatalf("case %d: mutated header %s is %d bytes, cap is %d",
									i, name, len(v), tc.cfg.MaxValueBytes)
							}
							continue
						}
						if want := sample.Headers[name]; vi < len(want) && v != want[vi] {
							t.Fatalf("case %d: untouched header %s changed: %q -> %q",
								i, name, want[vi], v)
						}
					}
				}
			}
		})
	}
}

// A body or URL cap the corpus cannot satisfy is reported at plan time,
// rather than being silently violated by passing an oversized sample body
// through untouched.
func TestPlanRefusesSamplesLargerThanTheCaps(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"body", func(c *Config) { c.MaxBodyBytes = 8 }},
		{"url", func(c *Config) { c.MaxURLBytes = 8 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.mutate(&cfg)
			_, err := NewPlan(testCorpus(t), cfg, testEngineVersion, []byte("seed-toosmall"))
			if !errors.Is(err, ErrSampleExceedsLimits) {
				t.Fatalf("NewPlan = %v, want ErrSampleExceedsLimits", err)
			}
			if !strings.Contains(err.Error(), "sample") {
				t.Fatalf("error %q does not name the offending sample", err)
			}
		})
	}
}

// Acceptance criterion 4, part 2: no mutation may change where the request goes.
func TestNoCaseChangesTheDestination(t *testing.T) {
	c := testCorpus(t)
	cfg := DefaultConfig()
	cfg.MaxValueBytes = 2048
	p, err := NewPlan(c, cfg, testEngineVersion, []byte("seed-destination"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}

	for i := 0; i < p.Total(); i++ {
		got, err := p.Case(i)
		if err != nil {
			t.Fatalf("Case(%d): %v", i, err)
		}
		sample, err := c.Find(got.SampleID)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		original, err := sample.ParsedURL()
		if err != nil {
			t.Fatal(err)
		}
		mutated, err := url.Parse(got.Request.URL)
		if err != nil {
			t.Fatalf("case %d produced an unparsable url %q: %v", i, got.Request.URL, err)
		}
		if got.Request.Method != sample.Method {
			t.Fatalf("case %d changed the method: %q -> %q", i, sample.Method, got.Request.Method)
		}
		if mutated.Scheme != original.Scheme {
			t.Fatalf("case %d changed the scheme: %q -> %q", i, original.Scheme, mutated.Scheme)
		}
		if mutated.Host != original.Host {
			t.Fatalf("case %d changed the host: %q -> %q", i, original.Host, mutated.Host)
		}
		if mutated.Path != original.Path {
			t.Fatalf("case %d changed the path: %q -> %q", i, original.Path, mutated.Path)
		}
		if mutated.User != nil {
			t.Fatalf("case %d introduced credentials into the url", i)
		}
	}
}

// Acceptance criterion 4, part 3: every generated request still passes the
// safety layer's scope check. Scope validation stays mandatory before any
// request is sent; this asserts the generator does not manufacture work that
// the guard would only have to throw away.
func TestEveryCasePassesTheSafetyScopeCheck(t *testing.T) {
	scope := &safety.Scope{
		Targets: []safety.Target{{
			Scheme: "http", Host: "testbed", Port: 8000,
			PathPrefixes:     []string{"/api"},
			Methods:          []string{"GET", "POST"},
			AllowedAddresses: []string{"127.0.0.1/32"},
		}},
		MaxRedirects: 2,
	}
	scope.Normalize()
	if err := scope.Validate(); err != nil {
		t.Fatalf("scope invalid: %v", err)
	}

	cfg := DefaultConfig()
	cfg.MaxValueBytes = 1024
	p, err := NewPlan(testCorpus(t), cfg, testEngineVersion, []byte("seed-scope"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}

	for i := 0; i < p.Total(); i++ {
		c, err := p.Case(i)
		if err != nil {
			t.Fatalf("Case(%d): %v", i, err)
		}
		u, err := url.Parse(c.Request.URL)
		if err != nil {
			t.Fatalf("case %d: unparsable url: %v", i, err)
		}
		if _, err := scope.Check(c.Request.Method, u); err != nil {
			t.Fatalf("case %d (%s/%s) would be refused by the scope guard: %v\n url: %s",
				i, c.TargetKind, c.Mutator, err, c.Request.URL)
		}
	}
}

// Generated requests must be acceptable to net/http: a header value carrying
// CR or LF would let a mutation forge extra headers, which is smuggling
// rather than input fuzzing.
func TestGeneratedHeadersAreWellFormed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxValueBytes = 512
	p, err := NewPlan(testCorpus(t), cfg, testEngineVersion, []byte("seed-headers"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}

	for i := 0; i < p.Total(); i++ {
		c, err := p.Case(i)
		if err != nil {
			t.Fatalf("Case(%d): %v", i, err)
		}
		for name, values := range c.Request.Headers {
			for _, v := range values {
				if strings.ContainsAny(v, "\r\n\x00") {
					t.Fatalf("case %d: header %s carries a CR, LF or NUL: %q", i, name, v)
				}
			}
		}
		req, err := http.NewRequest(c.Request.Method, c.Request.URL, strings.NewReader(string(c.Request.Body)))
		if err != nil {
			t.Fatalf("case %d: net/http rejected the generated request: %v", i, err)
		}
		for name, values := range c.Request.Headers {
			for _, v := range values {
				req.Header.Add(name, v)
			}
		}
	}
}

// Headers that decide the destination, the framing, or carry credentials are
// never mutated, whatever the configuration asks for.
func TestForbiddenHeadersAreNeverMutated(t *testing.T) {
	for _, name := range []string{
		"Host", "host", "Content-Length", "Transfer-Encoding",
		"Authorization", "Cookie", "X-Forwarded-Host", "X-Forwarded-For",
	} {
		if !IsForbiddenHeader(name) {
			t.Errorf("IsForbiddenHeader(%q) = false, want true", name)
		}
		cfg := DefaultConfig()
		cfg.MutableHeaders = []string{name}
		cfg.Normalize()
		if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("config allowing %q to be mutated = %v, want ErrInvalidConfig", name, err)
		}
		if cfg.AllowsHeader(name) {
			t.Errorf("AllowsHeader(%q) = true, want false", name)
		}
	}

	// And a sample carrying them must come out with them untouched.
	raw := `{
  "corpus_version": "1",
  "samples": [{
    "id": "with-credentials",
    "method": "GET",
    "url": "http://testbed:8000/api/items?page=1",
    "headers": {
      "Host": ["testbed:8000"],
      "Authorization": ["Bearer secret-token-value"],
      "Cookie": ["session=abc123"],
      "Accept": ["application/json"]
    }
  }]
}`
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	p, err := NewPlan(c, DefaultConfig(), testEngineVersion, []byte("seed-forbidden"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}

	for i := 0; i < p.Total(); i++ {
		got, err := p.Case(i)
		if err != nil {
			t.Fatalf("Case(%d): %v", i, err)
		}
		if got.TargetKind == TargetHeader && IsForbiddenHeader(got.TargetName) {
			t.Fatalf("case %d targeted forbidden header %q", i, got.TargetName)
		}
		for _, name := range []string{"Host", "Authorization", "Cookie"} {
			want := c.Samples[0].Headers[name]
			if len(got.Request.Headers[name]) != len(want) || got.Request.Headers[name][0] != want[0] {
				t.Fatalf("case %d altered %s: %q -> %q", i, name, want, got.Request.Headers[name])
			}
		}
	}
}

// A JSON sample is fuzzed both as fields and as opaque bytes, so both valid
// and malformed JSON bodies are generated.
func TestJSONSampleProducesValidAndMalformedBodies(t *testing.T) {
	raw := `{
  "corpus_version": "1",
  "samples": [{
    "id": "json-only",
    "method": "POST",
    "url": "http://testbed:8000/api/orders",
    "headers": {"Content-Type": ["application/json"]},
    "body": "{\"qty\":2,\"sku\":\"A-1\"}"
  }]
}`
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	p, err := NewPlan(c, DefaultConfig(), testEngineVersion, []byte("seed-json"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}

	var validJSON, malformedJSON int
	for i := 0; i < p.Total(); i++ {
		got, err := p.Case(i)
		if err != nil {
			t.Fatalf("Case(%d): %v", i, err)
		}
		if len(got.Request.Body) == 0 {
			continue
		}
		if json.Valid(got.Request.Body) {
			validJSON++
		} else {
			malformedJSON++
		}
	}
	if validJSON == 0 {
		t.Error("no structurally valid JSON bodies were generated")
	}
	if malformedJSON == 0 {
		t.Error("no malformed JSON bodies were generated; raw-body mutation is not reaching JSON samples")
	}
	t.Logf("json bodies: %d valid, %d malformed", validJSON, malformedJSON)
}

// The mutator set must actually vary its output, otherwise the determinism
// tests would pass trivially on a constant sequence.
func TestPlanProducesVariedMutations(t *testing.T) {
	p := testPlan(t)

	mutators := map[string]int{}
	kinds := map[TargetKind]int{}
	bodies := map[string]bool{}
	for i := 0; i < p.Total(); i++ {
		c, err := p.Case(i)
		if err != nil {
			t.Fatalf("Case(%d): %v", i, err)
		}
		mutators[c.Mutator]++
		kinds[c.TargetKind]++
		bodies[string(c.Canonical())] = true
	}

	if len(mutators) < 8 {
		t.Errorf("only %d distinct mutators were exercised: %v", len(mutators), mutators)
	}
	for _, want := range []TargetKind{TargetQuery, TargetHeader, TargetJSON, TargetForm, TargetRawBody} {
		if kinds[want] == 0 {
			t.Errorf("target kind %q was never exercised", want)
		}
	}
	if unique, total := len(bodies), p.Total(); unique < total*3/4 {
		t.Errorf("only %d of %d cases are distinct; mutations are too repetitive", unique, total)
	}
	t.Logf("%d distinct mutators across %d target kinds, %d/%d distinct cases",
		len(mutators), len(kinds), len(bodies), p.Total())
}

func TestCaseIndexOutOfRange(t *testing.T) {
	p := testPlan(t)
	for _, i := range []int{-1, p.Total(), p.Total() + 1000} {
		if _, err := p.Case(i); !errors.Is(err, ErrCaseOutOfRange) {
			t.Errorf("Case(%d) = %v, want ErrCaseOutOfRange", i, err)
		}
	}
}

func TestPlanRefusesUnusableInputs(t *testing.T) {
	good := testCorpus(t)

	if _, err := NewPlan(good, DefaultConfig(), "", []byte("s")); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewPlan without an engine version = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewPlan(good, DefaultConfig(), testEngineVersion, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewPlan without a seed = %v, want ErrInvalidConfig", err)
	}

	// A corpus whose only sample has nothing mutable yields an empty plan.
	raw := `{"corpus_version":"1","samples":[{"id":"bare","method":"GET","url":"http://testbed:8000/api/ping"}]}`
	bare, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	cfg := DefaultConfig()
	cfg.MutableHeaders = nil
	if _, err := NewPlan(bare, cfg, testEngineVersion, []byte("s")); !errors.Is(err, ErrPlanEmpty) {
		t.Errorf("NewPlan on a corpus with no mutable targets = %v, want ErrPlanEmpty", err)
	}
}

func TestMaxTargetsPerSampleBoundsThePlan(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxTargetsPerSample = 2
	cfg.MutationsPerTarget = 3

	p, err := NewPlan(testCorpus(t), cfg, testEngineVersion, []byte("seed-bound"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	// 4 samples, at most 2 targets each, 3 mutations per target.
	if max := 4 * 2 * 3; p.Total() > max {
		t.Fatalf("plan has %d cases, want at most %d", p.Total(), max)
	}
}
