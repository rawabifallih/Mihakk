package mutate

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"mihakk/internal/corpus"
)

// ambiguousHeaderCorpusJSON carries the same header under four spellings with
// four different values. HTTP header names are case-insensitive, so these fold
// into one canonical entry; they are distinct JSON keys, so all four survive
// decoding. Merging them by ranging over the map ordered their values by Go's
// randomised map iteration, which made the corpus digest -- and every mutation
// derived from it -- differ between runs of identical input.
const ambiguousHeaderCorpusJSON = `{
  "corpus_version": "1",
  "samples": [
    {
      "id": "ambiguous-headers",
      "method": "GET",
      "url": "http://testbed:8000/api/items?page=1&q=shoes",
      "headers": {
        "X-Tag": ["alpha"],
        "x-tag": ["beta"],
        "X-TAG": ["gamma"],
        "x-TaG": ["delta"],
        "Accept": ["application/json"],
        "accept": ["text/plain"],
        "Content-Type": ["application/json"],
        "content-type": ["text/plain"]
      }
    }
  ]
}`

func parseAmbiguous(t *testing.T) *corpus.Corpus {
	t.Helper()
	c, err := corpus.Parse([]byte(ambiguousHeaderCorpusJSON))
	if err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

// Repeated parses of identical input must agree. Before the fix this produced
// several distinct digests within a single process.
func TestAmbiguousHeaderMergeIsStableInProcess(t *testing.T) {
	first := parseAmbiguous(t)
	wantDigest := first.Digest()
	wantValues := append([]string(nil), first.Samples[0].Headers["X-Tag"]...)

	for i := 0; i < 500; i++ {
		c := parseAmbiguous(t)
		if got := c.Digest(); got != wantDigest {
			t.Fatalf("parse %d produced digest %s, want %s", i, got, wantDigest)
		}
		got := c.Samples[0].Headers["X-Tag"]
		if len(got) != len(wantValues) {
			t.Fatalf("parse %d merged %d values, want %d", i, len(got), len(wantValues))
		}
		for j := range wantValues {
			if got[j] != wantValues[j] {
				t.Fatalf("parse %d: X-Tag[%d] = %q, want %q", i, j, got[j], wantValues[j])
			}
		}
	}

	// Values are concatenated in ascending order of the original spelling.
	want := []string{"gamma", "alpha", "delta", "beta"} // X-TAG, X-Tag, x-TaG, x-tag
	for i, v := range want {
		if wantValues[i] != v {
			t.Fatalf("merged X-Tag = %v, want %v (sorted by original spelling)", wantValues, want)
		}
	}
}

// The whole generated sequence must be stable too, not just the digest.
func TestAmbiguousHeaderSequenceIsStableInProcess(t *testing.T) {
	baseline := generateSequential(t, ambiguousPlan(t))
	for i := 0; i < 50; i++ {
		requireEqualSequences(t, baseline, generateSequential(t, ambiguousPlan(t)), "repeat parse")
	}
}

func ambiguousPlan(t *testing.T) *Plan {
	t.Helper()
	p, err := NewPlan(parseAmbiguous(t), DefaultConfig(), testEngineVersion, []byte("seed-ambiguous"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return p
}

// The cross-process test for the ambiguous-header corpus: two separate OS
// processes must generate the same sequence byte for byte.
func TestAmbiguousHeadersAreIdenticalAcrossProcesses(t *testing.T) {
	parent := generateSequential(t, ambiguousPlan(t))

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), ambiguousDumpEnv+"=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("child process failed: %v\nstderr: %s", err, stderr.String())
	}

	var child [][]byte
	dec := json.NewDecoder(&stdout)
	for {
		var line json.RawMessage
		if err := dec.Decode(&line); err != nil {
			break
		}
		child = append(child, []byte(line))
	}
	if len(child) == 0 {
		t.Fatalf("child produced no cases; stderr: %s", stderr.String())
	}

	requireEqualSequences(t, parent, child, "ambiguous headers across processes")
	t.Logf("compared %d cases across two processes", len(parent))
}

const ambiguousDumpEnv = "MIHAKK_TEST_DUMP_AMBIGUOUS"

// dumpAmbiguousCases is the child-process entry point, wired up in TestMain.
func dumpAmbiguousCases() error {
	c, err := corpus.Parse([]byte(ambiguousHeaderCorpusJSON))
	if err != nil {
		return err
	}
	p, err := NewPlan(c, DefaultConfig(), testEngineVersion, []byte("seed-ambiguous"))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	for i := 0; i < p.Total(); i++ {
		cse, err := p.Case(i)
		if err != nil {
			return err
		}
		if err := enc.Encode(json.RawMessage(cse.Canonical())); err != nil {
			return err
		}
	}
	return nil
}

// A JSON body whose object keys arrive in varied order must also produce a
// stable sequence: the walk sorts keys, but this guards the guarantee.
func TestJSONKeyOrderDoesNotAffectTheSequence(t *testing.T) {
	a := `{"corpus_version":"1","samples":[{"id":"j","method":"POST",
	  "url":"http://testbed:8000/api/orders","headers":{"Content-Type":["application/json"]},
	  "body":"{\"zeta\":1,\"alpha\":2,\"mid\":{\"b\":3,\"a\":4}}"}]}`
	b := `{"corpus_version":"1","samples":[{"id":"j","method":"POST",
	  "url":"http://testbed:8000/api/orders","headers":{"Content-Type":["application/json"]},
	  "body":"{\"alpha\":2,\"mid\":{\"a\":4,\"b\":3},\"zeta\":1}"}]}`

	plan := func(raw string) *Plan {
		c, err := corpus.Parse([]byte(raw))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		p, err := NewPlan(c, DefaultConfig(), testEngineVersion, []byte("seed-jsonkeys"))
		if err != nil {
			t.Fatalf("NewPlan: %v", err)
		}
		return p
	}
	// The digests differ because the raw body text differs, but each input on
	// its own must generate a stable sequence across repeated parses.
	for _, raw := range []string{a, b} {
		baseline := generateSequential(t, plan(raw))
		for i := 0; i < 25; i++ {
			requireEqualSequences(t, baseline, generateSequential(t, plan(raw)), "repeated json parse")
		}
	}
}

// --- Encoding inflation -----------------------------------------------------

// inflationCorpus has field names that need percent-encoding and values with
// 4-byte runes. One 4-byte rune becomes 12 characters once percent-encoded,
// which is the worst-case expansion the size check must survive.
const inflationCorpusJSON = `{
  "corpus_version": "1",
  "samples": [
    {
      "id": "encoded-query",
      "method": "GET",
      "url": "http://testbed:8000/api/items?field%20name=plain&tag%5B0%5D=x&emoji=A",
      "headers": {"Accept": ["application/json"]}
    },
    {
      "id": "encoded-form",
      "method": "POST",
      "url": "http://testbed:8000/api/search",
      "headers": {"Content-Type": ["application/x-www-form-urlencoded"]},
      "body": "field%20name=plain&tag%5B0%5D=x&term=shoes"
    }
  ]
}`

// A 4-byte rune percent-encodes to 12 characters. Confirm the assumption the
// bounds checks rest on.
func TestFourByteRuneExpandsTwelvefold(t *testing.T) {
	const rune4 = "\U0001f600"
	if len(rune4) != 4 {
		t.Fatalf("test rune is %d bytes, want 4", len(rune4))
	}
	encoded := url.QueryEscape(rune4)
	if len(encoded) != 12 {
		t.Fatalf("QueryEscape(%q) = %q (%d bytes), want 12", rune4, encoded, len(encoded))
	}
}

// Whatever the cap, a plan either refuses to build or every case it produces
// fits. A case that exceeds the cap must never be returned.
func TestNoCaseEverExceedsTheCapsUnderEncodingInflation(t *testing.T) {
	corpora := map[string]string{
		"encoded names and runes": inflationCorpusJSON,
		"mixed":                   testCorpusJSON,
	}

	for name, raw := range corpora {
		t.Run(name, func(t *testing.T) {
			c, err := corpus.Parse([]byte(raw))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			// Sweep caps across and well past the interesting boundary.
			for _, urlCap := range []int{40, 60, 80, 100, 120, 160, 200, 400, 2048} {
				for _, bodyCap := range []int{16, 32, 64, 128, 256, 1024, 8192} {
					cfg := DefaultConfig()
					cfg.MaxURLBytes = urlCap
					cfg.MaxBodyBytes = bodyCap
					cfg.MaxValueBytes = 256 // deliberately larger than the caps

					fresh, err := corpus.Parse([]byte(raw))
					if err != nil {
						t.Fatal(err)
					}
					p, err := NewPlan(fresh, cfg, testEngineVersion, []byte("seed-inflation"))
					if err != nil {
						// Refusing up front is a valid outcome; it must say why.
						if !errors.Is(err, ErrSampleExceedsLimits) && !errors.Is(err, ErrPlanEmpty) {
							t.Fatalf("url=%d body=%d: NewPlan = %v, want a size refusal", urlCap, bodyCap, err)
						}
						continue
					}
					for i := 0; i < p.Total(); i++ {
						cse, err := p.Case(i)
						if err != nil {
							if errors.Is(err, ErrCaseExceedsLimits) {
								continue // reported rather than returned oversized
							}
							t.Fatalf("url=%d body=%d case %d: %v", urlCap, bodyCap, i, err)
						}
						if n := len(cse.Request.URL); n > urlCap {
							t.Fatalf("url=%d body=%d: case %d (%s/%s) returned a %d byte url\n %s",
								urlCap, bodyCap, i, cse.TargetKind, cse.Mutator, n, cse.Request.URL)
						}
						if n := len(cse.Request.Body); n > bodyCap {
							t.Fatalf("url=%d body=%d: case %d (%s/%s) returned a %d byte body",
								urlCap, bodyCap, i, cse.TargetKind, cse.Mutator, n)
						}
					}
				}
			}
			_ = c
		})
	}
}

// A sample sitting just under the cap in raw form, but over it once
// re-encoded, is refused at plan time with an explanation.
func TestSampleRefusedWhenReEncodingPushesItOverTheCap(t *testing.T) {
	// The raw URL carries a literal 4-byte rune; url.Values.Encode will turn
	// it into 12 characters.
	raw := `{"corpus_version":"1","samples":[{"id":"inflates","method":"GET",
	  "url":"http://testbed:8000/api/i?e=😀","headers":{"Accept":["application/json"]}}]}`
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rawLen := len(c.Samples[0].URL)

	u, err := c.Samples[0].ParsedURL()
	if err != nil {
		t.Fatal(err)
	}
	encoded := *u
	encoded.RawQuery = u.Query().Encode()
	encodedLen := len(encoded.String())

	if encodedLen <= rawLen {
		t.Fatalf("re-encoding did not expand the url: raw=%d encoded=%d", rawLen, encodedLen)
	}
	t.Logf("raw url %d bytes, re-encoded %d bytes", rawLen, encodedLen)

	// A cap between the two must be refused, naming the expansion.
	cfg := DefaultConfig()
	cfg.MaxURLBytes = rawLen
	_, err = NewPlan(c, cfg, testEngineVersion, []byte("seed-reencode"))
	if !errors.Is(err, ErrSampleExceedsLimits) {
		t.Fatalf("NewPlan with cap %d = %v, want ErrSampleExceedsLimits", rawLen, err)
	}
	if !strings.Contains(err.Error(), "re-encoded") {
		t.Fatalf("error %q does not explain the re-encoding expansion", err)
	}

	// A cap above the encoded length is accepted, and every case fits.
	cfg.MaxURLBytes = encodedLen + 64
	fresh, _ := corpus.Parse([]byte(raw))
	p, err := NewPlan(fresh, cfg, testEngineVersion, []byte("seed-reencode"))
	if err != nil {
		t.Fatalf("NewPlan with a sufficient cap = %v", err)
	}
	for i := 0; i < p.Total(); i++ {
		cse, err := p.Case(i)
		if err != nil {
			if errors.Is(err, ErrCaseExceedsLimits) {
				continue
			}
			t.Fatalf("case %d: %v", i, err)
		}
		if n := len(cse.Request.URL); n > cfg.MaxURLBytes {
			t.Fatalf("case %d returned a %d byte url, cap %d", i, n, cfg.MaxURLBytes)
		}
	}
}

// A form body that grows when re-encoded is refused on the same terms.
func TestFormBodyRefusedWhenReEncodingPushesItOverTheCap(t *testing.T) {
	raw := `{"corpus_version":"1","samples":[{"id":"form","method":"POST",
	  "url":"http://testbed:8000/api/search","headers":{"Content-Type":["application/x-www-form-urlencoded"]},
	  "body":"term=😀&sort=price"}]}`
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	body, err := c.Samples[0].DecodedBody()
	if err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	rawLen, encodedLen := len(body), len(values.Encode())
	if encodedLen <= rawLen {
		t.Fatalf("re-encoding did not expand the form body: raw=%d encoded=%d", rawLen, encodedLen)
	}
	t.Logf("raw form body %d bytes, re-encoded %d bytes", rawLen, encodedLen)

	cfg := DefaultConfig()
	cfg.MaxBodyBytes = rawLen
	if _, err := NewPlan(c, cfg, testEngineVersion, []byte("seed-form")); !errors.Is(err, ErrSampleExceedsLimits) {
		t.Fatalf("NewPlan with cap %d = %v, want ErrSampleExceedsLimits", rawLen, err)
	}
}

// A JSON body containing characters that encoding/json escapes also grows on
// re-encode, and is checked on the same terms.
func TestJSONBodyReEncodingExpansionIsChecked(t *testing.T) {
	// "<" becomes <: one byte turns into six.
	raw := `{"corpus_version":"1","samples":[{"id":"json","method":"POST",
	  "url":"http://testbed:8000/api/orders","headers":{"Content-Type":["application/json"]},
	  "body":"{\"note\":\"<a>&<b>\"}"}]}`
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	body, _ := c.Samples[0].DecodedBody()
	doc, err := decodeJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= len(body) {
		t.Skipf("this Go version does not expand the body on re-encode (raw=%d encoded=%d)", len(body), len(encoded))
	}
	t.Logf("raw json body %d bytes, re-encoded %d bytes", len(body), len(encoded))

	cfg := DefaultConfig()
	cfg.MaxBodyBytes = len(body)
	if _, err := NewPlan(c, cfg, testEngineVersion, []byte("seed-jsonescape")); !errors.Is(err, ErrSampleExceedsLimits) {
		t.Fatalf("NewPlan with cap %d = %v, want ErrSampleExceedsLimits", len(body), err)
	}
}

// A generated JSON body must stay parseable when it came from field-level
// mutation: the size fallback must not truncate it into invalid JSON.
func TestJSONSizeFallbackKeepsTheBodyValid(t *testing.T) {
	raw := `{"corpus_version":"1","samples":[{"id":"j","method":"POST",
	  "url":"http://testbed:8000/api/orders","headers":{"Content-Type":["application/json"]},
	  "body":"{\"a\":\"xxxxxxxxxx\",\"b\":\"yyyyyyyyyy\"}"}]}`
	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	body, _ := c.Samples[0].DecodedBody()

	cfg := DefaultConfig()
	cfg.MaxBodyBytes = len(body) + 2 // barely any slack
	cfg.MaxValueBytes = 4096         // mutators will want far more than fits

	p, err := NewPlan(c, cfg, testEngineVersion, []byte("seed-fallback"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}

	var fallbacks int
	for i := 0; i < p.Total(); i++ {
		cse, err := p.Case(i)
		if err != nil {
			if errors.Is(err, ErrCaseExceedsLimits) {
				continue
			}
			t.Fatalf("case %d: %v", i, err)
		}
		if len(cse.Request.Body) > cfg.MaxBodyBytes {
			t.Fatalf("case %d body is %d bytes, cap %d", i, len(cse.Request.Body), cfg.MaxBodyBytes)
		}
		// Raw-body mutation is allowed to produce malformed JSON on purpose;
		// field-level mutation must not.
		if cse.TargetKind == TargetJSON && len(cse.Request.Body) > 0 {
			if !json.Valid(cse.Request.Body) {
				t.Fatalf("case %d (%s) produced invalid JSON after the size fallback: %s",
					i, cse.Mutator, cse.Request.Body)
			}
			fallbacks++
		}
	}
	if fallbacks == 0 {
		t.Fatal("no field-level JSON cases were generated; the test is not exercising the fallback")
	}
	t.Logf("%d field-level JSON cases stayed valid under a tight cap", fallbacks)
}

// The fallback to an empty value is not always enough: if the *parameter name*
// is what inflates on re-encode, an empty value cannot bring the URL under the
// cap. This is the case that previously returned an over-limit request,
// because the fallback result was never re-checked.
func TestEmptyValueFallbackIsNotAssumedSufficient(t *testing.T) {
	// A query parameter whose name is two 4-byte runes: 8 raw bytes become 24
	// characters once percent-encoded.
	raw := `{"corpus_version":"1","samples":[{"id":"wide-name","method":"GET",
	  "url":"http://testbed:8000/api/i?😀😀=x","headers":{"Accept":["application/json"]}}]}`

	c, err := corpus.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rawLen := len(c.Samples[0].URL)

	u, err := c.Samples[0].ParsedURL()
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for name := range q {
		q[name] = []string{""} // the best the fallback can do
	}
	floor := *u
	floor.RawQuery = q.Encode()
	floorLen := len(floor.String())

	if floorLen <= rawLen {
		t.Fatalf("the parameter name does not inflate: raw=%d floor=%d", rawLen, floorLen)
	}
	t.Logf("raw url %d bytes; encoded with an empty value %d bytes", rawLen, floorLen)

	// Any cap in this window is satisfiable by the raw text but not by the
	// encoded form, even with an empty value.
	for cap := rawLen; cap < floorLen; cap++ {
		fresh, err := corpus.Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		cfg := DefaultConfig()
		cfg.MaxURLBytes = cap

		p, err := NewPlan(fresh, cfg, testEngineVersion, []byte("seed-floor"))
		if err != nil {
			if errors.Is(err, ErrSampleExceedsLimits) || errors.Is(err, ErrPlanEmpty) {
				continue // refused up front, which is correct
			}
			t.Fatalf("cap=%d: NewPlan = %v", cap, err)
		}
		for i := 0; i < p.Total(); i++ {
			cse, err := p.Case(i)
			if err != nil {
				if errors.Is(err, ErrCaseExceedsLimits) {
					continue // reported rather than returned oversized
				}
				t.Fatalf("cap=%d case %d: %v", cap, i, err)
			}
			if n := len(cse.Request.URL); n > cap {
				t.Fatalf("cap=%d: case %d (%s/%s) returned a %d byte url\n %s",
					cap, i, cse.TargetKind, cse.Mutator, n, cse.Request.URL)
			}
		}
	}
}
