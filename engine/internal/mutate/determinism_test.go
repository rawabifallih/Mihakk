package mutate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"sort"
	"sync"
	"testing"
	"time"

	"mihakk/internal/corpus"
)

const testEngineVersion = "0.2.0-test"

// testCorpusJSON is shared by this process and the child process spawned
// by the cross-process determinism test, so both demonstrably start from
// byte-identical inputs.
const testCorpusJSON = `{
  "corpus_version": "1",
  "samples": [
    {
      "id": "list-items",
      "method": "GET",
      "url": "http://testbed:8000/api/items?page=1&limit=20&q=shoes",
      "headers": {"Accept": ["application/json"], "User-Agent": ["mihakk/0.1"]}
    },
    {
      "id": "create-order",
      "method": "POST",
      "url": "http://testbed:8000/api/orders",
      "headers": {"Content-Type": ["application/json"], "Accept": ["application/json"]},
      "body": "{\"customer\":{\"id\":42,\"name\":\"Rawabi\"},\"items\":[{\"sku\":\"A-1\",\"qty\":2}],\"express\":true,\"note\":null}"
    },
    {
      "id": "login-form",
      "method": "POST",
      "url": "http://testbed:8000/api/session",
      "headers": {"Content-Type": ["application/x-www-form-urlencoded"]},
      "body": "username=rawabi&remember=1"
    },
    {
      "id": "upload-blob",
      "method": "POST",
      "url": "http://testbed:8000/api/blob",
      "headers": {"Content-Type": ["application/octet-stream"]},
      "body": "cmF3LWJpbmFyeS1wYXlsb2Fk",
      "body_encoding": "base64"
    }
  ]
}`

// testCorpus exercises every target kind: query parameters, a JSON body, a
// form body, a raw body and mutable headers.
func testCorpus(t *testing.T) *corpus.Corpus {
	t.Helper()
	c, err := corpus.Parse([]byte(testCorpusJSON))
	if err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

func testPlan(t *testing.T) *Plan {
	t.Helper()
	p, err := NewPlan(testCorpus(t), DefaultConfig(), testEngineVersion, []byte("seed-alpha"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return p
}

// generateSequential produces every case in index order.
func generateSequential(t *testing.T, p *Plan) [][]byte {
	t.Helper()
	out := make([][]byte, p.Total())
	for i := 0; i < p.Total(); i++ {
		c, err := p.Case(i)
		if err != nil {
			t.Fatalf("Case(%d): %v", i, err)
		}
		out[i] = c.Canonical()
	}
	return out
}

// generateConcurrent produces every case using n workers that pull indices
// from a shared queue and finish in a deliberately jumbled order.
func generateConcurrent(t *testing.T, p *Plan, workers int) [][]byte {
	t.Helper()
	out := make([][]byte, p.Total())
	indices := make(chan int)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			// Each worker jitters independently, so completion order varies
			// between runs. If generation depended on ordering at all, this is
			// what would expose it.
			jitter := rand.New(rand.NewSource(int64(worker) * 7919))
			for i := range indices {
				if jitter.Intn(4) == 0 {
					time.Sleep(time.Duration(jitter.Intn(200)) * time.Microsecond)
				}
				c, err := p.Case(i)
				if err != nil {
					t.Errorf("Case(%d): %v", i, err)
					return
				}
				out[i] = c.Canonical()
			}
		}(w)
	}
	for i := 0; i < p.Total(); i++ {
		indices <- i
	}
	close(indices)
	wg.Wait()
	return out
}

func requireEqualSequences(t *testing.T, want, got [][]byte, label string) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s: got %d cases, want %d", label, len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(want[i], got[i]) {
			t.Fatalf("%s: case %d differs\n want: %s\n  got: %s", label, i, want[i], got[i])
		}
	}
}

// Acceptance criterion 1: one worker and sixteen workers produce the same
// inputs when ordered by case index, whatever order the workers finish in.
func TestSameInputsAtAnyConcurrency(t *testing.T) {
	p := testPlan(t)
	if p.Total() < 100 {
		t.Fatalf("plan has only %d cases; the test corpus is too small to be meaningful", p.Total())
	}
	t.Logf("plan: %d cases, derivation %s", p.Total(), p.DerivationDigest())

	baseline := generateSequential(t, p)

	for _, workers := range []int{1, 2, 16} {
		got := generateConcurrent(t, p, workers)
		requireEqualSequences(t, baseline, got, fmt.Sprintf("%d workers", workers))
	}

	// Repeat the 16-worker run: a different interleaving must still match.
	for run := 0; run < 3; run++ {
		got := generateConcurrent(t, p, 16)
		requireEqualSequences(t, baseline, got, fmt.Sprintf("16 workers, repeat %d", run))
	}
}

// Generating cases out of order, or generating only a subset, must not change
// any individual case: Case(i) depends on i alone.
func TestCaseIsIndependentOfGenerationOrder(t *testing.T) {
	p := testPlan(t)
	baseline := generateSequential(t, p)

	order := rand.New(rand.NewSource(12345)).Perm(p.Total())
	for _, i := range order {
		c, err := p.Case(i)
		if err != nil {
			t.Fatalf("Case(%d): %v", i, err)
		}
		if !bytes.Equal(c.Canonical(), baseline[i]) {
			t.Fatalf("case %d generated out of order differs\n want: %s\n  got: %s", i, baseline[i], c.Canonical())
		}
	}

	// Generating a single case in a fresh plan must match too.
	fresh := testPlan(t)
	for _, i := range []int{0, 1, p.Total() / 2, p.Total() - 1} {
		c, err := fresh.Case(i)
		if err != nil {
			t.Fatalf("Case(%d): %v", i, err)
		}
		if !bytes.Equal(c.Canonical(), baseline[i]) {
			t.Fatalf("case %d from a fresh plan differs", i)
		}
	}
}

// Acceptance criterion 2: two separate OS processes generate the same
// sequence byte for byte. The child re-executes this test binary in dump mode
// and prints the canonical cases; the parent compares them with its own.
func TestSeparateProcessesProduceIdenticalSequences(t *testing.T) {
	parent := generateSequential(t, testPlan(t))

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), dumpEnv+"=1")
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

	// Compare the generated requests themselves, not logs or timings.
	requireEqualSequences(t, parent, child, "separate process")
	t.Logf("compared %d cases across two processes", len(parent))
}

const dumpEnv = "MIHAKK_TEST_DUMP_CASES"

// TestMain lets the test binary act as the child process for the
// cross-process determinism test.
func TestMain(m *testing.M) {
	if os.Getenv(dumpEnv) != "" {
		if err := dumpCases(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv(ambiguousDumpEnv) != "" {
		if err := dumpAmbiguousCases(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// dumpCases regenerates the sequence from the same literal inputs and writes
// each canonical case as one JSON value on stdout.
func dumpCases() error {
	c, err := corpus.Parse([]byte(testCorpusJSON))
	if err != nil {
		return fmt.Errorf("child: parse corpus: %w", err)
	}
	p, err := NewPlan(c, DefaultConfig(), testEngineVersion, []byte("seed-alpha"))
	if err != nil {
		return fmt.Errorf("child: new plan: %w", err)
	}
	enc := json.NewEncoder(os.Stdout)
	for i := 0; i < p.Total(); i++ {
		cse, err := p.Case(i)
		if err != nil {
			return fmt.Errorf("child: case %d: %w", i, err)
		}
		if err := enc.Encode(json.RawMessage(cse.Canonical())); err != nil {
			return err
		}
	}
	return nil
}

// Acceptance criterion 3: seed, engine version, config and corpus each change
// the derivation digest and the generated mutations, independently.
func TestEachInputChangesTheSequence(t *testing.T) {
	base := testCorpus(t)
	baseCfg := DefaultConfig()
	basePlan, err := NewPlan(base, baseCfg, testEngineVersion, []byte("seed-alpha"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	baseSeq := generateSequential(t, basePlan)

	build := func(t *testing.T, c *corpus.Corpus, cfg Config, version string, seed []byte) *Plan {
		t.Helper()
		p, err := NewPlan(c, cfg, version, seed)
		if err != nil {
			t.Fatalf("NewPlan: %v", err)
		}
		return p
	}

	t.Run("seed", func(t *testing.T) {
		p := build(t, testCorpus(t), baseCfg, testEngineVersion, []byte("seed-beta"))
		assertDifferentDerivationAndOutput(t, basePlan, baseSeq, p)
	})

	t.Run("engine_version", func(t *testing.T) {
		p := build(t, testCorpus(t), baseCfg, "0.2.1-test", []byte("seed-alpha"))
		assertDifferentDerivationAndOutput(t, basePlan, baseSeq, p)
	})

	t.Run("config", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.MaxValueBytes = 256 // same target set, different generation
		p := build(t, testCorpus(t), cfg, testEngineVersion, []byte("seed-alpha"))
		assertDifferentDerivationAndOutput(t, basePlan, baseSeq, p)
	})

	t.Run("corpus", func(t *testing.T) {
		c := testCorpus(t)
		// Change one sample's value without changing the target structure, so
		// the case count stays comparable.
		c.Samples[0].URL = "http://testbed:8000/api/items?page=2&limit=20&q=shoes"
		p := build(t, c, baseCfg, testEngineVersion, []byte("seed-alpha"))
		assertDifferentDerivationAndOutput(t, basePlan, baseSeq, p)
	})
}

// assertDifferentDerivationAndOutput checks that the fingerprint moved and
// that the difference actually shows up in the generated requests.
func assertDifferentDerivationAndOutput(t *testing.T, basePlan *Plan, baseSeq [][]byte, other *Plan) {
	t.Helper()
	if other.DerivationDigest() == basePlan.DerivationDigest() {
		t.Fatalf("derivation digest did not change: %s", other.DerivationDigest())
	}

	otherSeq := generateSequential(t, other)

	compare := minInt(len(baseSeq), len(otherSeq))
	if compare == 0 {
		t.Fatal("no cases to compare")
	}
	differing := 0
	for i := 0; i < compare; i++ {
		if !bytes.Equal(baseSeq[i], otherSeq[i]) {
			differing++
		}
	}
	// Require a substantial fraction to differ, not merely one case: a single
	// difference could be coincidence, while a changed derivation should
	// re-roll essentially the whole sequence.
	if ratio := float64(differing) / float64(compare); ratio < 0.5 {
		t.Fatalf("only %d of %d compared cases differ (%.1f%%); expected the sequence to be re-rolled",
			differing, compare, ratio*100)
	}
	t.Logf("%d of %d cases differ", differing, compare)
}

// Equivalent-but-differently-written inputs must NOT change the sequence, or
// every harmless reformat would invalidate saved cases.
func TestEquivalentInputsKeepTheSameSequence(t *testing.T) {
	a := testPlan(t)
	aSeq := generateSequential(t, a)

	// Same samples, listed in a different order, with differently-cased
	// method and header names.
	reordered := `{
  "corpus_version": "1",
  "samples": [
    {
      "id": "upload-blob",
      "method": "post",
      "url": "http://testbed:8000/api/blob",
      "headers": {"content-type": ["application/octet-stream"]},
      "body": "cmF3LWJpbmFyeS1wYXlsb2Fk",
      "body_encoding": "base64"
    },
    {
      "id": "login-form",
      "method": "POST",
      "url": "http://testbed:8000/api/session",
      "headers": {"CONTENT-TYPE": ["application/x-www-form-urlencoded"]},
      "body": "username=rawabi&remember=1"
    },
    {
      "id": "create-order",
      "method": "POST",
      "url": "http://testbed:8000/api/orders",
      "headers": {"content-type": ["application/json"], "accept": ["application/json"]},
      "body": "{\"customer\":{\"id\":42,\"name\":\"Rawabi\"},\"items\":[{\"sku\":\"A-1\",\"qty\":2}],\"express\":true,\"note\":null}"
    },
    {
      "id": "list-items",
      "method": "get",
      "url": "http://testbed:8000/api/items?page=1&limit=20&q=shoes",
      "headers": {"accept": ["application/json"], "user-agent": ["mihakk/0.1"]}
    }
  ]
}`
	c, err := corpus.Parse([]byte(reordered))
	if err != nil {
		t.Fatalf("parse reordered corpus: %v", err)
	}

	cfg := DefaultConfig()
	cfg.MutableHeaders = []string{"x-request-id", "USER-AGENT", "Accept", "Accept-Language", "Accept"}

	b, err := NewPlan(c, cfg, testEngineVersion, []byte("seed-alpha"))
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	if a.DerivationDigest() != b.DerivationDigest() {
		t.Fatalf("equivalent inputs produced different derivations:\n a=%s\n b=%s",
			a.DerivationDigest(), b.DerivationDigest())
	}
	requireEqualSequences(t, aSeq, generateSequential(t, b), "equivalent inputs")
}

// The case index ordering must be stable: sorting by index recovers the
// canonical sequence even if cases arrive shuffled.
func TestSortingByIndexRecoversTheSequence(t *testing.T) {
	p := testPlan(t)
	baseline := generateSequential(t, p)

	type indexed struct {
		idx  int
		data []byte
	}
	shuffled := make([]indexed, 0, p.Total())
	for _, i := range rand.New(rand.NewSource(999)).Perm(p.Total()) {
		c, err := p.Case(i)
		if err != nil {
			t.Fatalf("Case(%d): %v", i, err)
		}
		shuffled = append(shuffled, indexed{c.Index, c.Canonical()})
	}
	sort.Slice(shuffled, func(i, j int) bool { return shuffled[i].idx < shuffled[j].idx })

	for i, s := range shuffled {
		if s.idx != i {
			t.Fatalf("after sorting, position %d holds index %d", i, s.idx)
		}
		if !bytes.Equal(s.data, baseline[i]) {
			t.Fatalf("case %d differs after sort-by-index", i)
		}
	}
}
