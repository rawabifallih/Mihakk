package mutate

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestStreamIsDeterministicForAKey(t *testing.T) {
	key := [32]byte{1, 2, 3}
	a := newStream(key)
	b := newStream(key)
	if !bytes.Equal(a.bytes(256), b.bytes(256)) {
		t.Fatal("two streams with the same key produced different bytes")
	}

	var other [32]byte
	copy(other[:], key[:])
	other[31] ^= 1
	c := newStream(other)
	if bytes.Equal(newStream(key).bytes(256), c.bytes(256)) {
		t.Fatal("a one-bit key change produced the same bytes")
	}
}

// The stream must not repeat within a case: a short period would make the
// mutators produce visibly repetitive input.
func TestStreamDoesNotRepeatAcrossBlocks(t *testing.T) {
	s := newStream([32]byte{7})
	first := s.bytes(32)
	for block := 0; block < 32; block++ {
		if bytes.Equal(first, s.bytes(32)) {
			t.Fatalf("stream repeated its first block at block %d", block+1)
		}
	}
}

func TestIntnStaysInRangeAndCoversIt(t *testing.T) {
	s := newStream([32]byte{9})
	const n = 7
	seen := map[int]int{}
	for i := 0; i < 5000; i++ {
		v := s.intn(n)
		if v < 0 || v >= n {
			t.Fatalf("intn(%d) = %d, out of range", n, v)
		}
		seen[v]++
	}
	if len(seen) != n {
		t.Fatalf("intn(%d) produced only %d distinct values: %v", n, len(seen), seen)
	}
	// Rejection sampling should keep the buckets roughly even. A crude bound
	// catches a badly biased implementation without being flaky.
	expected := 5000 / n
	for v, count := range seen {
		if math.Abs(float64(count-expected)) > float64(expected)/2 {
			t.Errorf("value %d appeared %d times, expected around %d", v, count, expected)
		}
	}
}

func TestIntnHandlesDegenerateBounds(t *testing.T) {
	s := newStream([32]byte{11})
	if got := s.intn(0); got != 0 {
		t.Errorf("intn(0) = %d, want 0", got)
	}
	if got := s.intn(-5); got != 0 {
		t.Errorf("intn(-5) = %d, want 0", got)
	}
	if got := s.intn(1); got != 0 {
		t.Errorf("intn(1) = %d, want 0", got)
	}
}

func TestPowerOfTwoBoundsAreUniform(t *testing.T) {
	s := newStream([32]byte{13})
	seen := map[int]int{}
	for i := 0; i < 4000; i++ {
		seen[s.intn(8)]++
	}
	if len(seen) != 8 {
		t.Fatalf("intn(8) produced %d distinct values, want 8", len(seen))
	}
}

func TestBooleanIsBalanced(t *testing.T) {
	s := newStream([32]byte{17})
	trues := 0
	const n = 4000
	for i := 0; i < n; i++ {
		if s.boolean() {
			trues++
		}
	}
	if trues < n*2/5 || trues > n*3/5 {
		t.Fatalf("boolean() returned true %d times out of %d, expected roughly half", trues, n)
	}
}

func TestBytesZeroLength(t *testing.T) {
	s := newStream([32]byte{19})
	if got := s.bytes(0); got != nil {
		t.Fatalf("bytes(0) = %v, want nil", got)
	}
	if got := s.bytes(-1); got != nil {
		t.Fatalf("bytes(-1) = %v, want nil", got)
	}
}

func TestClampStringHonoursBudgetAndUTF8(t *testing.T) {
	// A three-byte rune clamped to two bytes must be dropped, not split.
	const snowman = "☃" // 3 bytes
	if got := clampString(snowman, 2); got != "" {
		t.Fatalf("clampString(3-byte rune, 2) = %q, want empty", got)
	}
	if got := clampString(snowman, 3); got != snowman {
		t.Fatalf("clampString(3-byte rune, 3) = %q, want it intact", got)
	}
	if got := clampString("abcdef", 3); got != "abc" {
		t.Fatalf("clampString = %q, want abc", got)
	}
	if got := clampString("abc", 0); got != "" {
		t.Fatalf("clampString(_, 0) = %q, want empty", got)
	}
	for _, in := range []string{"", "a", snowman, "a" + snowman + "b", "\U0001f600"} {
		for budget := 0; budget <= len(in)+2; budget++ {
			out := clampString(in, budget)
			if len(out) > budget {
				t.Fatalf("clampString(%q, %d) returned %d bytes", in, budget, len(out))
			}
		}
	}
}

func TestConfigValidation(t *testing.T) {
	base := DefaultConfig()
	if err := base.Validate(); err != nil {
		t.Fatalf("DefaultConfig is invalid: %v", err)
	}

	mutators := map[string]func(*Config){
		"mutations_per_target":   func(c *Config) { c.MutationsPerTarget = 0 },
		"max_value_bytes":        func(c *Config) { c.MaxValueBytes = 0 },
		"max_body_bytes":         func(c *Config) { c.MaxBodyBytes = 0 },
		"max_url_bytes":          func(c *Config) { c.MaxURLBytes = 0 },
		"max_targets_per_sample": func(c *Config) { c.MaxTargetsPerSample = 0 },
		"nothing enabled": func(c *Config) {
			c.MutateQuery, c.MutateBody, c.MutateHeaders = false, false, false
		},
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			mutate(&cfg)
			if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate() = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestConfigDigestIsSpellingStable(t *testing.T) {
	a := DefaultConfig()
	a.MutableHeaders = []string{"Accept", "Accept-Language", "User-Agent", "X-Request-Id"}
	b := DefaultConfig()
	b.MutableHeaders = []string{"x-request-id", "ACCEPT", "user-agent", "Accept-Language", "Accept"}

	if a.Digest() != b.Digest() {
		t.Fatalf("equivalent header allowlists produced different digests:\n a=%s\n b=%s", a.Digest(), b.Digest())
	}

	c := DefaultConfig()
	c.MutableHeaders = append(c.MutableHeaders, "X-Extra")
	if c.Digest() == a.Digest() {
		t.Fatal("adding a mutable header did not change the digest")
	}
}

func TestAllowsHeaderRespectsTheAllowlist(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Normalize()

	if !cfg.AllowsHeader("accept") {
		t.Error("AllowsHeader(accept) = false, want true")
	}
	if cfg.AllowsHeader("X-Not-Listed") {
		t.Error("AllowsHeader(X-Not-Listed) = true, want false")
	}

	off := DefaultConfig()
	off.MutateHeaders = false
	if off.AllowsHeader("Accept") {
		t.Error("AllowsHeader returned true while header mutation is disabled")
	}
}
