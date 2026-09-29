package mutate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// ErrInvalidConfig means the mutation settings cannot be used as they stand.
var ErrInvalidConfig = errors.New("mihakk: invalid mutation config")

// Config controls how the mutation space is enumerated and how large a
// generated input may get. Every field feeds the config digest, so changing
// any of them changes every generated mutation.
type Config struct {
	// MutationsPerTarget is how many distinct mutations to generate for each
	// mutable field.
	MutationsPerTarget int `json:"mutations_per_target"`

	// MaxValueBytes caps a value that a mutation produces. It does not apply
	// to a sample's own header values, which pass through untouched.
	MaxValueBytes int `json:"max_value_bytes"`
	// MaxBodyBytes caps the whole generated body, mutated or not. A sample
	// whose body already exceeds it is refused when the plan is built.
	MaxBodyBytes int `json:"max_body_bytes"`
	// MaxURLBytes caps the whole generated URL, on the same terms.
	MaxURLBytes int `json:"max_url_bytes"`
	// MaxTargetsPerSample bounds how many mutable locations one sample
	// contributes, so a large body cannot explode the plan size.
	MaxTargetsPerSample int `json:"max_targets_per_sample"`

	MutateQuery   bool `json:"mutate_query"`
	MutateBody    bool `json:"mutate_body"`
	MutateHeaders bool `json:"mutate_headers"`

	// MutableHeaders is an allowlist of header names that may be mutated.
	// It is an allowlist rather than a denylist because the dangerous set is
	// open-ended: Host and friends change where the request goes, and
	// credential headers turn fuzzing into an authentication-bypass attempt.
	MutableHeaders []string `json:"mutable_headers"`
}

// DefaultConfig is deliberately modest: a small number of mutations per field
// and short values, so a first run stays well inside the session limits.
func DefaultConfig() Config {
	return Config{
		MutationsPerTarget:  8,
		MaxValueBytes:       512,
		MaxBodyBytes:        8192,
		MaxURLBytes:         2048,
		MaxTargetsPerSample: 64,
		MutateQuery:         true,
		MutateBody:          true,
		MutateHeaders:       true,
		MutableHeaders:      []string{"Accept", "Accept-Language", "User-Agent", "X-Request-Id"},
	}
}

// forbiddenHeaders can never be mutated, whatever the configuration says.
//
// Host and the forwarding headers decide where the request goes or how the
// target routes it; Content-Length and Transfer-Encoding must stay consistent
// with the body the engine actually sends; and mutating credential headers
// would make Mihakk generate authentication-bypass attempts, which is out of
// scope by design.
var forbiddenHeaders = map[string]bool{
	"Host":                true,
	"Content-Length":      true,
	"Transfer-Encoding":   true,
	"Connection":          true,
	"Upgrade":             true,
	"X-Forwarded-Host":    true,
	"X-Forwarded-For":     true,
	"X-Forwarded-Proto":   true,
	"Forwarded":           true,
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
}

// IsForbiddenHeader reports whether a header is never mutable.
func IsForbiddenHeader(name string) bool {
	return forbiddenHeaders[http.CanonicalHeaderKey(strings.TrimSpace(name))]
}

// Normalize canonicalises the header allowlist so equivalent spellings produce
// the same config digest.
func (c *Config) Normalize() {
	names := make([]string, 0, len(c.MutableHeaders))
	seen := map[string]bool{}
	for _, n := range c.MutableHeaders {
		key := http.CanonicalHeaderKey(strings.TrimSpace(n))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		names = append(names, key)
	}
	sort.Strings(names)
	if len(names) == 0 {
		names = nil
	}
	c.MutableHeaders = names
}

// Validate refuses settings that would generate unbounded or empty work.
func (c *Config) Validate() error {
	if c.MutationsPerTarget < 1 {
		return fmt.Errorf("%w: mutations_per_target must be >= 1", ErrInvalidConfig)
	}
	if c.MaxValueBytes < 1 {
		return fmt.Errorf("%w: max_value_bytes must be >= 1", ErrInvalidConfig)
	}
	if c.MaxBodyBytes < 1 {
		return fmt.Errorf("%w: max_body_bytes must be >= 1", ErrInvalidConfig)
	}
	if c.MaxURLBytes < 1 {
		return fmt.Errorf("%w: max_url_bytes must be >= 1", ErrInvalidConfig)
	}
	if c.MaxTargetsPerSample < 1 {
		return fmt.Errorf("%w: max_targets_per_sample must be >= 1", ErrInvalidConfig)
	}
	if !c.MutateQuery && !c.MutateBody && !c.MutateHeaders {
		return fmt.Errorf("%w: at least one of mutate_query/mutate_body/mutate_headers must be enabled", ErrInvalidConfig)
	}
	for _, n := range c.MutableHeaders {
		if IsForbiddenHeader(n) {
			return fmt.Errorf("%w: header %q can never be mutated (it changes the destination, "+
				"the framing, or carries credentials)", ErrInvalidConfig, n)
		}
	}
	return nil
}

// Digest fingerprints the canonical config.
func (c *Config) Digest() string {
	canon := *c
	canon.Normalize()
	b, err := json.Marshal(canon)
	if err != nil {
		panic("mutate: config digest: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// AllowsHeader reports whether a header may be mutated under this config.
func (c *Config) AllowsHeader(name string) bool {
	if !c.MutateHeaders {
		return false
	}
	key := http.CanonicalHeaderKey(strings.TrimSpace(name))
	if IsForbiddenHeader(key) {
		return false
	}
	for _, n := range c.MutableHeaders {
		if n == key {
			return true
		}
	}
	return false
}
