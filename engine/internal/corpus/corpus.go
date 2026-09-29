// Package corpus holds the valid request samples that mutation-based fuzzing
// starts from.
//
// The corpus is canonicalised before use, and its digest is part of the
// derivation fingerprint that makes mutation generation reproducible. Two
// corpora that differ in ordering or spelling but not in content produce the
// same digest; any difference in actual content does not.
package corpus

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
)

var (
	// ErrInvalidCorpus means the samples cannot be used as they stand.
	ErrInvalidCorpus = errors.New("mihakk: invalid corpus")
	// ErrNoSuchSample means a lookup by ID found nothing.
	ErrNoSuchSample = errors.New("mihakk: no such sample")
)

// BodyKind describes how a sample's body should be interpreted for mutation.
type BodyKind string

const (
	BodyNone BodyKind = "none"
	BodyJSON BodyKind = "json"
	BodyForm BodyKind = "form"
	BodyRaw  BodyKind = "raw"
)

// Sample is one valid request that the operator knows the target accepts.
type Sample struct {
	ID      string              `json:"id"`
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers,omitempty"`

	// Body is the request body as text. Binary bodies set BodyEncoding to
	// "base64" and put the encoded form here.
	Body         string `json:"body,omitempty"`
	BodyEncoding string `json:"body_encoding,omitempty"`
}

// Corpus is an ordered set of samples.
type Corpus struct {
	CorpusVersion string   `json:"corpus_version"`
	Samples       []Sample `json:"samples"`
}

// CorpusVersion is the schema version of a corpus file.
const CorpusVersion = "1"

// Load reads, canonicalises and validates a corpus file.
func Load(path string) (*Corpus, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mihakk: reading corpus: %w", err)
	}
	return Parse(raw)
}

// Parse canonicalises and validates corpus bytes.
func Parse(raw []byte) (*Corpus, error) {
	var c Corpus
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: parsing corpus: %v", ErrInvalidCorpus, err)
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Normalize rewrites the corpus into canonical form: uppercase methods,
// canonical header names, samples sorted by ID. Canonicalising before hashing
// is what makes Digest stable across equivalent-but-differently-written files.
func (c *Corpus) Normalize() {
	if c.CorpusVersion == "" {
		c.CorpusVersion = CorpusVersion
	}
	for i := range c.Samples {
		s := &c.Samples[i]
		s.ID = strings.TrimSpace(s.ID)
		s.Method = strings.ToUpper(strings.TrimSpace(s.Method))
		s.URL = strings.TrimSpace(s.URL)
		s.BodyEncoding = strings.ToLower(strings.TrimSpace(s.BodyEncoding))

		if len(s.Headers) == 0 {
			s.Headers = nil
			continue
		}
		s.Headers = mergeHeaders(s.Headers)
	}
	sort.SliceStable(c.Samples, func(i, j int) bool { return c.Samples[i].ID < c.Samples[j].ID })
}

// mergeHeaders folds header names that differ only by case into one canonical
// entry.
//
// HTTP header names are case-insensitive, so a file may legitimately contain
// both "X-Tag" and "x-tag". They are distinct JSON keys, so both survive
// decoding, and merging them by ranging over the map would order their values
// by Go's randomised map iteration -- which made the corpus digest, and every
// mutation derived from it, differ between runs of the same input.
//
// Values are therefore concatenated in ascending order of the original
// spelling. That is a fixed, documented order, and it matches HTTP semantics:
// a header sent twice is one header with two values.
func mergeHeaders(in map[string][]string) map[string][]string {
	type spelled struct {
		spelling string
		values   []string
	}
	grouped := make(map[string][]spelled, len(in))
	for name, values := range in {
		key := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		grouped[key] = append(grouped[key], spelled{spelling: name, values: values})
	}
	if len(grouped) == 0 {
		return nil
	}

	out := make(map[string][]string, len(grouped))
	for key, list := range grouped {
		// Sort by the original spelling: the grouping loop above filled this
		// slice in random map order.
		sort.Slice(list, func(i, j int) bool { return list[i].spelling < list[j].spelling })
		merged := make([]string, 0, len(list))
		for _, sp := range list {
			merged = append(merged, sp.values...)
		}
		out[key] = merged
	}
	return out
}

// Validate rejects a corpus that cannot be fuzzed safely or reproducibly.
func (c *Corpus) Validate() error {
	if c.CorpusVersion != CorpusVersion {
		return fmt.Errorf("%w: unsupported corpus_version %q (expected %q)",
			ErrInvalidCorpus, c.CorpusVersion, CorpusVersion)
	}
	if len(c.Samples) == 0 {
		return fmt.Errorf("%w: corpus must contain at least one sample", ErrInvalidCorpus)
	}
	seen := map[string]bool{}
	for i, s := range c.Samples {
		if s.ID == "" {
			return fmt.Errorf("%w: sample %d has an empty id", ErrInvalidCorpus, i)
		}
		if seen[s.ID] {
			return fmt.Errorf("%w: duplicate sample id %q", ErrInvalidCorpus, s.ID)
		}
		seen[s.ID] = true

		if s.Method == "" {
			return fmt.Errorf("%w: sample %q has no method", ErrInvalidCorpus, s.ID)
		}
		u, err := url.Parse(s.URL)
		if err != nil {
			return fmt.Errorf("%w: sample %q has an unparsable url: %v", ErrInvalidCorpus, s.ID, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%w: sample %q must use an absolute http/https url", ErrInvalidCorpus, s.ID)
		}
		if u.Host == "" {
			return fmt.Errorf("%w: sample %q has no host", ErrInvalidCorpus, s.ID)
		}
		if u.User != nil {
			return fmt.Errorf("%w: sample %q must not carry credentials in the url", ErrInvalidCorpus, s.ID)
		}
		switch s.BodyEncoding {
		case "", "base64":
		default:
			return fmt.Errorf("%w: sample %q has unsupported body_encoding %q", ErrInvalidCorpus, s.ID, s.BodyEncoding)
		}
		if _, err := s.DecodedBody(); err != nil {
			return fmt.Errorf("%w: sample %q: %v", ErrInvalidCorpus, s.ID, err)
		}
	}
	return nil
}

// Digest fingerprints the canonical corpus. It is part of the derivation
// fingerprint, so changing any sample changes every generated mutation.
func (c *Corpus) Digest() string {
	canon := *c
	canon.Normalize()
	b, err := json.Marshal(canon)
	if err != nil {
		panic("corpus: digest: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Find returns the sample with the given ID.
func (c *Corpus) Find(id string) (*Sample, error) {
	for i := range c.Samples {
		if c.Samples[i].ID == id {
			return &c.Samples[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrNoSuchSample, id)
}

// DecodedBody returns the sample's body bytes.
func (s *Sample) DecodedBody() ([]byte, error) {
	if s.Body == "" {
		return nil, nil
	}
	if s.BodyEncoding == "base64" {
		out, err := base64.StdEncoding.DecodeString(s.Body)
		if err != nil {
			return nil, fmt.Errorf("body_encoding is base64 but the body does not decode: %w", err)
		}
		return out, nil
	}
	return []byte(s.Body), nil
}

// ParsedURL returns the sample's URL.
func (s *Sample) ParsedURL() (*url.URL, error) {
	return url.Parse(s.URL)
}

// ContentType returns the sample's declared content type, lowercased and
// without parameters.
func (s *Sample) ContentType() string {
	// Iterate in sorted name order. On a sample that has not been normalised,
	// several spellings of Content-Type may coexist, and picking whichever the
	// map yielded first would be non-deterministic.
	for _, name := range s.HeaderNames() {
		values := s.Headers[name]
		if http.CanonicalHeaderKey(name) != "Content-Type" || len(values) == 0 {
			continue
		}
		ct := values[0]
		if i := strings.IndexByte(ct, ';'); i >= 0 {
			ct = ct[:i]
		}
		return strings.ToLower(strings.TrimSpace(ct))
	}
	return ""
}

// BodyKind classifies the body for mutation purposes.
func (s *Sample) BodyKind() BodyKind {
	body, err := s.DecodedBody()
	if err != nil || len(body) == 0 {
		return BodyNone
	}
	switch s.ContentType() {
	case "application/json":
		return BodyJSON
	case "application/x-www-form-urlencoded":
		return BodyForm
	}
	// Fall back to sniffing: a body that parses as JSON is treated as JSON so
	// that field-aware mutation still applies when Content-Type is missing.
	if json.Valid(body) {
		return BodyJSON
	}
	return BodyRaw
}

// HeaderNames returns the sample's header names in sorted order, so that any
// enumeration over headers is deterministic.
func (s *Sample) HeaderNames() []string {
	names := make([]string, 0, len(s.Headers))
	for name := range s.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
