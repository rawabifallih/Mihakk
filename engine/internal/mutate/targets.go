package mutate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"mihakk/internal/corpus"
)

// TargetKind says which part of a request a mutation applies to.
type TargetKind string

const (
	TargetQuery   TargetKind = "query"
	TargetJSON    TargetKind = "json"
	TargetForm    TargetKind = "form"
	TargetHeader  TargetKind = "header"
	TargetRawBody TargetKind = "raw_body"
)

// Target names one mutable location inside a sample.
//
// The request path is deliberately absent. Mutating it could produce a
// destination outside the authorised path prefixes, and a fuzzer whose own
// output has to be discarded by the scope guard wastes budget and confuses
// results. Path mutation is a documented MVP limitation, not an oversight.
type Target struct {
	Kind TargetKind `json:"kind"`
	Name string     `json:"name"`

	// ValueIndex selects among repeated query/form values with the same name.
	ValueIndex int `json:"value_index,omitempty"`

	// steps locates a node inside a JSON body.
	steps []pathStep
}

type pathStep struct {
	Key     string
	Index   int
	IsIndex bool
}

func pathString(steps []pathStep) string {
	var b strings.Builder
	b.WriteByte('$')
	for _, s := range steps {
		if s.IsIndex {
			b.WriteByte('[')
			b.WriteString(strconv.Itoa(s.Index))
			b.WriteByte(']')
			continue
		}
		b.WriteByte('.')
		b.WriteString(s.Key)
	}
	return b.String()
}

// enumerateTargets lists every mutable location in a sample, in a fixed
// canonical order. The order is part of the reproducibility contract: case
// index i maps to a target by position, so the same corpus and config must
// always yield the same list.
func enumerateTargets(s *corpus.Sample, cfg *Config) ([]Target, error) {
	var targets []Target

	if cfg.MutateQuery {
		u, err := s.ParsedURL()
		if err != nil {
			return nil, err
		}
		q := u.Query()
		names := make([]string, 0, len(q))
		for name := range q {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			for i := range q[name] {
				targets = append(targets, Target{Kind: TargetQuery, Name: name, ValueIndex: i})
			}
		}
	}

	if cfg.MutateHeaders {
		for _, name := range s.HeaderNames() {
			if !cfg.AllowsHeader(name) {
				continue
			}
			for i := range s.Headers[name] {
				targets = append(targets, Target{Kind: TargetHeader, Name: name, ValueIndex: i})
			}
		}
	}

	if cfg.MutateBody {
		body, err := s.DecodedBody()
		if err != nil {
			return nil, err
		}
		switch s.BodyKind() {
		case corpus.BodyJSON:
			doc, err := decodeJSON(body)
			if err != nil {
				return nil, fmt.Errorf("sample %q: %w", s.ID, err)
			}
			var walk func(node any, steps []pathStep)
			walk = func(node any, steps []pathStep) {
				owned := append([]pathStep(nil), steps...)
				targets = append(targets, Target{
					Kind: TargetJSON, Name: pathString(owned), steps: owned,
				})
				switch t := node.(type) {
				case map[string]any:
					keys := make([]string, 0, len(t))
					for k := range t {
						keys = append(keys, k)
					}
					sort.Strings(keys) // map order in Go is random; sorting makes this reproducible
					for _, k := range keys {
						walk(t[k], append(owned, pathStep{Key: k}))
					}
				case []any:
					for i := range t {
						walk(t[i], append(owned, pathStep{Index: i, IsIndex: true}))
					}
				}
			}
			walk(doc, nil)

			// A JSON body is also fuzzed as opaque bytes, so that truncation
			// and bit flips produce syntactically malformed JSON -- something
			// field-level mutation cannot reach, because the result is always
			// re-encoded as valid JSON.
			targets = append(targets, Target{Kind: TargetRawBody, Name: "<body>"})

		case corpus.BodyForm:
			values, err := url.ParseQuery(string(body))
			if err != nil {
				return nil, fmt.Errorf("sample %q: form body does not parse: %w", s.ID, err)
			}
			names := make([]string, 0, len(values))
			for name := range values {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				for i := range values[name] {
					targets = append(targets, Target{Kind: TargetForm, Name: name, ValueIndex: i})
				}
			}

		case corpus.BodyRaw:
			targets = append(targets, Target{Kind: TargetRawBody, Name: "<body>"})
		}
	}

	// Bound the plan: a large sample must not generate an unbounded number of
	// cases. Truncation is deterministic because the list order is.
	if cfg.MaxTargetsPerSample > 0 && len(targets) > cfg.MaxTargetsPerSample {
		targets = targets[:cfg.MaxTargetsPerSample]
	}
	return targets, nil
}

// decodeJSON decodes with UseNumber so numeric literals survive a decode and
// re-encode round trip unchanged.
func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("body is not valid JSON: %w", err)
	}
	return doc, nil
}

// getAtPath returns the node at steps.
func getAtPath(doc any, steps []pathStep) (any, bool) {
	cur := doc
	for _, s := range steps {
		switch t := cur.(type) {
		case map[string]any:
			if s.IsIndex {
				return nil, false
			}
			v, ok := t[s.Key]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			if !s.IsIndex || s.Index < 0 || s.Index >= len(t) {
				return nil, false
			}
			cur = t[s.Index]
		default:
			return nil, false
		}
	}
	return cur, true
}

// setAtPath writes v at steps and returns the resulting document. An empty
// path replaces the whole document.
func setAtPath(doc any, steps []pathStep, v any) (any, error) {
	if len(steps) == 0 {
		return v, nil
	}
	parent, ok := getAtPath(doc, steps[:len(steps)-1])
	if !ok {
		return nil, fmt.Errorf("mutate: path %s no longer exists", pathString(steps))
	}
	last := steps[len(steps)-1]
	switch t := parent.(type) {
	case map[string]any:
		if last.IsIndex {
			return nil, fmt.Errorf("mutate: path %s expects an object key", pathString(steps))
		}
		t[last.Key] = v
	case []any:
		if !last.IsIndex || last.Index < 0 || last.Index >= len(t) {
			return nil, fmt.Errorf("mutate: path %s is out of range", pathString(steps))
		}
		t[last.Index] = v
	default:
		return nil, fmt.Errorf("mutate: path %s has no container", pathString(steps))
	}
	return doc, nil
}
