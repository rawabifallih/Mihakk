package mutate

import (
	"encoding/json"
	"strings"
)

// Mutators produce malformed *structure*: boundary values, type confusion,
// truncation, oversized input, encoding damage and delimiter characters.
//
// They deliberately do not produce ready-made exploit payloads. There are no
// SQL injection strings, no script tags, no template-injection probes and no
// authentication-bypass attempts. Mihakk looks for crashes and unusual
// behaviour under unexpected input; turning it into an exploit generator is
// out of scope by design. Individual delimiter characters (quotes, angle
// brackets, backslashes, newlines, NUL) are included because they are how you
// find a parser that mishandles its own input format, not because they are
// assembled into an attack.
//
// Every mutator must honour its byte budget: nothing here may produce a value
// larger than budget.

// clampString truncates at a UTF-8 boundary so a clamped value stays valid
// UTF-8 wherever the input was.
func clampString(s string, budget int) string {
	if budget <= 0 {
		return ""
	}
	if len(s) <= budget {
		return s
	}
	cut := s[:budget]
	for len(cut) > 0 && !utf8Complete(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// utf8Complete reports whether s ends on a complete UTF-8 sequence.
func utf8Complete(s string) bool {
	if s == "" {
		return true
	}
	for i := len(s) - 1; i >= 0 && i >= len(s)-4; i-- {
		b := s[i]
		if b&0xC0 == 0x80 {
			continue // continuation byte, keep walking back
		}
		trailing := len(s) - i
		switch {
		case b&0x80 == 0:
			return trailing == 1
		case b&0xE0 == 0xC0:
			return trailing == 2
		case b&0xF0 == 0xE0:
			return trailing == 3
		case b&0xF8 == 0xF0:
			return trailing == 4
		default:
			return false
		}
	}
	return false
}

// delimiters are single structural characters, not payloads.
var delimiters = []string{
	"'", "\"", "`", "\\", "/", "<", ">", "&", "|", ";", ":", ",",
	"{", "}", "[", "]", "(", ")", "=", "?", "#", "%", "*",
	"\n", "\r", "\t", "\x00",
}

// numericEdges are boundary numbers expressed as text.
var numericEdges = []string{
	"0", "-0", "1", "-1",
	"2147483647", "-2147483648",
	"2147483648", "-2147483649",
	"9223372036854775807", "-9223372036854775808",
	"9223372036854775808", "-9223372036854775809",
	"1e309", "-1e309",
	"0.1", "-0.0000001", "1e-400",
	"NaN", "Infinity", "-Infinity",
	"0x10", "0b1", "010", "1_000",
	"", " ", "+", "-", ".", "1.2.3",
}

// jsonNumberEdges is the subset of numericEdges that is valid JSON number
// grammar. type_to_number must use this list: encoding/json refuses to
// marshal a json.Number like "NaN" or "0x10", which would fail generation
// rather than produce an interesting request.
//
// The invalid literals are not lost -- they still reach the target through
// the string-valued mutators (as {"qty":"NaN"}), which exercises the target's
// own parsing and coercion. Emitting a syntactically malformed JSON *body* is
// covered separately by the raw-body mutators, which also apply to JSON
// samples.
var jsonNumberEdges = []string{
	"0", "-0", "1", "-1",
	"2147483647", "-2147483648",
	"2147483648", "-2147483649",
	"9223372036854775807", "-9223372036854775808",
	"9223372036854775808", "-9223372036854775809",
	"1e309", "-1e309",
	"0.1", "-0.0000001", "1e-400",
}

// unicodeOddities exercise encoding handling without being an attack.
// Written as escapes, never literal characters: several of these are
// invisible or direction-changing, and a literal BOM is not even legal Go.
var unicodeOddities = []string{
	"\x00", "\x1b", "\x7f",
	"\u00e9", "\u0301", // e-acute, combining acute accent
	"\u200b", "\u200e", "\u202e", // zero-width space, LTR mark, RTL override
	"\ufeff", "\ufffd", // BOM, replacement character
	"\U0001f600", // astral plane
	"\u0627\u0644\u0639\u0631\u0628\u064a\u0629", // non-Latin script
	"\uff21\uff22", // fullwidth Latin
}

// encodingDamage breaks percent-encoding and escaping assumptions.
var encodingDamage = []string{
	"%", "%%", "%z", "%zz", "%00", "%0a", "%2f", "%25", "%u0041",
	"\\x00", "\\u0000", "\\\\", "\\",
	"&amp;", "&#0;", "+", "%20%20",
}

type stringMutator struct {
	name  string
	apply func(s *stream, original string, budget int) string
}

// stringMutators apply to query values, form values and header values.
var stringMutators = []stringMutator{
	{"empty", func(_ *stream, _ string, _ int) string { return "" }},

	{"oversized", func(s *stream, original string, budget int) string {
		if budget <= 0 {
			return ""
		}
		unit := original
		if unit == "" {
			unit = "A"
		}
		repeated := strings.Repeat(unit, budget/len(unit)+1)
		return repeated[:budget]
	}},

	{"whitespace", func(s *stream, original string, budget int) string {
		pads := []string{" ", "\t", "\n", "\r\n", "\u00a0"}
		pad := pads[s.pick(len(pads))]
		return clampString(pad+original+pad, budget)
	}},

	{"truncated", func(s *stream, original string, budget int) string {
		if original == "" {
			return ""
		}
		return clampString(original[:s.intn(len(original))], budget)
	}},

	{"repeated", func(s *stream, original string, budget int) string {
		if original == "" {
			original = "A"
		}
		times := 2 + s.intn(8)
		return clampString(strings.Repeat(original, times), budget)
	}},

	{"numeric_edge", func(s *stream, _ string, budget int) string {
		return clampString(numericEdges[s.pick(len(numericEdges))], budget)
	}},

	{"delimiter", func(s *stream, original string, budget int) string {
		d := delimiters[s.pick(len(delimiters))]
		switch s.intn(3) {
		case 0:
			return clampString(d, budget)
		case 1:
			return clampString(original+d, budget)
		default:
			return clampString(d+original, budget)
		}
	}},

	{"unicode", func(s *stream, original string, budget int) string {
		u := unicodeOddities[s.pick(len(unicodeOddities))]
		if s.boolean() {
			return clampString(u, budget)
		}
		return clampString(original+u, budget)
	}},

	{"encoding_damage", func(s *stream, original string, budget int) string {
		e := encodingDamage[s.pick(len(encodingDamage))]
		if s.boolean() {
			return clampString(e, budget)
		}
		return clampString(e+original, budget)
	}},

	{"random_bytes", func(s *stream, _ string, budget int) string {
		n := 1 + s.intn(minInt(64, maxInt(1, budget)))
		raw := s.bytes(n)
		// Kept printable so reports stay readable; the structural point is the
		// unexpected content, not unprintable bytes specifically.
		out := make([]byte, len(raw))
		for i, b := range raw {
			out[i] = byte(33 + int(b)%94)
		}
		return clampString(string(out), budget)
	}},

	{"case_flip", func(s *stream, original string, budget int) string {
		if original == "" {
			return "A"
		}
		if s.boolean() {
			return clampString(strings.ToUpper(original), budget)
		}
		return clampString(strings.ToLower(original), budget)
	}},

	{"null_literal", func(s *stream, _ string, budget int) string {
		lits := []string{"null", "nil", "NULL", "undefined", "None", "false", "true", "[]", "{}"}
		return clampString(lits[s.pick(len(lits))], budget)
	}},
}

type jsonMutator struct {
	name  string
	apply func(s *stream, original any, budget int) any
}

// jsonMutators additionally exercise type confusion, which is only meaningful
// in a typed document.
var jsonMutators = buildJSONMutators()

func buildJSONMutators() []jsonMutator {
	out := make([]jsonMutator, 0, len(stringMutators)+7)

	// Reuse the string mutators against the textual form of the node.
	for _, m := range stringMutators {
		m := m
		out = append(out, jsonMutator{"json_" + m.name, func(s *stream, original any, budget int) any {
			return m.apply(s, jsonText(original), budget)
		}})
	}

	out = append(out,
		jsonMutator{"type_to_null", func(*stream, any, int) any { return nil }},
		jsonMutator{"type_to_bool", func(s *stream, _ any, _ int) any { return s.boolean() }},
		jsonMutator{"type_to_number", func(s *stream, _ any, _ int) any {
			return json.Number(jsonNumberEdges[s.pick(len(jsonNumberEdges))])
		}},
		jsonMutator{"type_to_array", func(s *stream, original any, _ int) any {
			switch s.intn(3) {
			case 0:
				return []any{}
			case 1:
				return []any{original}
			default:
				return []any{original, original}
			}
		}},
		jsonMutator{"type_to_object", func(s *stream, original any, _ int) any {
			switch s.intn(3) {
			case 0:
				return map[string]any{}
			case 1:
				return map[string]any{"value": original}
			default:
				return map[string]any{"": original}
			}
		}},
		jsonMutator{"deep_nest", func(s *stream, original any, _ int) any {
			depth := 4 + s.intn(12)
			node := original
			for i := 0; i < depth; i++ {
				node = []any{node}
			}
			return node
		}},
		jsonMutator{"type_to_string", func(s *stream, original any, budget int) any {
			return clampString(jsonText(original), budget)
		}},
	)
	return out
}

// jsonText renders a JSON node as text for the string mutators.
func jsonText(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

type rawMutator struct {
	name  string
	apply func(s *stream, original []byte, budget int) []byte
}

// rawMutators apply to opaque bodies.
var rawMutators = []rawMutator{
	{"raw_empty", func(*stream, []byte, int) []byte { return nil }},

	{"raw_truncate", func(s *stream, original []byte, _ int) []byte {
		if len(original) == 0 {
			return nil
		}
		return original[:s.intn(len(original))]
	}},

	{"raw_bit_flip", func(s *stream, original []byte, _ int) []byte {
		if len(original) == 0 {
			return []byte{0}
		}
		out := append([]byte(nil), original...)
		flips := 1 + s.intn(8)
		for i := 0; i < flips; i++ {
			pos := s.intn(len(out))
			out[pos] ^= 1 << uint(s.intn(8))
		}
		return out
	}},

	{"raw_oversized", func(s *stream, original []byte, budget int) []byte {
		if budget <= 0 {
			return nil
		}
		unit := original
		if len(unit) == 0 {
			unit = []byte("A")
		}
		out := make([]byte, 0, budget+len(unit))
		for len(out) < budget {
			out = append(out, unit...)
		}
		return out[:budget]
	}},

	{"raw_null_bytes", func(s *stream, original []byte, budget int) []byte {
		out := append([]byte(nil), original...)
		inserts := 1 + s.intn(4)
		for i := 0; i < inserts && len(out) < budget; i++ {
			pos := s.intn(len(out) + 1)
			tail := append([]byte{0}, out[pos:]...)
			out = append(out[:pos:pos], tail...)
		}
		if len(out) > budget {
			out = out[:budget]
		}
		return out
	}},

	{"raw_random", func(s *stream, _ []byte, budget int) []byte {
		n := 1 + s.intn(minInt(256, maxInt(1, budget)))
		return s.bytes(n)
	}},
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
