package safety

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Placeholder replaces every redacted value. It is a fixed marker so reports
// and diffs stay readable, and so a reviewer can see that something was
// removed rather than that a field was absent.
const Placeholder = "[REDACTED]"

// sensitiveNames are header names, query parameters and JSON object keys whose
// values never reach a log, a stored case or a report. Matching is done on a
// normalised form (lowercased, "_" folded to "-").
var sensitiveNames = map[string]bool{
	"authorization": true, "proxy-authorization": true, "authentication": true,
	"cookie": true, "set-cookie": true,
	"x-api-key": true, "api-key": true, "apikey": true,
	"x-auth-token": true, "auth-token": true, "x-authentication-token": true,
	"x-access-token": true, "access-token": true, "access-key": true,
	"refresh-token": true, "x-refresh-token": true,
	"x-csrf-token": true, "csrf-token": true, "x-xsrf-token": true, "xsrf-token": true,
	"x-session-token": true, "session-token": true,
	"session": true, "sessionid": true, "session-id": true, "sid": true,
	"token": true, "id-token": true, "bearer": true,
	"secret": true, "client-secret": true, "secret-key": true, "api-secret": true,
	"password": true, "passwd": true, "pwd": true, "passphrase": true, "pass": true,
	"signature": true, "sig": true,
	"private-key": true, "privatekey": true,
	"x-amz-security-token": true, "x-goog-api-key": true,
}

// valuePatterns catch credentials that appear in free text or in fields whose
// name gives nothing away.
var valuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`), // JWT
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{8,}`),
	regexp.MustCompile(`(?i)\bbasic\s+[A-Za-z0-9+/=]{12,}`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{16,}\b`),
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`),
	regexp.MustCompile(`-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----`),
}

// Redactor removes credentials on the way out of the engine. It is applied at
// the boundary -- before anything is written to the audit log, the case store
// or an event -- so no downstream component has to remember to do it.
//
// Mihakk additionally avoids the problem at the source: stored cases keep a
// regeneration recipe rather than concrete request headers, so credentials are
// not written to disk even before redaction runs.
type Redactor struct {
	extraNames map[string]bool

	// literals are exact secret values the caller knows about -- the token in
	// a sample's Authorization header, the password in its body. Name-based
	// redaction stops working the moment a mutation makes a body unparseable;
	// the literal value is still the same string, so it can still be removed.
	literals []string
}

// NewRedactor builds a redactor. extraHeaders adds deployment-specific header
// or field names to the built-in list.
func NewRedactor(extraNames ...string) *Redactor {
	r := &Redactor{extraNames: map[string]bool{}}
	for _, n := range extraNames {
		if n = normalizeName(n); n != "" {
			r.extraNames[n] = true
		}
	}
	return r
}

// minLiteralLength avoids registering a value so short that redacting it
// everywhere would mangle unrelated text.
const minLiteralLength = 6

// AddLiteral registers an exact value that must never be emitted. Values
// shorter than minLiteralLength are ignored: replacing a three-character
// string across every report would destroy more than it protects.
func (r *Redactor) AddLiteral(value string) {
	if len(value) < minLiteralLength {
		return
	}
	for _, existing := range r.literals {
		if existing == value {
			return
		}
	}
	r.literals = append(r.literals, value)
}

func normalizeName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	return strings.ReplaceAll(n, "_", "-")
}

// IsSensitiveName reports whether a header/param/field name must be redacted.
func (r *Redactor) IsSensitiveName(name string) bool {
	n := normalizeName(name)
	if sensitiveNames[n] {
		return true
	}
	return r.extraNames[n]
}

// Headers returns a copy with sensitive values replaced. The original header
// set is never modified, and names are preserved so a reader can still see
// which headers were sent.
func (r *Redactor) Headers(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for name, values := range h {
		if r.IsSensitiveName(name) {
			out[name] = []string{Placeholder}
			continue
		}
		cleaned := make([]string, len(values))
		for i, v := range values {
			cleaned[i] = r.String(v)
		}
		out[name] = cleaned
	}
	return out
}

// String redacts credential-shaped substrings, and any registered literal,
// in free text.
func (r *Redactor) String(s string) string {
	for _, literal := range r.literals {
		s = strings.ReplaceAll(s, literal, Placeholder)
	}
	for _, p := range valuePatterns {
		s = p.ReplaceAllString(s, Placeholder)
	}
	return s
}

// URL redacts sensitive query parameters and any credentials in the userinfo,
// returning a string safe to log.
func (r *Redactor) URL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	if c.User != nil {
		c.User = url.User(Placeholder)
	}
	if c.RawQuery != "" {
		q := c.Query()
		for key := range q {
			if r.IsSensitiveName(key) {
				q.Set(key, Placeholder)
			} else {
				for i, v := range q[key] {
					q[key][i] = r.String(v)
				}
			}
		}
		c.RawQuery = q.Encode()
	}
	c.Fragment = ""
	return r.String(c.String())
}

// Body redacts a request or response body. JSON is walked key by key so that
// sensitive fields are removed by name; anything else falls back to pattern
// matching on the raw text.
func (r *Redactor) Body(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	var parsed any
	if err := json.Unmarshal(b, &parsed); err == nil {
		redacted := r.value(parsed)
		if out, err := json.Marshal(redacted); err == nil {
			// A literal can still appear in a key, or inside a value the
			// walk left alone, so the encoded form gets one final sweep.
			return []byte(r.String(string(out)))
		}
	}
	return []byte(r.String(string(b)))
}

// value walks a decoded JSON document.
func (r *Redactor) value(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, inner := range t {
			if r.IsSensitiveName(k) {
				out[k] = Placeholder
				continue
			}
			out[k] = r.value(inner)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, inner := range t {
			out[i] = r.value(inner)
		}
		return out
	case string:
		return r.String(t)
	default:
		return v
	}
}
