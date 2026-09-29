package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Target is one entry in the allowlist. A target is deliberately narrow: an
// exact scheme, host and port, plus the path prefixes and methods the operator
// authorised. There are no wildcard hosts in the MVP -- a wildcard is an easy
// way to accidentally authorise something you do not own.
type Target struct {
	Scheme       string   `json:"scheme"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	PathPrefixes []string `json:"path_prefixes"`
	Methods      []string `json:"methods"`

	// AllowedAddresses authorises the specific restricted addresses this target
	// may resolve to. Entries are single IPs ("127.0.0.1") or narrow CIDRs
	// ("127.0.0.1/32"); broad ranges such as 10.0.0.0/8 are refused, because
	// authorising a whole private network means an unintended DNS answer
	// anywhere inside it would still be accepted.
	//
	// Public addresses need no entry -- this list exists only to open a
	// deliberate, minimal hole for an isolated local testbed.
	//
	// Link-local (including the cloud metadata address 169.254.169.254),
	// multicast, unspecified and broadcast addresses can never be authorised
	// here: Validate refuses such an entry outright. See alwaysRefusedAddress
	// in dialer.go for the reasoning.
	AllowedAddresses []string `json:"allowed_addresses,omitempty"`
}

// Address-range width limits for AllowedAddresses. /24 is 256 addresses; that
// is the widest span we consider a deliberate, reviewable authorisation.
const (
	MinIPv4PrefixLen = 24
	MinIPv6PrefixLen = 120
)

// parseAllowedAddress accepts a bare IP or a CIDR and returns its canonical
// masked prefix.
func parseAllowedAddress(entry string) (netip.Prefix, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return netip.Prefix{}, fmt.Errorf("empty entry")
	}
	if !strings.Contains(entry, "/") {
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not an IP address", entry)
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a valid CIDR", entry)
	}
	if prefix.Addr().Is4In6() {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}

// AllowedPrefixes returns the parsed allowlist. Validate has already rejected
// unparsable entries, so parse failures here are skipped rather than returned.
func (t Target) AllowedPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(t.AllowedAddresses))
	for _, entry := range t.AllowedAddresses {
		if p, err := parseAllowedAddress(entry); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// Scope is the complete allowlist for a session.
type Scope struct {
	Targets []Target `json:"targets"`

	// MaxRedirects caps the redirect chain. Every hop is re-validated against
	// the allowlist regardless of this value.
	MaxRedirects int `json:"max_redirects"`
}

const defaultMaxRedirects = 3

// DefaultPort returns the conventional port for a scheme, or 0 if unknown.
func DefaultPort(scheme string) int {
	switch strings.ToLower(scheme) {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

// Normalize rewrites the scope into its canonical form: lowercase scheme and
// host, explicit port, cleaned and sorted path prefixes, uppercase and sorted
// methods, sorted targets. Normalising before hashing is what makes Digest
// stable across equivalent-but-differently-written configurations.
func (s *Scope) Normalize() {
	if s.MaxRedirects == 0 {
		s.MaxRedirects = defaultMaxRedirects
	}
	for i := range s.Targets {
		t := &s.Targets[i]
		t.Scheme = strings.ToLower(strings.TrimSpace(t.Scheme))
		t.Host = strings.ToLower(strings.TrimSpace(t.Host))
		t.Host = strings.TrimSuffix(t.Host, ".") // drop the FQDN root dot
		if t.Port == 0 {
			t.Port = DefaultPort(t.Scheme)
		}

		prefixes := make([]string, 0, len(t.PathPrefixes))
		seen := map[string]bool{}
		for _, p := range t.PathPrefixes {
			cp := cleanPrefix(p)
			if cp != "" && !seen[cp] {
				seen[cp] = true
				prefixes = append(prefixes, cp)
			}
		}
		sort.Strings(prefixes)
		t.PathPrefixes = prefixes

		methods := make([]string, 0, len(t.Methods))
		seenM := map[string]bool{}
		for _, m := range t.Methods {
			um := strings.ToUpper(strings.TrimSpace(m))
			if um != "" && !seenM[um] {
				seenM[um] = true
				methods = append(methods, um)
			}
		}
		sort.Strings(methods)
		t.Methods = methods

		// Canonicalise the address allowlist so that "127.0.0.1" and
		// "127.0.0.1/32" produce the same scope digest.
		addrs := make([]string, 0, len(t.AllowedAddresses))
		seenA := map[string]bool{}
		for _, entry := range t.AllowedAddresses {
			canonical := strings.TrimSpace(entry)
			if p, err := parseAllowedAddress(entry); err == nil {
				canonical = p.String()
			}
			if canonical != "" && !seenA[canonical] {
				seenA[canonical] = true
				addrs = append(addrs, canonical)
			}
		}
		sort.Strings(addrs)
		if len(addrs) == 0 {
			addrs = nil
		}
		t.AllowedAddresses = addrs
	}
	sort.Slice(s.Targets, func(i, j int) bool {
		a, b := s.Targets[i], s.Targets[j]
		if a.Scheme != b.Scheme {
			return a.Scheme < b.Scheme
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Port < b.Port
	})
}

// cleanPrefix normalises a path prefix to a rooted, trailing-slash-free form.
// "" and "/" both mean "the whole host", which we represent as "/".
func cleanPrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = path.Clean(p)
	return p
}

// Validate rejects configurations that cannot be enforced safely. The engine
// calls this before a session starts and refuses to run on error.
func (s *Scope) Validate() error {
	if len(s.Targets) == 0 {
		return fmt.Errorf("%w: scope must list at least one target", ErrInvalidConfig)
	}
	if s.MaxRedirects < 0 {
		return fmt.Errorf("%w: max_redirects must not be negative", ErrInvalidConfig)
	}
	for i, t := range s.Targets {
		switch t.Scheme {
		case "http", "https":
		default:
			return fmt.Errorf("%w: target %d has unsupported scheme %q (only http/https)", ErrInvalidConfig, i, t.Scheme)
		}
		if t.Host == "" {
			return fmt.Errorf("%w: target %d has an empty host", ErrInvalidConfig, i)
		}
		if strings.ContainsAny(t.Host, "*?") {
			return fmt.Errorf("%w: target %d host %q contains a wildcard; hosts must be exact", ErrInvalidConfig, i, t.Host)
		}
		if strings.Contains(t.Host, "/") || strings.Contains(t.Host, "@") {
			return fmt.Errorf("%w: target %d host %q must be a bare hostname or IP", ErrInvalidConfig, i, t.Host)
		}
		if t.Port < 1 || t.Port > 65535 {
			return fmt.Errorf("%w: target %d has invalid port %d", ErrInvalidConfig, i, t.Port)
		}
		if len(t.PathPrefixes) == 0 {
			return fmt.Errorf("%w: target %d must list at least one path prefix", ErrInvalidConfig, i)
		}
		if len(t.Methods) == 0 {
			return fmt.Errorf("%w: target %d must list at least one method", ErrInvalidConfig, i)
		}
		for _, entry := range t.AllowedAddresses {
			prefix, err := parseAllowedAddress(entry)
			if err != nil {
				return fmt.Errorf("%w: target %d allowed_addresses: %v", ErrInvalidConfig, i, err)
			}
			minBits := MinIPv4PrefixLen
			if prefix.Addr().Is6() {
				minBits = MinIPv6PrefixLen
			}
			if prefix.Bits() < minBits {
				return fmt.Errorf("%w: target %d allowed_addresses entry %s is too broad; "+
					"authorise specific addresses or a prefix of /%d or narrower",
					ErrInvalidConfig, i, prefix, minBits)
			}
			if neverAuthorisablePrefix(prefix) {
				return fmt.Errorf("%w: target %d allowed_addresses entry %s covers link-local, "+
					"multicast or unspecified addresses, which can never be authorised",
					ErrInvalidConfig, i, prefix)
			}
		}
	}
	return nil
}

// Digest is a stable fingerprint of the normalised scope. The authorisation
// acknowledgement is bound to this value, so acknowledging one scope and then
// running a different one is refused.
func (s *Scope) Digest() string {
	c := s.clone()
	c.Normalize()
	b, err := json.Marshal(c)
	if err != nil {
		// Scope contains only strings, ints and bools; Marshal cannot fail.
		panic("safety: scope digest: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// clone deep-copies the scope, including every slice inside a target.
//
// Digest normalises before hashing, and a shallow copy shares its Targets
// backing array with the original: normalising the copy rewrote the
// original's targets in place. That made Digest a mutating operation on a
// value callers reasonably treat as read-only, and two goroutines asking for
// the digest at once raced on it.
// Clone returns a deep copy. Callers that need to record or display a scope take
// a copy rather than a reference, so nothing they do afterwards can reach the
// scope an enforcing component is using.
func (s *Scope) Clone() Scope { return s.clone() }

func (s *Scope) clone() Scope {
	out := *s
	out.Targets = make([]Target, len(s.Targets))
	for i, t := range s.Targets {
		t.PathPrefixes = append([]string(nil), t.PathPrefixes...)
		t.Methods = append([]string(nil), t.Methods...)
		t.AllowedAddresses = append([]string(nil), t.AllowedAddresses...)
		out.Targets[i] = t
	}
	return out
}

// Authority returns the "host:port" form used to match dial addresses.
func (t Target) Authority() string {
	return net_JoinHostPort(t.Host, t.Port)
}

func net_JoinHostPort(host string, port int) string {
	if strings.Contains(host, ":") { // IPv6 literal
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// Check validates a method+URL against the allowlist and returns the matching
// target. It is called before every request and again after every redirect.
func (s *Scope) Check(method string, u *url.URL) (*Target, error) {
	if u == nil {
		return nil, fmt.Errorf("%w: nil url", ErrOutOfScope)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: credentials in the URL are not allowed", ErrOutOfScope)
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, fmt.Errorf("%w: url has no host", ErrOutOfScope)
	}

	port := DefaultPort(scheme)
	if ps := u.Port(); ps != "" {
		p, err := strconv.Atoi(ps)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("%w: invalid port %q", ErrOutOfScope, ps)
		}
		port = p
	}
	if port == 0 {
		return nil, fmt.Errorf("%w: unsupported scheme %q", ErrOutOfScope, u.Scheme)
	}

	reqMethod := strings.ToUpper(strings.TrimSpace(method))
	if reqMethod == "" {
		reqMethod = "GET"
	}
	reqPath := normalizeRequestPath(u)

	// Report the most specific refusal we can: host/port first, then method,
	// then path. This keeps operator-facing messages actionable.
	hostMatched := false
	methodMatched := false
	for i := range s.Targets {
		t := &s.Targets[i]
		if t.Scheme != scheme || t.Host != host || t.Port != port {
			continue
		}
		hostMatched = true
		if !containsString(t.Methods, reqMethod) {
			continue
		}
		methodMatched = true
		for _, prefix := range t.PathPrefixes {
			if pathHasPrefix(reqPath, prefix) {
				return t, nil
			}
		}
	}

	switch {
	case !hostMatched:
		return nil, fmt.Errorf("%w: %s://%s is not in the allowlist", ErrOutOfScope, scheme, net_JoinHostPort(host, port))
	case !methodMatched:
		return nil, fmt.Errorf("%w: method %s is not allowed for %s", ErrOutOfScope, reqMethod, host)
	default:
		return nil, fmt.Errorf("%w: path %s is not under an allowed prefix for %s", ErrOutOfScope, reqPath, host)
	}
}

// normalizeRequestPath resolves dot segments so that "/api/../admin" is checked
// as "/admin" rather than sneaking past a "/api" prefix. url.Parse has already
// percent-decoded u.Path, so "%2e%2e%2f" is handled here too.
func normalizeRequestPath(u *url.URL) string {
	p := u.Path
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

// pathHasPrefix matches on segment boundaries: prefix "/api" matches "/api" and
// "/api/users" but not "/apikeys".
func pathHasPrefix(p, prefix string) bool {
	if prefix == "/" {
		return true
	}
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// TargetForAuthority finds the target matching a dial address ("host:port").
// The dialer uses it to decide whether private addresses are permitted.
func (s *Scope) TargetForAuthority(authority string) (*Target, bool) {
	authority = strings.ToLower(authority)
	for i := range s.Targets {
		if s.Targets[i].Authority() == authority {
			return &s.Targets[i], true
		}
	}
	return nil, false
}
