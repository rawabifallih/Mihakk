package safety

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// IsRestrictedAddress reports whether an IP belongs to a range Mihakk refuses
// to reach unless a specific AllowedAddresses entry authorises it.
//
// The point is not that these ranges are "bad", but that a hostname the
// operator authorised must not be able to steer the engine into loopback,
// link-local or internal networks -- whether by misconfiguration or by a DNS
// answer that changes between the check and the connect.
func IsRestrictedAddress(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Treat IPv4-mapped IPv6 (::ffff:127.0.0.1) as its IPv4 form.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}

	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0: // 0.0.0.0/8 "this network"
			return true
		case v4[0] == 10: // 10.0.0.0/8
			return true
		case v4[0] == 127: // 127.0.0.0/8 (also caught by IsLoopback)
			return true
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64.0.0/10 CGNAT
			return true
		case v4[0] == 169 && v4[1] == 254: // 169.254.0.0/16
			return true
		case v4[0] == 172 && v4[1]&0xf0 == 16: // 172.16.0.0/12
			return true
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24
			return true
		case v4[0] == 192 && v4[1] == 168: // 192.168.0.0/16
			return true
		case v4[0] == 198 && v4[1]&0xfe == 18: // 198.18.0.0/15 benchmarking
			return true
		case v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255:
			return true
		}
		return false
	}

	// IPv6 unique-local fc00::/7.
	if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
		return true
	}
	return false
}

// alwaysRefusedAddress marks the ranges that NO configuration may authorise,
// however narrow or explicit the entry:
//
//   - link-local IPv4 169.254.0.0/16 and IPv6 fe80::/10, which include the
//     cloud metadata endpoint 169.254.169.254
//   - multicast, including interface-local multicast
//   - the unspecified address (0.0.0.0, ::)
//   - the IPv4 broadcast address 255.255.255.255
//
// Rationale: no legitimate web target lives in these ranges, while the
// metadata endpoint hands out cloud credentials to anything that reaches it.
// Making it allowlistable would turn a single configuration mistake into
// credential exposure -- a bad trade for flexibility nobody needs.
//
// This is enforced in two independent places, so neither alone is load-bearing:
// Scope.Validate refuses a config that lists any of these in allowed_addresses
// (the session never starts), and Target.AuthorisesAddress refuses them again
// at dial time. Accepted as an MVP constraint: a target on a link-local
// address cannot be tested; give it a loopback or narrow private address
// instead. See README.md, "قيد مقصود: نطاقات محظورة لا يمكن تصريحها إطلاقًا".
func alwaysRefusedAddress(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255 {
		return true
	}
	return false
}

// neverAuthorisablePrefix reports whether a prefix overlaps a range that can
// never be authorised. Both the network and broadcast ends are checked so a
// prefix cannot straddle its way into a forbidden range.
func neverAuthorisablePrefix(p netip.Prefix) bool {
	if !p.IsValid() {
		return true
	}
	lo := p.Masked().Addr()
	if alwaysRefusedAddress(net.IP(lo.AsSlice())) {
		return true
	}
	hi := lastAddrInPrefix(p)
	return alwaysRefusedAddress(net.IP(hi.AsSlice()))
}

func lastAddrInPrefix(p netip.Prefix) netip.Addr {
	addr := p.Masked().Addr()
	bytes := addr.AsSlice()
	hostBits := addr.BitLen() - p.Bits()
	for i := len(bytes) - 1; i >= 0 && hostBits > 0; i-- {
		n := hostBits
		if n > 8 {
			n = 8
		}
		bytes[i] |= byte(0xff >> (8 - n))
		hostBits -= n
	}
	out, _ := netip.AddrFromSlice(bytes)
	return out
}

// AuthorisesAddress reports whether this target may connect to ip.
//
// Three tiers, in order:
//  1. Always-refused ranges (see alwaysRefusedAddress) are rejected outright;
//     no AllowedAddresses entry can override this.
//  2. Public addresses are accepted -- the hostname allowlist already bounds
//     the target, so they need no entry.
//  3. Other restricted addresses (loopback, private, CGNAT) are accepted only
//     when an explicit AllowedAddresses entry covers that exact address, so a
//     hostname that resolves to some *other* address inside an authorised
//     private network is still refused.
func (t Target) AuthorisesAddress(ip net.IP) error {
	if alwaysRefusedAddress(ip) {
		return fmt.Errorf("%s is link-local, multicast or unspecified and can never be authorised", ip)
	}
	if !IsRestrictedAddress(ip) {
		return nil
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("%s is not a usable address", ip)
	}
	addr = addr.Unmap()
	for _, prefix := range t.AllowedPrefixes() {
		if prefix.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("%s is a restricted address and no allowed_addresses entry covers it", ip)
}

// GuardedDialer opens connections only to addresses that passed validation.
//
// DNS-rebinding defence: the host is resolved once, every returned address is
// validated, and the connection is then made to the chosen address *literal*.
// Because no hostname reaches the kernel, there is no second resolution that
// could return a different address after the check. The Control hook is a
// backstop that re-checks the address the socket is actually connecting to.
type GuardedDialer struct {
	Scope *Scope

	// LookupIP resolves a hostname. Injectable so tests can drive resolution
	// (including a rebinding scenario) without touching real DNS.
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)

	// ConnectTimeout bounds a single TCP connect attempt.
	ConnectTimeout time.Duration

	// OnDial, when set, is called with the host and the pinned address for
	// audit logging.
	OnDial func(host, pinnedAddr string)
}

func (d *GuardedDialer) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if d.LookupIP != nil {
		return d.LookupIP(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// DialContext is installed as the transport's dialer. addr arrives as
// "host:port" from the HTTP transport.
func (d *GuardedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.Scope == nil {
		return nil, fmt.Errorf("%w: dialer has no scope", ErrInvalidConfig)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot parse dial address %q", ErrOutOfScope, addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot parse dial port %q", ErrOutOfScope, portStr)
	}

	// Re-check at the socket layer. The URL was already validated, but this is
	// the last place before bytes leave the process, so it does not trust that.
	target, ok := d.Scope.TargetForAuthority(net_JoinHostPort(host, port))
	if !ok {
		return nil, fmt.Errorf("%w: dial to %s is not in the allowlist", ErrOutOfScope, addr)
	}

	var candidates []net.IP
	if ip := net.ParseIP(host); ip != nil {
		candidates = []net.IP{ip}
	} else {
		resolved, err := d.lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("mihakk: resolving %s: %w", host, err)
		}
		candidates = resolved
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: %s resolved to no addresses", ErrDisallowedAddress, host)
	}

	allowed := make([]net.IP, 0, len(candidates))
	refusals := make([]string, 0, len(candidates))
	for _, ip := range candidates {
		if err := target.AuthorisesAddress(ip); err != nil {
			refusals = append(refusals, err.Error())
			continue
		}
		allowed = append(allowed, ip)
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: %s resolved to no authorised address: %s",
			ErrDisallowedAddress, host, strings.Join(refusals, "; "))
	}

	var lastErr error
	for _, ip := range allowed {
		pinned := net.JoinHostPort(ip.String(), portStr)
		conn, err := d.dialPinned(ctx, network, pinned, ip, port)
		if err != nil {
			lastErr = err
			continue
		}
		if d.OnDial != nil {
			d.OnDial(host, pinned)
		}
		return conn, nil
	}
	return nil, lastErr
}

// dialPinned connects to a single validated address literal.
func (d *GuardedDialer) dialPinned(ctx context.Context, network, pinned string, ip net.IP, port int) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: d.ConnectTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			// Backstop: the address the socket is about to use must be the one
			// we validated. Any divergence aborts before the connect syscall.
			ahost, aport, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: unparsable socket address %q", ErrAddressNotPinned, address)
			}
			aip := net.ParseIP(ahost)
			if aip == nil || !aip.Equal(ip) || aport != strconv.Itoa(port) {
				return fmt.Errorf("%w: expected %s, socket used %s",
					ErrAddressNotPinned, net.JoinHostPort(ip.String(), strconv.Itoa(port)), address)
			}
			return nil
		},
	}
	return dialer.DialContext(ctx, network, pinned)
}
