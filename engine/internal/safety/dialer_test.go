package safety

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestIsRestrictedAddress(t *testing.T) {
	restricted := []string{
		"127.0.0.1", "127.0.0.53", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.255",
		"192.168.1.1", "169.254.169.254", "100.64.0.1", "224.0.0.1", "255.255.255.255",
		"::1", "::", "fe80::1", "fc00::1", "fd12::34", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
	}
	for _, s := range restricted {
		if !IsRestrictedAddress(net.ParseIP(s)) {
			t.Errorf("IsRestrictedAddress(%s) = false, want true", s)
		}
	}
	public := []string{"8.8.8.8", "203.0.113.10", "172.32.0.1", "172.15.255.255", "2001:4860:4860::8888"}
	for _, s := range public {
		if IsRestrictedAddress(net.ParseIP(s)) {
			t.Errorf("IsRestrictedAddress(%s) = true, want false", s)
		}
	}
	if !IsRestrictedAddress(nil) {
		t.Error("IsRestrictedAddress(nil) = false, want true")
	}
}

// listenerPort starts a loopback TCP listener that accepts and immediately
// closes connections, and returns it with its port.
func listenerPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// scopeWithHost builds a single-target scope. allowed lists the restricted
// addresses the target may resolve to; nil means "public addresses only".
func scopeWithHost(host string, port int, allowed ...string) *Scope {
	s := &Scope{Targets: []Target{{
		Scheme: "http", Host: host, Port: port,
		PathPrefixes: []string{"/"}, Methods: []string{"GET"},
		AllowedAddresses: allowed,
	}}}
	s.Normalize()
	return s
}

func TestDialRefusesAddressOutsideScope(t *testing.T) {
	d := &GuardedDialer{Scope: scopeWithHost("app.local", 8080, "127.0.0.1/32")}
	_, err := d.DialContext(context.Background(), "tcp", "other.local:8080")
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("DialContext() = %v, want ErrOutOfScope", err)
	}
}

func TestDialRefusesRestrictedResolutionByDefault(t *testing.T) {
	// app.local resolves into loopback but the target did not opt in.
	d := &GuardedDialer{
		Scope: scopeWithHost("app.local", 8080),
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", "app.local:8080")
	if !errors.Is(err, ErrDisallowedAddress) {
		t.Fatalf("DialContext() = %v, want ErrDisallowedAddress", err)
	}
}

func TestDialRefusesLinkLocalMetadataAddress(t *testing.T) {
	d := &GuardedDialer{
		Scope: scopeWithHost("app.local", 80),
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", "app.local:80")
	if !errors.Is(err, ErrDisallowedAddress) {
		t.Fatalf("DialContext() = %v, want ErrDisallowedAddress", err)
	}
}

// TestDialResolvesOnceAndPinsAddress is the DNS-rebinding defence: the host is
// resolved a single time, and the connection is made to that validated address
// literal. A resolver that changes its answer after the check cannot influence
// where the socket actually connects, because it is never consulted again.
func TestDialResolvesOnceAndPinsAddress(t *testing.T) {
	ln, port := listenerPort(t)
	defer ln.Close()

	var lookups atomic.Int32
	d := &GuardedDialer{
		Scope: scopeWithHost("app.local", port, "127.0.0.1/32"),
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			n := lookups.Add(1)
			if n == 1 {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			// A rebinding resolver would hand out a different address here.
			return []net.IP{net.ParseIP("10.99.99.99")}, nil
		},
	}

	conn, err := d.DialContext(context.Background(), "tcp", "app.local:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("DialContext() = %v", err)
	}
	defer conn.Close()

	if got := lookups.Load(); got != 1 {
		t.Fatalf("resolver consulted %d times, want exactly 1 (a second lookup reopens the rebinding window)", got)
	}
	remote := conn.RemoteAddr().(*net.TCPAddr)
	if !remote.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("connected to %s, want the validated address 127.0.0.1", remote.IP)
	}
}

// TestDialPinnedRejectsMismatchedSocketAddress covers the Control backstop:
// even if something handed the dialer a different address than the validated
// one, the connect is aborted before the syscall.
func TestDialPinnedRejectsMismatchedSocketAddress(t *testing.T) {
	ln, port := listenerPort(t)
	defer ln.Close()

	d := &GuardedDialer{Scope: scopeWithHost("app.local", port, "127.0.0.1/32")}
	// Dial 127.0.0.1 while claiming 127.0.0.2 was the validated address.
	_, err := d.dialPinned(context.Background(), "tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), net.ParseIP("127.0.0.2"), port)
	if !errors.Is(err, ErrAddressNotPinned) {
		t.Fatalf("dialPinned() = %v, want ErrAddressNotPinned", err)
	}
}

func TestDialAllowsLoopbackWhenTargetOptsIn(t *testing.T) {
	ln, port := listenerPort(t)
	defer ln.Close()

	d := &GuardedDialer{Scope: scopeWithHost("127.0.0.1", port, "127.0.0.1/32")}
	conn, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("DialContext() = %v, want success for an opted-in testbed target", err)
	}
	conn.Close()
}

func TestDialRefusesEmptyResolution(t *testing.T) {
	d := &GuardedDialer{
		Scope:    scopeWithHost("app.local", 80, "127.0.0.1/32"),
		LookupIP: func(context.Context, string) ([]net.IP, error) { return nil, nil },
	}
	_, err := d.DialContext(context.Background(), "tcp", "app.local:80")
	if !errors.Is(err, ErrDisallowedAddress) {
		t.Fatalf("DialContext() = %v, want ErrDisallowedAddress", err)
	}
}
