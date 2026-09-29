package safety

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Restricted addresses are authorised one at a time. A hostname that resolves
// somewhere else inside the same private network is still refused -- which is
// the failure mode a broad "allow private addresses" switch would have missed.
func TestUnauthorisedPrivateAddressIsRefusedEvenWithinAnAllowedNetwork(t *testing.T) {
	cases := []struct {
		name     string
		allowed  []string
		resolved string
	}{
		{"different host in the same /8", []string{"10.1.2.3/32"}, "10.9.9.9"},
		{"different host in the same /24", []string{"192.168.1.10/32"}, "192.168.1.11"},
		{"loopback when only one private host is allowed", []string{"10.1.2.3/32"}, "127.0.0.1"},
		{"private when only loopback is allowed", []string{"127.0.0.1/32"}, "10.0.0.5"},
		{"nothing allowed at all", nil, "127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &GuardedDialer{
				Scope: scopeWithHost("app.local", 8080, tc.allowed...),
				LookupIP: func(context.Context, string) ([]net.IP, error) {
					return []net.IP{net.ParseIP(tc.resolved)}, nil
				},
			}
			_, err := d.DialContext(context.Background(), "tcp", "app.local:8080")
			if !errors.Is(err, ErrDisallowedAddress) {
				t.Fatalf("dial to %s = %v, want ErrDisallowedAddress", tc.resolved, err)
			}
		})
	}
}

// A DNS answer that flips to an unauthorised address between sessions must be
// refused, including the cloud metadata endpoint.
func TestDNSChangeToUnauthorisedAddressIsRefused(t *testing.T) {
	hostile := []string{
		"169.254.169.254",        // cloud metadata
		"169.254.1.1",            // link-local generally
		"127.0.0.1",              // loopback
		"10.0.0.1",               // private
		"192.168.0.1",            // private
		"172.16.0.1",             // private
		"100.64.0.1",             // CGNAT
		"0.0.0.0",                // unspecified
		"::1",                    // IPv6 loopback
		"fe80::1",                // IPv6 link-local
		"fd00::1",                // IPv6 unique-local
		"::ffff:169.254.169.254", // metadata smuggled as IPv4-mapped IPv6
	}
	for _, addr := range hostile {
		t.Run(addr, func(t *testing.T) {
			// The target authorises only the testbed's loopback address.
			d := &GuardedDialer{
				Scope: scopeWithHost("app.local", 8080, "127.0.0.2/32"),
				LookupIP: func(context.Context, string) ([]net.IP, error) {
					return []net.IP{net.ParseIP(addr)}, nil
				},
			}
			_, err := d.DialContext(context.Background(), "tcp", "app.local:8080")
			if !errors.Is(err, ErrDisallowedAddress) {
				t.Fatalf("dial after DNS change to %s = %v, want ErrDisallowedAddress", addr, err)
			}
		})
	}
}

// Link-local can never be authorised, even by an explicit, narrow entry.
func TestLinkLocalCannotBeAuthorisedAtAll(t *testing.T) {
	for _, entry := range []string{"169.254.169.254/32", "169.254.0.0/24", "fe80::1/128"} {
		t.Run(entry, func(t *testing.T) {
			s := &Scope{Targets: []Target{{
				Scheme: "http", Host: "app.local", Port: 80,
				PathPrefixes: []string{"/"}, Methods: []string{"GET"},
				AllowedAddresses: []string{entry},
			}}}
			s.Normalize()
			if err := s.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate() with %s = %v, want ErrInvalidConfig", entry, err)
			}
		})
	}

	// And the dial-time check refuses it independently of config validation.
	target := Target{AllowedAddresses: []string{"169.254.169.254/32"}}
	if err := target.AuthorisesAddress(net.ParseIP("169.254.169.254")); err == nil {
		t.Fatal("AuthorisesAddress(169.254.169.254) = nil, want a refusal")
	}
}

// Broad private ranges are refused as configuration: authorising a whole
// network re-opens exactly the hole the explicit list is meant to close.
func TestBroadAddressRangesAreRefusedAsConfiguration(t *testing.T) {
	tooBroad := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "0.0.0.0/0", "127.0.0.0/8", "fd00::/8"}
	for _, entry := range tooBroad {
		t.Run(entry, func(t *testing.T) {
			s := &Scope{Targets: []Target{{
				Scheme: "http", Host: "app.local", Port: 80,
				PathPrefixes: []string{"/"}, Methods: []string{"GET"},
				AllowedAddresses: []string{entry},
			}}}
			s.Normalize()
			err := s.Validate()
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate() with %s = %v, want ErrInvalidConfig", entry, err)
			}
			if !strings.Contains(err.Error(), "too broad") && !strings.Contains(err.Error(), "never be authorised") {
				t.Fatalf("error message %q does not explain why the range was refused", err)
			}
		})
	}

	narrowEnough := []string{"127.0.0.1", "127.0.0.1/32", "10.1.2.0/24", "192.168.5.64/26", "fd00::1/128"}
	for _, entry := range narrowEnough {
		t.Run("accepted/"+entry, func(t *testing.T) {
			s := &Scope{Targets: []Target{{
				Scheme: "http", Host: "app.local", Port: 80,
				PathPrefixes: []string{"/"}, Methods: []string{"GET"},
				AllowedAddresses: []string{entry},
			}}}
			s.Normalize()
			if err := s.Validate(); err != nil {
				t.Fatalf("Validate() with %s = %v, want it accepted", entry, err)
			}
		})
	}
}

func TestAllowedAddressesRejectsUnparsableEntries(t *testing.T) {
	for _, entry := range []string{"not-an-ip", "300.1.1.1", "10.0.0.1/33", "example.com"} {
		s := &Scope{Targets: []Target{{
			Scheme: "http", Host: "app.local", Port: 80,
			PathPrefixes: []string{"/"}, Methods: []string{"GET"},
			AllowedAddresses: []string{entry},
		}}}
		s.Normalize()
		if err := s.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Validate() with %q = %v, want ErrInvalidConfig", entry, err)
		}
	}
}

// The authorised-address list is part of the scope digest, so widening it
// invalidates the operator's acknowledgement and the engine refuses the config.
func TestEditingAllowedAddressesInvalidatesTheAcknowledgement(t *testing.T) {
	now := timeNow()
	original := Scope{Targets: []Target{{
		Scheme: "http", Host: "testbed", Port: 8000,
		PathPrefixes: []string{"/api"}, Methods: []string{"GET"},
		AllowedAddresses: []string{"127.0.0.1/32"},
	}}}
	original.Normalize()

	ack := &Authorization{
		Operator: "rawabi", Statement: RequiredStatement,
		AckedAt: now, ScopeDigest: original.Digest(),
	}

	cfg := SessionConfig{ConfigVersion: ConfigVersion, Scope: original, Limits: DefaultLimits(), Authorization: ack}
	if err := cfg.Prepare(now); err != nil {
		t.Fatalf("original config refused: %v", err)
	}

	// Someone edits the address allowlist without re-acknowledging.
	for _, edit := range [][]string{
		{"127.0.0.1/32", "10.1.2.3/32"}, // widened
		{"10.1.2.3/32"},                 // swapped
		nil,                             // removed
	} {
		edited := Scope{Targets: []Target{{
			Scheme: "http", Host: "testbed", Port: 8000,
			PathPrefixes: []string{"/api"}, Methods: []string{"GET"},
			AllowedAddresses: edit,
		}}}
		edited.Normalize()

		if edited.Digest() == original.Digest() {
			t.Fatalf("editing allowed_addresses to %v did not change the scope digest", edit)
		}
		tampered := SessionConfig{
			ConfigVersion: ConfigVersion, Scope: edited,
			Limits: DefaultLimits(), Authorization: ack,
		}
		if err := tampered.Prepare(now); !errors.Is(err, ErrAuthorizationScopeMismatch) {
			t.Fatalf("Prepare() after editing to %v = %v, want ErrAuthorizationScopeMismatch", edit, err)
		}
	}
}

// Equivalent spellings must not change the digest, or every reformat would
// force a re-acknowledgement for no reason.
func TestAllowedAddressesDigestIsSpellingStable(t *testing.T) {
	a := Scope{Targets: []Target{{
		Scheme: "http", Host: "testbed", Port: 8000,
		PathPrefixes: []string{"/api"}, Methods: []string{"GET"},
		AllowedAddresses: []string{"127.0.0.1", "10.1.2.0/24"},
	}}}
	b := Scope{Targets: []Target{{
		Scheme: "http", Host: "testbed", Port: 8000,
		PathPrefixes: []string{"/api"}, Methods: []string{"GET"},
		AllowedAddresses: []string{"10.1.2.0/24", "127.0.0.1/32", "127.0.0.1"},
	}}}
	if a.Digest() != b.Digest() {
		t.Fatalf("equivalent address lists produced different digests:\n a=%s\n b=%s", a.Digest(), b.Digest())
	}
}

func TestAuthorisedAddressIsDialable(t *testing.T) {
	ln, port := listenerPort(t)
	defer ln.Close()

	d := &GuardedDialer{
		Scope: scopeWithHost("app.local", port, "127.0.0.1/32"),
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	}
	conn, err := d.DialContext(context.Background(), "tcp", "app.local:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("dial to an explicitly authorised address = %v, want success", err)
	}
	conn.Close()
}

// Public addresses need no entry: the hostname allowlist already bounds them.
func TestPublicAddressNeedsNoEntry(t *testing.T) {
	target := Target{}
	if err := target.AuthorisesAddress(net.ParseIP("203.0.113.10")); err != nil {
		t.Fatalf("AuthorisesAddress(public) = %v, want nil", err)
	}
}

// timeNow is a tiny indirection so this file does not import time twice for
// one call site.
func timeNow() time.Time { return time.Now() }
