package safety

import (
	"errors"
	"testing"
	"time"
)

func TestAuthorizationRequiredBeforeAnySession(t *testing.T) {
	var a *Authorization
	if err := a.Validate("sha256:abc", time.Now()); !errors.Is(err, ErrNoAuthorization) {
		t.Fatalf("nil ack = %v, want ErrNoAuthorization", err)
	}
}

func TestAuthorizationRejectsIncompleteAcks(t *testing.T) {
	now := time.Now()
	digest := "sha256:abc"
	good := Authorization{
		Operator:    "rawabi",
		Statement:   RequiredStatement,
		AckedAt:     now.Add(-time.Minute),
		ScopeDigest: digest,
	}
	if err := good.Validate(digest, now); err != nil {
		t.Fatalf("valid ack rejected: %v", err)
	}

	cases := map[string]func(*Authorization){
		"empty operator":    func(a *Authorization) { a.Operator = "  " },
		"wrong statement":   func(a *Authorization) { a.Statement = "yes I agree" },
		"boolean-ish":       func(a *Authorization) { a.Statement = "true" },
		"missing timestamp": func(a *Authorization) { a.AckedAt = time.Time{} },
		"future timestamp":  func(a *Authorization) { a.AckedAt = now.Add(time.Hour) },
		"expired":           func(a *Authorization) { a.AckedAt = now.Add(-MaxAckAge - time.Minute) },
		"no scope digest":   func(a *Authorization) { a.ScopeDigest = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := good
			mutate(&a)
			if err := a.Validate(digest, now); !errors.Is(err, ErrAuthorizationInvalid) {
				t.Fatalf("Validate() = %v, want ErrAuthorizationInvalid", err)
			}
		})
	}
}

// An acknowledgement is bound to one exact scope, so an ack collected for a
// narrow scope cannot be replayed against a wider one.
func TestAuthorizationIsBoundToScope(t *testing.T) {
	now := time.Now()
	narrow := Scope{Targets: []Target{{
		Scheme: "http", Host: "app.local", Port: 8080,
		PathPrefixes: []string{"/api"}, Methods: []string{"GET"},
	}}}
	wide := Scope{Targets: []Target{{
		Scheme: "http", Host: "app.local", Port: 8080,
		PathPrefixes: []string{"/"}, Methods: []string{"GET", "POST", "DELETE"},
	}}}
	narrow.Normalize()
	wide.Normalize()

	ack := Authorization{
		Operator:    "rawabi",
		Statement:   RequiredStatement,
		AckedAt:     now,
		ScopeDigest: narrow.Digest(),
	}
	if err := ack.Validate(narrow.Digest(), now); err != nil {
		t.Fatalf("ack against its own scope = %v", err)
	}
	if err := ack.Validate(wide.Digest(), now); !errors.Is(err, ErrAuthorizationScopeMismatch) {
		t.Fatalf("ack replayed against a wider scope = %v, want ErrAuthorizationScopeMismatch", err)
	}
}

func TestAuthorizationToleratesSmallClockSkew(t *testing.T) {
	now := time.Now()
	a := Authorization{
		Operator:    "rawabi",
		Statement:   RequiredStatement,
		AckedAt:     now.Add(30 * time.Second), // operator clock slightly ahead
		ScopeDigest: "sha256:abc",
	}
	if err := a.Validate("sha256:abc", now); err != nil {
		t.Fatalf("small clock skew rejected: %v", err)
	}
}
