package safety

import (
	"fmt"
	"strings"
	"time"
)

// RequiredStatement is the exact text an operator must supply to start a
// session. It is a fixed string rather than a boolean so that acknowledging
// authorisation is a deliberate act that appears verbatim in the audit log.
// The dashboard shows the Arabic rendering next to it; the machine-checked
// value is this constant.
const RequiredStatement = "I am authorised to test the targets listed in this scope."

// MaxAckAge forces a fresh acknowledgement for long-lived deployments: an ack
// recorded yesterday cannot silently authorise today's session.
const MaxAckAge = 24 * time.Hour

// allowedClockSkew tolerates a small clock difference between the operator's
// machine and the engine.
const allowedClockSkew = 2 * time.Minute

// Authorization records who accepted responsibility for a session, when, and
// for exactly which scope. It is bound to Scope.Digest, so an ack collected for
// one allowlist cannot be replayed against a different one.
type Authorization struct {
	Operator    string    `json:"operator"`
	Statement   string    `json:"statement"`
	AckedAt     time.Time `json:"acked_at"`
	ScopeDigest string    `json:"scope_digest"`
}

// Validate refuses anything short of a complete, current, scope-bound ack.
// The engine calls this before a session starts and again before a reproduce.
func (a *Authorization) Validate(scopeDigest string, now time.Time) error {
	if a == nil {
		return ErrNoAuthorization
	}
	if strings.TrimSpace(a.Operator) == "" {
		return fmt.Errorf("%w: operator is required", ErrAuthorizationInvalid)
	}
	if a.Statement != RequiredStatement {
		return fmt.Errorf("%w: statement must be exactly %q", ErrAuthorizationInvalid, RequiredStatement)
	}
	if a.AckedAt.IsZero() {
		return fmt.Errorf("%w: acked_at is required", ErrAuthorizationInvalid)
	}
	if a.AckedAt.After(now.Add(allowedClockSkew)) {
		return fmt.Errorf("%w: acked_at is in the future", ErrAuthorizationInvalid)
	}
	if now.Sub(a.AckedAt) > MaxAckAge {
		return fmt.Errorf("%w: acknowledgement is older than %s; re-confirm authorisation",
			ErrAuthorizationInvalid, MaxAckAge)
	}
	if strings.TrimSpace(a.ScopeDigest) == "" {
		return fmt.Errorf("%w: scope_digest is required", ErrAuthorizationInvalid)
	}
	if a.ScopeDigest != scopeDigest {
		return fmt.Errorf("%w: acknowledged %s but the configured scope is %s",
			ErrAuthorizationScopeMismatch, a.ScopeDigest, scopeDigest)
	}
	return nil
}
