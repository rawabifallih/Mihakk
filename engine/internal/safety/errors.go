// Package safety implements the controls that make Mihakk usable only against
// targets the operator is authorised to test.
//
// Every control in this package is enforced inside the engine, on the path that
// actually opens sockets. Nothing above this layer (CLI, control API, dashboard)
// can opt out of it: the guarded client is the only way the engine reaches a
// target, and it refuses to build without an in-scope target, a validated
// authorisation acknowledgement, and an active governor.
package safety

import "errors"

// Refusals. Callers match on these to report precisely why a request was
// refused; the messages are safe to surface to operators and to logs because
// they never embed credentials.
var (
	// ErrOutOfScope means the destination is not covered by the allowlist.
	ErrOutOfScope = errors.New("mihakk: destination is outside the authorised scope")

	// ErrRedirectOutOfScope means a redirect tried to leave the allowlist.
	ErrRedirectOutOfScope = errors.New("mihakk: redirect target is outside the authorised scope")

	// ErrTooManyRedirects means the redirect chain exceeded the configured cap.
	ErrTooManyRedirects = errors.New("mihakk: too many redirects")

	// ErrDisallowedAddress means the host resolved to an address the scope does
	// not permit (loopback, private, link-local, ... unless explicitly allowed).
	ErrDisallowedAddress = errors.New("mihakk: host resolved to a disallowed address")

	// ErrAddressNotPinned means the socket connected to an address other than
	// the one validated for this dial. This is the DNS-rebinding backstop.
	ErrAddressNotPinned = errors.New("mihakk: connection address does not match the validated address")

	// ErrNoAuthorization means no authorisation acknowledgement was supplied.
	ErrNoAuthorization = errors.New("mihakk: authorisation acknowledgement is required before any session starts")

	// ErrAuthorizationInvalid means the acknowledgement was supplied but does
	// not satisfy the required form (wrong statement, expired, wrong operator).
	ErrAuthorizationInvalid = errors.New("mihakk: authorisation acknowledgement is not valid")

	// ErrAuthorizationScopeMismatch means the operator acknowledged a different
	// scope than the one about to run. Acks are bound to an exact scope.
	ErrAuthorizationScopeMismatch = errors.New("mihakk: authorisation acknowledgement does not match the configured scope")

	// ErrBudgetExhausted means the session hit its total request budget.
	ErrBudgetExhausted = errors.New("mihakk: total request budget exhausted")

	// ErrSessionStopped means the session was stopped (kill switch or deadline).
	ErrSessionStopped = errors.New("mihakk: session stopped")

	// ErrSessionExpired means the session exceeded its maximum duration.
	ErrSessionExpired = errors.New("mihakk: session exceeded its maximum duration")

	// ErrInvalidConfig means the supplied scope/limits/authorisation are not a
	// usable configuration. The engine refuses to start rather than guessing.
	ErrInvalidConfig = errors.New("mihakk: invalid safety configuration")
)
