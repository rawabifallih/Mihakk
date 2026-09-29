package safety

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Response is the capped, measured result of one guarded request.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Truncated  bool
	Latency    time.Duration
	FinalURL   string
	Accounting RequestAccounting
}

// RequestAccounting is the outcome of one Client.Do call. HTTP counts include
// every redirect hop. FinalResponseObserved says the chain reached a final
// response; an earlier redirect response alone does not set it.
type RequestAccounting struct {
	HTTPAnswered          int64
	HTTPUnanswered        int64
	HTTPRefused           int64
	FinalResponseObserved bool
}

// Attempted reports whether at least one HTTP round trip was attempted. A
// target-side connection refusal is an attempt; a safety refusal at connect is not.
func (a RequestAccounting) Attempted() bool {
	return a.HTTPAnswered+a.HTTPUnanswered > 0
}

type requestAccountingKey struct{}

type requestAccounting struct {
	answered, unanswered, refused atomic.Int64
}

func (a *requestAccounting) snapshot() RequestAccounting {
	return RequestAccounting{
		HTTPAnswered: a.answered.Load(), HTTPUnanswered: a.unanswered.Load(),
		HTTPRefused: a.refused.Load(),
	}
}

// ClientConfig assembles the guarded client. Every field that matters is
// mandatory: NewClient refuses to build a client without a valid scope, a
// valid authorisation acknowledgement and a governor, which is what makes the
// controls impossible to bypass from layers above.
type ClientConfig struct {
	Scope         *Scope
	Governor      *Governor
	Authorization *Authorization
	Redactor      *Redactor

	// Now and LookupIP exist for tests; both default to the real thing.
	Now      func() time.Time
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)

	// OnDial is forwarded to the dialer for audit logging.
	OnDial func(host, pinnedAddr string)

	// TLSRootCAs adds trust anchors for HTTPS targets, which a local testbed
	// with a self-signed certificate needs. Certificate verification itself is
	// never disabled: there is deliberately no insecure-skip-verify option.
	TLSRootCAs *x509.CertPool
}

// governedTransport meters every real HTTP round trip.
//
// The governor lives here rather than in Client.Do because redirect hops are
// issued by http.Client internally: metering in Do would let a 302 chain send
// N requests while consuming one unit of budget and one rate token. Each hop
// is also scope-checked here, at the last point before it is sent.
//
// The concurrency slot is held from the round trip until the response body is
// closed, and http.Client closes each intermediate body before issuing the
// next hop, so a redirect chain acquires and releases sequentially and cannot
// deadlock against max_concurrency.
type governedTransport struct {
	base     http.RoundTripper
	scope    *Scope
	gov      *Governor
	redactor *Redactor
}

func (t *governedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, err := t.scope.Check(req.Method, req.URL); err != nil {
		return nil, err
	}
	release, err := t.gov.Acquire(req.Context())
	if err != nil {
		return nil, err
	}
	// Every call that got this far is one HTTP request charged to the budget --
	// one per redirect hop -- and it ends in exactly one of three ways. Counted
	// here, and only counted: nothing below depends on the tally.
	resp, err := t.base.RoundTrip(req)
	perRequest, _ := req.Context().Value(requestAccountingKey{}).(*requestAccounting)
	switch {
	case err == nil:
		t.gov.hopAnswered.Add(1)
		if perRequest != nil {
			perRequest.answered.Add(1)
		}
	case errors.Is(err, ErrDisallowedAddress) || errors.Is(err, ErrAddressNotPinned) ||
		errors.Is(err, ErrOutOfScope):
		// The dialer refused the address: charged, never sent.
		t.gov.hopRefused.Add(1)
		if perRequest != nil {
			perRequest.refused.Add(1)
		}
	default:
		// Attempted, and no response came back: a refused connection, a reset,
		// a timeout. Whether any byte reached the target is not known.
		t.gov.hopUnanswered.Add(1)
		if perRequest != nil {
			perRequest.unanswered.Add(1)
		}
	}
	if err != nil {
		release()
		return nil, err
	}
	resp.Body = &releaseOnClose{ReadCloser: resp.Body, release: release}
	return resp, nil
}

// releaseOnClose returns the concurrency slot when the body is closed.
type releaseOnClose struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

func (r *releaseOnClose) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(r.release)
	return err
}

// Client is the only path from the engine to a target.
type Client struct {
	scope    *Scope
	gov      *Governor
	redactor *Redactor
	http     *http.Client
}

// NewClient validates the whole safety configuration and wires the transport.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Scope == nil {
		return nil, fmt.Errorf("%w: scope is required", ErrInvalidConfig)
	}
	if cfg.Governor == nil {
		return nil, fmt.Errorf("%w: governor is required", ErrInvalidConfig)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	// Cloned, not referenced. The caller keeps its own SessionConfig, and holding
	// its scope directly made what the dialer enforces mutable from outside: a
	// change to the caller's struct after this point changed the allowlist a live
	// run was being checked against. It also left "the scope that was enforced"
	// with no stable meaning, and so nothing that could be recorded or tested.
	cloned := cfg.Scope.Clone()
	scope := &cloned
	scope.Normalize()
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	// No session may start without a current, scope-bound acknowledgement.
	if err := cfg.Authorization.Validate(scope.Digest(), now()); err != nil {
		return nil, err
	}

	redactor := cfg.Redactor
	if redactor == nil {
		redactor = NewRedactor()
	}

	dialer := &GuardedDialer{
		Scope:          scope,
		LookupIP:       cfg.LookupIP,
		ConnectTimeout: cfg.Governor.Limits().RequestTimeout.Duration(),
		OnDial:         cfg.OnDial,
	}

	base := &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   cfg.Governor.Limits().RequestTimeout.Duration(),
		ResponseHeaderTimeout: cfg.Governor.Limits().RequestTimeout.Duration(),
		// Proxies are refused: a proxy would defeat address pinning by
		// resolving the destination itself.
		Proxy: nil,
	}
	if cfg.TLSRootCAs != nil {
		base.TLSClientConfig = &tls.Config{RootCAs: cfg.TLSRootCAs, MinVersion: tls.VersionTLS12}
	}

	c := &Client{scope: scope, gov: cfg.Governor, redactor: redactor}
	c.http = &http.Client{
		Transport: &governedTransport{base: base, scope: scope, gov: cfg.Governor, redactor: redactor},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > scope.MaxRedirects {
				return fmt.Errorf("%w: %d hops (max %d)", ErrTooManyRedirects, len(via), scope.MaxRedirects)
			}
			// Re-run the full check on every hop. A redirect is just another
			// destination and gets no benefit of the doubt.
			if _, err := scope.Check(req.Method, req.URL); err != nil {
				return fmt.Errorf("%w: %s", ErrRedirectOutOfScope, redactor.URL(req.URL))
			}
			return nil
		},
	}
	return c, nil
}

// Redactor exposes the configured redactor so callers log through it.
func (c *Client) Redactor() *Redactor { return c.redactor }

// Scope returns a copy of the scope this client enforces.
//
// This is the authoritative answer to "what was this run allowed to reach". The
// guarded client is the only way out of the engine, so anything that records or
// displays a scope -- the stored session, the audit log, the start response, a
// report -- derives it from here rather than from the configuration it was built
// out of. Those two can differ, and if they ever do, the one that governed the
// traffic is this one.
func (c *Client) Scope() Scope { return c.scope.Clone() }

// Do runs one request under every session control: scope check, rate limit,
// concurrency slot, total budget, per-request timeout, kill switch, capped
// response body.
func (c *Client) Do(ctx context.Context, req *http.Request) (*Response, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", ErrInvalidConfig)
	}
	// Pre-flight scope check, before any resource is consumed.
	if _, err := c.scope.Check(req.Method, req.URL); err != nil {
		return nil, err
	}

	// Resource accounting happens per round trip inside governedTransport, so
	// that every redirect hop is charged. The whole chain shares one deadline.
	base, stopBase := mergeDone(c.gov.Context(), ctx)
	defer stopBase()
	reqCtx, cancel := context.WithTimeout(base, c.gov.Limits().RequestTimeout.Duration())
	defer cancel()
	perRequest := &requestAccounting{}
	reqCtx = context.WithValue(reqCtx, requestAccountingKey{}, perRequest)

	start := time.Now()
	resp, err := c.http.Do(req.WithContext(reqCtx))
	if err != nil {
		accounting := perRequest.snapshot()
		if cause := c.gov.StopCause(); cause != nil {
			return &Response{Accounting: accounting}, cause
		}
		return &Response{Accounting: accounting}, err
	}
	defer resp.Body.Close()

	body, truncated, readErr := ReadCapped(resp.Body, c.gov.Limits().MaxResponseBytes)
	latency := time.Since(start)
	accounting := perRequest.snapshot()
	accounting.FinalResponseObserved = true
	if readErr != nil {
		return &Response{StatusCode: resp.StatusCode, Header: resp.Header,
			Latency: latency, FinalURL: resp.Request.URL.String(), Accounting: accounting}, readErr
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
		Truncated:  truncated,
		Latency:    latency,
		FinalURL:   resp.Request.URL.String(),
		Accounting: accounting,
	}, nil
}
