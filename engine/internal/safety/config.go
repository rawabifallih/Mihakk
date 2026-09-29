package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ConfigVersion is bumped when the shape of SessionConfig changes in a way
// that affects reproduction. It is part of the reproduction recipe recorded
// with every saved case.
const ConfigVersion = "1"

// SessionConfig is the safety half of a session definition and the contract
// shared with the Python orchestrator. Mutation and target settings are added
// alongside it in later phases; this struct owns only what must be validated
// before the engine is allowed to send anything.
type SessionConfig struct {
	ConfigVersion string         `json:"config_version"`
	Scope         Scope          `json:"scope"`
	Limits        Limits         `json:"limits"`
	Authorization *Authorization `json:"authorization"`

	// RedactExtraNames adds deployment-specific header or field names to the
	// built-in redaction list.
	RedactExtraNames []string `json:"redact_extra_names,omitempty"`
}

// LoadSessionConfig reads and prepares a config file, refusing anything that
// would not be safe to run.
func LoadSessionConfig(path string, now time.Time) (*SessionConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mihakk: reading config: %w", err)
	}
	var cfg SessionConfig
	dec := json.NewDecoder(newTrimReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: parsing config: %v", ErrInvalidConfig, err)
	}
	if err := cfg.Prepare(now); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Prepare normalises then validates the whole configuration. It is the single
// gate every entry point (CLI, control API) must pass through.
func (c *SessionConfig) Prepare(now time.Time) error {
	if c.ConfigVersion == "" {
		c.ConfigVersion = ConfigVersion
	}
	if c.ConfigVersion != ConfigVersion {
		return fmt.Errorf("%w: unsupported config_version %q (expected %q)",
			ErrInvalidConfig, c.ConfigVersion, ConfigVersion)
	}

	c.Scope.Normalize()
	if err := c.Scope.Validate(); err != nil {
		return err
	}

	if c.Limits == (Limits{}) {
		c.Limits = DefaultLimits()
	}
	if err := c.Limits.Validate(); err != nil {
		return err
	}

	// Authorisation last, bound to the now-canonical scope.
	return c.Authorization.Validate(c.Scope.Digest(), now)
}

// Digest fingerprints the reproduction-relevant configuration. It deliberately
// excludes the authorisation block: re-acknowledging authorisation tomorrow
// must not invalidate yesterday's saved cases.
func (c *SessionConfig) Digest() string {
	subset := struct {
		ConfigVersion string   `json:"config_version"`
		Scope         Scope    `json:"scope"`
		Limits        Limits   `json:"limits"`
		RedactExtra   []string `json:"redact_extra_names,omitempty"`
	}{c.ConfigVersion, c.Scope, c.Limits, c.RedactExtraNames}

	b, err := json.Marshal(subset)
	if err != nil {
		panic("safety: config digest: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NewRedactorFromConfig builds the redactor described by the config.
func (c *SessionConfig) NewRedactor() *Redactor {
	return NewRedactor(c.RedactExtraNames...)
}
