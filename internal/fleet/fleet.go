// Package fleet contains the signed, content-free enterprise fleet contract.
//
// It is deliberately a control-plane contract, not a hosted control plane.
// Policy/model artifacts remain owned by their existing signed distribution
// systems and are referenced by digest only. This package never accepts or
// executes commands, secrets, prompts, documents, embeddings, or model data.
package fleet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegisllm/gateway/internal/policydistribution"
	"github.com/aegisllm/gateway/internal/securetransport"
)

const (
	FormatVersion       = 1
	ProtocolVersion     = 1
	DefaultMaxResponse  = 4 << 20
	DefaultPollInterval = 30 * time.Second
	DefaultTimeout      = 10 * time.Second
	maxGatewayID        = 128
	maxDigestLength     = 64
)

var (
	ErrInvalidContract  = errors.New("invalid fleet contract")
	ErrReplay           = errors.New("fleet revision replay")
	ErrDowngrade        = errors.New("fleet revision downgrade")
	ErrCrossTenant      = errors.New("cross-tenant fleet operation")
	ErrRevoked          = errors.New("gateway enrollment is revoked")
	ErrExpired          = errors.New("fleet contract is expired")
	ErrConflict         = errors.New("fleet optimistic revision conflict")
	ErrUnsafeAction     = errors.New("fleet action is not allowed")
	ErrAttestationClaim = errors.New("self-reported data is not attestation")
)

// Identity is immutable after enrollment. Tenant, environment, region and
// trust-domain are authority-derived and must never be accepted from a
// gateway request as scope selectors.
type Identity struct {
	GatewayID       string   `json:"gateway_id"`
	Tenant          string   `json:"tenant"`
	Environment     string   `json:"environment"`
	Region          string   `json:"region"`
	SoftwareVersion string   `json:"software_version"`
	BuildDigest     string   `json:"build_digest"`
	SBOMDigest      string   `json:"sbom_digest"`
	Provenance      string   `json:"provenance_digest"`
	Capabilities    []string `json:"capabilities,omitempty"`
	TrustDomain     string   `json:"trust_domain"`
	EnrollmentState string   `json:"enrollment_state"`
	CertificateID   string   `json:"certificate_id"`
	KeyID           string   `json:"key_id"`
	Revision        uint64   `json:"revision"`
}

func (i Identity) Validate() error {
	for name, value := range map[string]string{"gateway_id": i.GatewayID, "tenant": i.Tenant, "environment": i.Environment, "region": i.Region, "trust_domain": i.TrustDomain, "certificate_id": i.CertificateID, "key_id": i.KeyID} {
		if !safeLabel(value, 128) {
			return fmt.Errorf("%w: %s is invalid", ErrInvalidContract, name)
		}
	}
	if len(i.GatewayID) > maxGatewayID || i.Revision == 0 || i.EnrollmentState == "" {
		return fmt.Errorf("%w: identity metadata is incomplete", ErrInvalidContract)
	}
	for _, digest := range []string{i.BuildDigest, i.SBOMDigest, i.Provenance} {
		if !isDigest(digest) {
			return fmt.Errorf("%w: identity digest is invalid", ErrInvalidContract)
		}
	}
	return nil
}

type PeerIdentity struct {
	MTLS        bool
	GatewayID   string
	TrustDomain string
	Certificate string
	KeyID       string
}

type BootstrapMaterial struct {
	FormatVersion int    `json:"format_version"`
	Nonce         string `json:"nonce"`
	Tenant        string `json:"tenant"`
	Environment   string `json:"environment"`
	Region        string `json:"region"`
	TrustDomain   string `json:"trust_domain"`
	KeyID         string `json:"key_id"`
	Issued        string `json:"issued"`
	Expires       string `json:"expires"`
	Signature     []byte `json:"-"`
}

func (b BootstrapMaterial) signingBytes() ([]byte, error) {
	b.Signature = nil
	return canonical(b)
}
func CanonicalBootstrap(b BootstrapMaterial) ([]byte, error) { return b.signingBytes() }
func SignBootstrap(b *BootstrapMaterial, key ed25519.PrivateKey) error {
	if b == nil || len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: bootstrap signer", ErrInvalidContract)
	}
	b.FormatVersion = FormatVersion
	data, err := b.signingBytes()
	if err != nil {
		return err
	}
	b.Signature = ed25519.Sign(key, data)
	return nil
}
func (b BootstrapMaterial) Verify(key ed25519.PublicKey, now time.Time) error {
	if b.FormatVersion != FormatVersion || !safeLabel(b.Nonce, 128) || !safeLabel(b.Tenant, 128) || !safeLabel(b.Environment, 128) || !safeLabel(b.Region, 128) || !safeLabel(b.TrustDomain, 128) || !safeLabel(b.KeyID, 128) || len(b.Signature) != ed25519.SignatureSize || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bootstrap fields", ErrInvalidContract)
	}
	issued, err := time.Parse(time.RFC3339Nano, b.Issued)
	if err != nil {
		return fmt.Errorf("%w: bootstrap issued time", ErrInvalidContract)
	}
	expires, err := time.Parse(time.RFC3339Nano, b.Expires)
	if err != nil || !expires.After(issued) || (!now.IsZero() && (!now.Before(expires) || now.Before(issued))) {
		return ErrExpired
	}
	data, err := b.signingBytes()
	if err != nil || !ed25519.Verify(key, data, b.Signature) {
		return fmt.Errorf("%w: bootstrap signature", ErrInvalidContract)
	}
	return nil
}

type EnrollmentRequest struct {
	GatewayID       string            `json:"gateway_id"`
	SoftwareVersion string            `json:"software_version"`
	BuildDigest     string            `json:"build_digest"`
	SBOMDigest      string            `json:"sbom_digest"`
	Provenance      string            `json:"provenance_digest"`
	Capabilities    []string          `json:"capabilities,omitempty"`
	Bootstrap       BootstrapMaterial `json:"bootstrap"`
	CertificateID   string            `json:"certificate_id"`
	KeyID           string            `json:"key_id"`
}

type EnrollmentResponse struct {
	Identity    Identity `json:"identity"`
	TrustKeyIDs []string `json:"trust_key_ids"`
	Revision    uint64   `json:"revision"`
	Status      string   `json:"status"`
	Expires     string   `json:"expires"`
}

type EnrollmentClientConfig struct {
	ControlPlaneURL  string
	Timeout          time.Duration
	MaxResponseBytes int64
	HTTPClient       *http.Client
	TLS              securetransport.ClientTLSOptions
	Peer             PeerIdentity
}

// Enroll performs the client side of one-time bootstrap enrollment. In a
// production deployment the HTTP client is built from TLS above and the
// server binds PeerIdentity to the verified client certificate; headers are
// retained only as a deterministic fake transport seam.
func Enroll(ctx context.Context, cfg EnrollmentClientConfig, req EnrollmentRequest) (EnrollmentResponse, error) {
	if cfg.ControlPlaneURL == "" {
		return EnrollmentResponse{}, fmt.Errorf("%w: enrollment URL", ErrInvalidContract)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 1 << 20
	}
	client := cfg.HTTPClient
	var certs []*securetransport.File[tls.Certificate]
	if client == nil {
		tlsConfig, loaded, err := cfg.TLS.TLSConfig()
		if err != nil {
			return EnrollmentResponse{}, err
		}
		certs = loaded
		defer func() {
			for _, f := range certs {
				f.Close()
			}
		}()
		client = &http.Client{Timeout: cfg.Timeout, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(requestCtx, http.MethodPost, strings.TrimRight(cfg.ControlPlaneURL, "/")+"/v1/fleet/enroll", bytes.NewReader(body))
	if err != nil {
		return EnrollmentResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if cfg.Peer.MTLS {
		httpReq.Header.Set("X-Fleet-MTLS", "verified")
	}
	httpReq.Header.Set("X-Fleet-Gateway-ID", cfg.Peer.GatewayID)
	httpReq.Header.Set("X-Fleet-Trust-Domain", cfg.Peer.TrustDomain)
	httpReq.Header.Set("X-Fleet-Certificate-ID", cfg.Peer.Certificate)
	resp, err := client.Do(httpReq)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return EnrollmentResponse{}, fmt.Errorf("fleet enrollment status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxResponseBytes+1))
	if err != nil || int64(len(data)) > cfg.MaxResponseBytes {
		return EnrollmentResponse{}, errors.New("fleet enrollment response exceeds configured limit")
	}
	var out EnrollmentResponse
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return EnrollmentResponse{}, err
	}
	if err := out.Identity.Validate(); err != nil {
		return EnrollmentResponse{}, err
	}
	return out, nil
}

type ArtifactRef struct {
	ID      string `json:"id,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest"`
}

func (r ArtifactRef) Validate(required bool) error {
	if !required && r.ID == "" && r.Version == "" && r.Digest == "" {
		return nil
	}
	if required && !safeLabel(r.ID, 128) {
		return fmt.Errorf("%w: artifact id", ErrInvalidContract)
	}
	if r.ID != "" && !safeLabel(r.ID, 128) || r.Version != "" && !safeLabel(r.Version, 64) || !isDigest(r.Digest) {
		return fmt.Errorf("%w: artifact reference", ErrInvalidContract)
	}
	return nil
}

type RolloutConstraints struct {
	Stage           string `json:"stage"` // shadow, canary, wave
	CohortPercent   int    `json:"cohort_percent"`
	MaxConcurrency  int    `json:"max_concurrency"`
	ErrorBudgetBPS  int    `json:"error_budget_bps"`
	HealthWindowSec int    `json:"health_window_seconds"`
	RequireReady    bool   `json:"require_ready"`
	RequireEvidence bool   `json:"require_release_evidence"`
	Approval        string `json:"approval,omitempty"`
}

func (r RolloutConstraints) Validate() error {
	if r.Stage != "shadow" && r.Stage != "canary" && r.Stage != "wave" {
		return fmt.Errorf("%w: rollout stage", ErrInvalidContract)
	}
	if r.CohortPercent < 1 || r.CohortPercent > 100 || r.MaxConcurrency < 1 || r.ErrorBudgetBPS < 0 || r.ErrorBudgetBPS > 10000 || r.HealthWindowSec < 0 || r.HealthWindowSec > 86400 {
		return fmt.Errorf("%w: rollout bounds", ErrInvalidContract)
	}
	if r.RequireEvidence && r.Approval == "" {
		return fmt.Errorf("%w: release approval is required", ErrInvalidContract)
	}
	return nil
}

type DesiredState struct {
	FormatVersion         int                `json:"format_version"`
	BundleID              string             `json:"bundle_id"`
	Revision              uint64             `json:"revision"`
	Issuer                string             `json:"issuer"`
	KeyID                 string             `json:"key_id"`
	Created               string             `json:"created"`
	NotBefore             string             `json:"not_before,omitempty"`
	Expires               string             `json:"expires"`
	MinimumGatewayVersion string             `json:"minimum_gateway_version"`
	RequiredCapabilities  []string           `json:"required_capabilities,omitempty"`
	TenantSelectors       []string           `json:"tenant_selectors"`
	EnvironmentSelectors  []string           `json:"environment_selectors"`
	RegionSelectors       []string           `json:"region_selectors"`
	Policy                ArtifactRef        `json:"policy"`
	Model                 ArtifactRef        `json:"model,omitempty"`
	Route                 ArtifactRef        `json:"route,omitempty"`
	Tool                  ArtifactRef        `json:"tool,omitempty"`
	RAG                   ArtifactRef        `json:"rag,omitempty"`
	Quarantine            ArtifactRef        `json:"quarantine,omitempty"`
	Rollout               RolloutConstraints `json:"rollout"`
	OfflineGraceSeconds   int64              `json:"offline_grace_seconds"`
	Required              bool               `json:"required"`
	Signature             []byte             `json:"-"`
}

func (d DesiredState) signingBytes() ([]byte, error) {
	d.Signature = nil
	return canonical(d)
}
func CanonicalDesiredState(d DesiredState) ([]byte, error) { return d.signingBytes() }
func (d DesiredState) Digest() string {
	b, _ := d.signingBytes()
	return sha256Hex(b)
}
func SignDesiredState(d *DesiredState, key ed25519.PrivateKey) error {
	if d == nil || len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: desired-state signer", ErrInvalidContract)
	}
	d.FormatVersion = FormatVersion
	b, err := d.signingBytes()
	if err != nil {
		return err
	}
	d.Signature = ed25519.Sign(key, b)
	return nil
}
func (d DesiredState) Validate(now time.Time) error {
	if d.FormatVersion != FormatVersion || !safeLabel(d.BundleID, 128) || d.Revision == 0 || !safeLabel(d.Issuer, 128) || !safeLabel(d.KeyID, 128) || len(d.Signature) != ed25519.SignatureSize || d.MinimumGatewayVersion != "" && !validVersion(d.MinimumGatewayVersion) {
		return fmt.Errorf("%w: desired-state metadata", ErrInvalidContract)
	}
	created, err := time.Parse(time.RFC3339Nano, d.Created)
	if err != nil {
		return fmt.Errorf("%w: desired-state created time", ErrInvalidContract)
	}
	expires, err := time.Parse(time.RFC3339Nano, d.Expires)
	if err != nil || !expires.After(created) {
		return fmt.Errorf("%w: desired-state validity window", ErrInvalidContract)
	}
	if !now.IsZero() {
		if now.Before(created) || !now.Before(expires) {
			return ErrExpired
		}
		if d.NotBefore != "" {
			nb, e := time.Parse(time.RFC3339Nano, d.NotBefore)
			if e != nil || now.Before(nb) {
				return fmt.Errorf("%w: desired-state not yet valid", ErrInvalidContract)
			}
		}
	}
	if d.OfflineGraceSeconds < 0 || d.OfflineGraceSeconds > 7*24*60*60 || len(d.RequiredCapabilities) > 128 {
		return fmt.Errorf("%w: desired-state offline grace or capabilities", ErrInvalidContract)
	}
	for _, cap := range d.RequiredCapabilities {
		if !safeLabel(cap, 128) {
			return fmt.Errorf("%w: desired-state capability", ErrInvalidContract)
		}
	}
	for _, selectors := range [][]string{d.TenantSelectors, d.EnvironmentSelectors, d.RegionSelectors} {
		if len(selectors) > 64 {
			return fmt.Errorf("%w: selector count", ErrInvalidContract)
		}
		for _, selector := range selectors {
			if selector != "*" && !safeLabel(selector, 128) {
				return fmt.Errorf("%w: selector", ErrInvalidContract)
			}
		}
	}
	for _, ref := range []struct {
		ref      ArtifactRef
		required bool
	}{{d.Policy, true}, {d.Model, false}, {d.Route, false}, {d.Tool, false}, {d.RAG, false}, {d.Quarantine, false}} {
		if err := ref.ref.Validate(ref.required); err != nil {
			return err
		}
	}
	if err := d.Rollout.Validate(); err != nil {
		return err
	}
	return nil
}

// ValidateUnsigned validates structure before the control plane signs a
// bundle. It cannot be used to apply state because Verify still requires the
// real signature.
func (d DesiredState) ValidateUnsigned(now time.Time) error {
	d.Signature = make([]byte, ed25519.SignatureSize)
	return d.Validate(now)
}
func (d DesiredState) Verify(key ed25519.PublicKey, now time.Time) error {
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: desired-state trust key", ErrInvalidContract)
	}
	if err := d.Validate(now); err != nil {
		return err
	}
	b, err := d.signingBytes()
	if err != nil || !ed25519.Verify(key, b, d.Signature) {
		return fmt.Errorf("%w: desired-state signature", ErrInvalidContract)
	}
	return nil
}

type SignedDesiredState struct {
	State     DesiredState `json:"state"`
	Signature string       `json:"signature"`
}

func (s SignedDesiredState) MarshalJSON() ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(s.State.Signature)
	return canonical(struct {
		State DesiredState `json:"state"`
		Sig   string       `json:"signature"`
	}{s.State, encoded})
}
func (s *SignedDesiredState) UnmarshalJSON(data []byte) error {
	var wire struct {
		State DesiredState `json:"state"`
		Sig   string       `json:"signature"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(wire.Sig)
	if err != nil {
		return err
	}
	wire.State.Signature = sig
	s.State, s.Signature = wire.State, wire.Sig
	return nil
}

type ActionKind string

const (
	ActionSync           ActionKind = "sync"
	ActionPauseRollout   ActionKind = "pause_rollout"
	ActionRollback       ActionKind = "rollback_verified_digest"
	ActionQuarantine     ActionKind = "quarantine_scope"
	ActionRotateTrust    ActionKind = "rotate_trust_reference"
	ActionRequireUpgrade ActionKind = "require_upgrade"
)

type Action struct {
	FormatVersion int        `json:"format_version"`
	ActionID      string     `json:"action_id"`
	Kind          ActionKind `json:"kind"`
	Tenant        string     `json:"tenant"`
	GatewayID     string     `json:"gateway_id"`
	Revision      uint64     `json:"revision"`
	TargetDigest  string     `json:"target_digest,omitempty"`
	Scope         string     `json:"scope,omitempty"`
	Issuer        string     `json:"issuer"`
	KeyID         string     `json:"key_id"`
	Issued        string     `json:"issued"`
	Expires       string     `json:"expires"`
	Signature     []byte     `json:"-"`
}

// SignedAction is the wire envelope for a remote declarative action. Keeping
// the signature outside the canonical action prevents accidental signing of
// the signature field while making omission on the wire impossible.
type SignedAction struct {
	Action    Action `json:"action"`
	Signature string `json:"signature"`
}

func (s SignedAction) MarshalJSON() ([]byte, error) {
	return canonical(struct {
		Action Action `json:"action"`
		Sig    string `json:"signature"`
	}{s.Action, base64.StdEncoding.EncodeToString(s.Action.Signature)})
}

func (s *SignedAction) UnmarshalJSON(data []byte) error {
	var wire struct {
		Action Action `json:"action"`
		Sig    string `json:"signature"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(wire.Sig)
	if err != nil {
		return err
	}
	wire.Action.Signature = sig
	s.Action, s.Signature = wire.Action, wire.Sig
	return nil
}

func (a Action) signingBytes() ([]byte, error) { a.Signature = nil; return canonical(a) }
func CanonicalAction(a Action) ([]byte, error) { return a.signingBytes() }
func (a Action) Validate(now time.Time) error {
	allowed := map[ActionKind]bool{ActionSync: true, ActionPauseRollout: true, ActionRollback: true, ActionQuarantine: true, ActionRotateTrust: true, ActionRequireUpgrade: true}
	if a.FormatVersion != FormatVersion || !allowed[a.Kind] || !safeLabel(a.ActionID, 128) || !safeLabel(a.Tenant, 128) || !safeLabel(a.GatewayID, maxGatewayID) || !safeLabel(a.Issuer, 128) || !safeLabel(a.KeyID, 128) || a.Revision == 0 || len(a.Signature) != ed25519.SignatureSize || a.Expires == "" || a.Issued == "" {
		return fmt.Errorf("%w: action fields", ErrInvalidContract)
	}
	if a.Kind == ActionRollback && !isDigest(a.TargetDigest) || a.Kind == ActionQuarantine && !safeLabel(a.Scope, 128) {
		return fmt.Errorf("%w: action target", ErrInvalidContract)
	}
	issued, err := time.Parse(time.RFC3339Nano, a.Issued)
	if err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339Nano, a.Expires)
	if err != nil || !expires.After(issued) {
		return ErrExpired
	}
	if !now.IsZero() && (!now.Before(expires) || now.Before(issued)) {
		return ErrExpired
	}
	return nil
}
func SignAction(a *Action, key ed25519.PrivateKey) error {
	if a == nil || len(key) != ed25519.PrivateKeySize {
		return ErrInvalidContract
	}
	a.FormatVersion = FormatVersion
	b, e := a.signingBytes()
	if e != nil {
		return e
	}
	a.Signature = ed25519.Sign(key, b)
	return nil
}
func (a Action) Verify(key ed25519.PublicKey, now time.Time) error {
	if e := a.Validate(now); e != nil {
		return e
	}
	b, e := a.signingBytes()
	if e != nil || !ed25519.Verify(key, b, a.Signature) {
		return fmt.Errorf("%w: action signature", ErrInvalidContract)
	}
	return nil
}

type Heartbeat struct {
	ProtocolVersion int    `json:"protocol_version"`
	IdentityDigest  string `json:"identity_digest"`
	GatewayID       string `json:"gateway_id"`
	Tenant          string `json:"tenant"`
	Environment     string `json:"environment"`
	Region          string `json:"region"`
	SoftwareVersion string `json:"software_version"`
	BuildDigest     string `json:"build_digest"`
	SBOMDigest      string `json:"sbom_digest"`
	PolicyDigest    string `json:"policy_digest"`
	ModelDigest     string `json:"model_digest,omitempty"`
	ConfigDigest    string `json:"config_digest"`
	Readiness       string `json:"readiness"`
	Health          string `json:"health"`
	Drift           string `json:"drift"`
	Quarantine      string `json:"quarantine"`
	LastSync        string `json:"last_sync,omitempty"`
	LastErrorCode   string `json:"last_error_code,omitempty"`
	EvidenceDigest  string `json:"evidence_digest,omitempty"`
	StateRevision   uint64 `json:"state_revision"`
	ClaimClass      string `json:"claim_class"` // claim; external_attested is an integration seam only.
	SentAt          string `json:"sent_at"`
}

func (h Heartbeat) Validate() error {
	if h.ProtocolVersion != ProtocolVersion || !safeLabel(h.GatewayID, maxGatewayID) || !safeLabel(h.Tenant, 128) || !safeLabel(h.Environment, 128) || !safeLabel(h.Region, 128) || !isDigest(h.IdentityDigest) || !isDigest(h.BuildDigest) || !isDigest(h.SBOMDigest) || h.PolicyDigest != "" && !isDigest(h.PolicyDigest) || !isDigest(h.ConfigDigest) || h.ClaimClass != "claim" && h.ClaimClass != "external_attested" || h.StateRevision == 0 {
		return fmt.Errorf("%w: heartbeat fields", ErrInvalidContract)
	}
	for _, label := range []string{h.Readiness, h.Health, h.Drift, h.Quarantine, h.LastErrorCode} {
		if label != "" && !safeLabel(label, 64) {
			return fmt.Errorf("%w: heartbeat label", ErrInvalidContract)
		}
	}
	return nil
}

type AuditEvent struct {
	Action    string `json:"action"`
	GatewayID string `json:"gateway_id,omitempty"`
	Tenant    string `json:"tenant,omitempty"`
	Revision  uint64 `json:"revision,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Outcome   string `json:"outcome"`
	At        string `json:"at"`
}
type AuditSink interface{ RecordFleet(AuditEvent) }

type EnrollmentAuthority struct {
	TrustStorePath   string
	FleetTrustDomain string
	Clock            func() time.Time
	mu               sync.Mutex
	used             map[string]bool
	gateways         map[string]Identity
	revision         uint64
}

func NewEnrollmentAuthority(trustPath, trustDomain string) *EnrollmentAuthority {
	return &EnrollmentAuthority{TrustStorePath: trustPath, FleetTrustDomain: trustDomain, Clock: time.Now, used: map[string]bool{}, gateways: map[string]Identity{}}
}
func (a *EnrollmentAuthority) Enroll(req EnrollmentRequest, peer PeerIdentity) (EnrollmentResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.Clock()
	if !peer.MTLS || peer.GatewayID != req.GatewayID || peer.TrustDomain != a.FleetTrustDomain || peer.Certificate == "" || peer.Certificate != req.CertificateID {
		return EnrollmentResponse{}, fmt.Errorf("%w: verified mTLS identity required", ErrInvalidContract)
	}
	if !safeLabel(req.GatewayID, maxGatewayID) || !isDigest(req.BuildDigest) || !isDigest(req.SBOMDigest) || !isDigest(req.Provenance) {
		return EnrollmentResponse{}, ErrInvalidContract
	}
	store := policydistribution.NewTrustStore(a.TrustStorePath)
	key, err := store.Key(req.Bootstrap.KeyID, now)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	if err = req.Bootstrap.Verify(key, now); err != nil {
		return EnrollmentResponse{}, err
	}
	if req.Bootstrap.TrustDomain != a.FleetTrustDomain || req.Bootstrap.Nonce == "" || a.used[req.Bootstrap.Nonce] {
		return EnrollmentResponse{}, ErrReplay
	}
	if old, ok := a.gateways[req.GatewayID]; ok {
		if old.TrustDomain != req.Bootstrap.TrustDomain || old.Tenant != req.Bootstrap.Tenant || old.Environment != req.Bootstrap.Environment || old.Region != req.Bootstrap.Region {
			return EnrollmentResponse{}, ErrCrossTenant
		}
		return EnrollmentResponse{}, fmt.Errorf("%w: duplicate gateway identity", ErrConflict)
	}
	a.used[req.Bootstrap.Nonce] = true
	a.revision++
	i := Identity{GatewayID: req.GatewayID, Tenant: req.Bootstrap.Tenant, Environment: req.Bootstrap.Environment, Region: req.Bootstrap.Region, SoftwareVersion: req.SoftwareVersion, BuildDigest: req.BuildDigest, SBOMDigest: req.SBOMDigest, Provenance: req.Provenance, Capabilities: sortedCopy(req.Capabilities), TrustDomain: req.Bootstrap.TrustDomain, EnrollmentState: "enrolled", CertificateID: req.CertificateID, KeyID: req.KeyID, Revision: a.revision}
	a.gateways[i.GatewayID] = i
	return EnrollmentResponse{Identity: i, TrustKeyIDs: []string{req.Bootstrap.KeyID}, Revision: a.revision, Status: "enrolled", Expires: req.Bootstrap.Expires}, nil
}

type AgentStatus struct {
	IdentityDigest    string `json:"identity_digest"`
	GatewayID         string `json:"gateway_id"`
	Tenant            string `json:"tenant"`
	Revision          uint64 `json:"revision"`
	DesiredDigest     string `json:"desired_digest,omitempty"`
	LastGood          string `json:"last_good,omitempty"`
	LastSync          string `json:"last_sync,omitempty"`
	LastErrorCode     string `json:"last_error_code,omitempty"`
	State             string `json:"state"`
	OfflineGraceUntil string `json:"offline_grace_until,omitempty"`
	FailClosed        bool   `json:"fail_closed"`
	Revoked           bool   `json:"revoked"`
}
type persistedAgentState struct {
	Identity         Identity        `json:"identity"`
	Desired          DesiredState    `json:"desired"`
	DesiredSignature string          `json:"desired_signature"`
	Status           AgentStatus     `json:"status"`
	OfflineSince     string          `json:"offline_since,omitempty"`
	ETag             string          `json:"etag,omitempty"`
	SeenActions      map[string]bool `json:"seen_actions,omitempty"`
}

type AgentConfig struct {
	Identity         Identity
	ControlPlaneURL  string
	TrustStorePath   string
	StatePath        string
	PollInterval     time.Duration
	Timeout          time.Duration
	MaxResponseBytes int64
	OfflineGrace     time.Duration
	RequireState     bool
	HTTPClient       *http.Client
	TLS              securetransport.ClientTLSOptions
	Clock            func() time.Time
	Apply            func(DesiredState) error
	Heartbeat        func() Heartbeat
	Audit            AuditSink
	ApplyAction      func(Action) error
	Jitter           func(time.Duration) time.Duration
}
type Agent struct {
	cfg     AgentConfig
	mu      sync.RWMutex
	state   persistedAgentState
	trust   *policydistribution.TrustStore
	running atomic.Bool
}

func NewAgent(cfg AgentConfig) (*Agent, error) {
	if err := cfg.Identity.Validate(); err != nil {
		return nil, err
	}
	if cfg.ControlPlaneURL == "" {
		return nil, fmt.Errorf("%w: control plane URL", ErrInvalidContract)
	}
	u, err := url.Parse(cfg.ControlPlaneURL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") && cfg.TLS.CAFile != "" {
		return nil, errors.New("fleet control plane must use HTTPS when TLS material is configured")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = DefaultMaxResponse
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.OfflineGrace <= 0 {
		cfg.OfflineGrace = 24 * time.Hour
	}
	if cfg.Jitter == nil {
		cfg.Jitter = func(d time.Duration) time.Duration { return d }
	}
	if cfg.Apply == nil {
		cfg.Apply = func(DesiredState) error { return nil }
	}
	if cfg.ApplyAction == nil {
		cfg.ApplyAction = func(Action) error { return nil }
	}
	a := &Agent{cfg: cfg, trust: policydistribution.NewTrustStore(cfg.TrustStorePath)}
	if err := a.load(); err != nil {
		return nil, err
	}
	return a, nil
}
func (a *Agent) load() error {
	if a.cfg.StatePath == "" {
		return nil
	}
	data, err := securetransport.ReadTrustedFile(a.cfg.StatePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var p persistedAgentState
	if err = json.Unmarshal(data, &p); err != nil {
		return err
	}
	if p.Identity.GatewayID != "" && p.Identity.GatewayID != a.cfg.Identity.GatewayID {
		return ErrCrossTenant
	}
	if p.Desired.BundleID != "" {
		sig, e := base64.StdEncoding.DecodeString(p.DesiredSignature)
		if e != nil {
			return e
		}
		p.Desired.Signature = sig
		key, e := a.trust.Key(p.Desired.KeyID, a.cfg.Clock())
		if e != nil {
			return e
		}
		if e = p.Desired.Verify(key, time.Time{}); e != nil {
			return e
		}
	}
	if p.SeenActions == nil {
		p.SeenActions = map[string]bool{}
	}
	a.state = p
	return nil
}
func (a *Agent) persistLocked() error {
	if a.cfg.StatePath == "" {
		return nil
	}
	p := a.state
	p.DesiredSignature = base64.StdEncoding.EncodeToString(p.Desired.Signature)
	p.Desired.Signature = nil
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(a.cfg.StatePath), 0750); err != nil {
		return err
	}
	tmp := a.cfg.StatePath + ".tmp"
	if err = os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.cfg.StatePath)
}
func (a *Agent) Status() AgentStatus { a.mu.RLock(); defer a.mu.RUnlock(); return a.state.Status }
func (a *Agent) Current() (DesiredState, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.state.Desired.BundleID == "" {
		return DesiredState{}, false
	}
	return a.state.Desired, true
}

// ApplyAction verifies and applies one declarative operation. The callback is
// a gateway-owned transition (for example, the existing quarantine engine),
// never an interpreter. Action IDs are durable idempotency keys.
func (a *Agent) ApplyAction(action Action, key ed25519.PublicKey, now time.Time) error {
	if err := action.Verify(key, now); err != nil {
		return err
	}
	a.mu.Lock()
	if action.GatewayID != a.cfg.Identity.GatewayID || action.Tenant != a.cfg.Identity.Tenant {
		a.mu.Unlock()
		return ErrCrossTenant
	}
	if a.state.Desired.BundleID == "" || action.Revision != a.state.Desired.Revision {
		a.mu.Unlock()
		return ErrConflict
	}
	if a.state.SeenActions == nil {
		a.state.SeenActions = map[string]bool{}
	}
	if a.state.SeenActions[action.ActionID] {
		a.mu.Unlock()
		return nil
	}
	if action.Kind == ActionRollback && action.TargetDigest != a.state.Desired.Digest() {
		a.mu.Unlock()
		return ErrUnsafeAction
	}
	apply := a.cfg.ApplyAction
	a.mu.Unlock()
	if err := apply(action); err != nil {
		return fmt.Errorf("fleet action rejected: %w", err)
	}
	a.mu.Lock()
	a.state.SeenActions[action.ActionID] = true
	if action.Kind == ActionRequireUpgrade {
		a.state.Status.FailClosed = true
		a.state.Status.State = "upgrade_required"
	}
	if err := a.persistLocked(); err != nil {
		a.mu.Unlock()
		return err
	}
	a.mu.Unlock()
	if a.cfg.Audit != nil {
		a.cfg.Audit.RecordFleet(AuditEvent{Action: string(action.Kind), GatewayID: action.GatewayID, Tenant: action.Tenant, Revision: action.Revision, Digest: action.TargetDigest, Outcome: "accepted", At: now.UTC().Format(time.RFC3339Nano)})
	}
	return nil
}
func (a *Agent) RequestAllowed(now time.Time) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.state.Status.Revoked {
		return false
	}
	d := a.state.Desired
	if d.BundleID == "" {
		return !a.cfg.RequireState
	}
	exp, e := time.Parse(time.RFC3339Nano, d.Expires)
	if e != nil {
		return false
	}
	grace := time.Duration(d.OfflineGraceSeconds) * time.Second
	if grace <= 0 {
		grace = a.cfg.OfflineGrace
	}
	return now.Before(exp.Add(grace))
}
func (a *Agent) Poll(ctx context.Context) error {
	if a.running.Swap(true) {
		return errors.New("fleet poll already running")
	}
	defer a.running.Store(false)
	client := a.cfg.HTTPClient
	var certs []*securetransport.File[tls.Certificate]
	if client == nil {
		tlsCfg, loaded, err := a.cfg.TLS.TLSConfig()
		if err != nil {
			return a.failure(err)
		}
		certs = loaded
		defer func() {
			for _, f := range certs {
				f.Close()
			}
		}()
		client = &http.Client{Timeout: a.cfg.Timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	}
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	endpoint := strings.TrimRight(a.cfg.ControlPlaneURL, "/") + "/v1/fleet/gateways/" + url.PathEscape(a.cfg.Identity.GatewayID) + "/desired-state"
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return a.failure(err)
	}
	req.Header.Set("X-Fleet-Gateway-ID", a.cfg.Identity.GatewayID)
	a.mu.RLock()
	etag := a.state.ETag
	a.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return a.failure(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return a.success()
	}
	if resp.StatusCode == http.StatusGone {
		return a.revoke()
	}
	if resp.StatusCode != http.StatusOK {
		return a.failure(fmt.Errorf("control plane status %d", resp.StatusCode))
	}
	if resp.ContentLength > a.cfg.MaxResponseBytes {
		return a.failure(errors.New("fleet response exceeds configured limit"))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, a.cfg.MaxResponseBytes+1))
	if err != nil || int64(len(data)) > a.cfg.MaxResponseBytes {
		return a.failure(errors.New("fleet response exceeds configured limit"))
	}
	var signed SignedDesiredState
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&signed); err != nil {
		return a.failure(err)
	}
	if signed.State.KeyID == "" {
		return a.failure(ErrInvalidContract)
	}
	key, err := a.trust.Key(signed.State.KeyID, a.cfg.Clock())
	if err != nil {
		return a.failure(err)
	}
	if err = signed.State.Verify(key, a.cfg.Clock()); err != nil {
		return a.failure(err)
	}
	if err = matchIdentity(a.cfg.Identity, signed.State); err != nil {
		return a.failure(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if signed.State.Revision < a.state.Desired.Revision {
		return a.failureLocked(ErrDowngrade)
	}
	if signed.State.Revision == a.state.Desired.Revision && a.state.Status.DesiredDigest != "" && a.state.Status.DesiredDigest != signed.State.Digest() {
		return a.failureLocked(ErrReplay)
	}
	if err = a.cfg.Apply(signed.State); err != nil {
		return a.failureLocked(fmt.Errorf("atomic fleet apply rejected: %w", err))
	}
	a.state.Desired = signed.State
	a.state.Status = AgentStatus{IdentityDigest: identityDigest(a.cfg.Identity), GatewayID: a.cfg.Identity.GatewayID, Tenant: a.cfg.Identity.Tenant, Revision: signed.State.Revision, DesiredDigest: signed.State.Digest(), LastGood: signed.State.Digest(), LastSync: a.cfg.Clock().UTC().Format(time.RFC3339Nano), State: "synced"}
	if resp.Header.Get("ETag") != "" {
		a.state.ETag = resp.Header.Get("ETag")
	}
	a.state.OfflineSince = ""
	if err = a.persistLocked(); err != nil {
		return err
	}
	if a.cfg.Audit != nil {
		a.cfg.Audit.RecordFleet(AuditEvent{Action: "desired_state_apply", GatewayID: a.cfg.Identity.GatewayID, Tenant: a.cfg.Identity.Tenant, Revision: signed.State.Revision, Digest: signed.State.Digest(), Outcome: "accepted", At: a.cfg.Clock().UTC().Format(time.RFC3339Nano)})
	}
	return nil
}

// PollActions retrieves only signed, revision-bound declarative transitions.
// The endpoint has no command or payload execution semantics; every action is
// verified before the gateway-owned callback is invoked.
func (a *Agent) PollActions(ctx context.Context) error {
	client := a.cfg.HTTPClient
	var certs []*securetransport.File[tls.Certificate]
	if client == nil {
		tlsCfg, loaded, err := a.cfg.TLS.TLSConfig()
		if err != nil {
			return err
		}
		certs = loaded
		defer func() {
			for _, f := range certs {
				f.Close()
			}
		}()
		client = &http.Client{Timeout: a.cfg.Timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	}
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	endpoint := strings.TrimRight(a.cfg.ControlPlaneURL, "/") + "/v1/fleet/gateways/" + url.PathEscape(a.cfg.Identity.GatewayID) + "/actions"
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Fleet-Gateway-ID", a.cfg.Identity.GatewayID)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane actions status %d", resp.StatusCode)
	}
	if resp.ContentLength > a.cfg.MaxResponseBytes {
		return errors.New("fleet actions response exceeds configured limit")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, a.cfg.MaxResponseBytes+1))
	if err != nil || int64(len(data)) > a.cfg.MaxResponseBytes {
		return errors.New("fleet actions response exceeds configured limit")
	}
	var actions []SignedAction
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&actions); err != nil {
		return err
	}
	if len(actions) > 64 {
		return errors.New("fleet actions response contains too many actions")
	}
	for _, signed := range actions {
		action := signed.Action
		key, err := a.trust.Key(action.KeyID, a.cfg.Clock())
		if err != nil {
			return err
		}
		if err := a.ApplyAction(action, key, a.cfg.Clock()); err != nil {
			return err
		}
	}
	return nil
}

// Run owns bounded retry/backoff for the control-plane seam. It never runs on
// the gateway request goroutine; callers should start it as a background
// lifecycle task and cancel it during shutdown.
func (a *Agent) Run(ctx context.Context) {
	attempt := 0
	for {
		err := a.Poll(ctx)
		_ = a.PollActions(ctx)
		_ = a.SendHeartbeat(ctx)
		if err == nil {
			attempt = 0
		} else {
			attempt++
		}
		wait := a.cfg.Jitter(Backoff(attempt, a.cfg.PollInterval, 5*time.Minute, nil))
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		}
	}
}

func (a *Agent) success() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.Status.LastSync = a.cfg.Clock().UTC().Format(time.RFC3339Nano)
	a.state.Status.LastErrorCode = ""
	if a.state.Status.State == "" {
		a.state.Status.State = "synced"
	}
	a.state.OfflineSince = ""
	return a.persistLocked()
}
func (a *Agent) failure(err error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.failureLocked(err)
}
func (a *Agent) failureLocked(err error) error {
	now := a.cfg.Clock().UTC()
	if a.state.OfflineSince == "" {
		a.state.OfflineSince = now.Format(time.RFC3339Nano)
	}
	a.state.Status.LastErrorCode = boundedError(err)
	a.state.Status.State = "offline"
	if !a.allowedLocked(now) {
		a.state.Status.FailClosed = true
	}
	_ = a.persistLocked()
	if a.cfg.Audit != nil {
		a.cfg.Audit.RecordFleet(AuditEvent{Action: "desired_state_poll", GatewayID: a.cfg.Identity.GatewayID, Tenant: a.cfg.Identity.Tenant, Outcome: "rejected", At: now.Format(time.RFC3339Nano)})
	}
	return err
}
func (a *Agent) revoke() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.Status.Revoked = true
	a.state.Status.FailClosed = true
	a.state.Status.State = "revoked"
	_ = a.persistLocked()
	return ErrRevoked
}
func (a *Agent) allowedLocked(now time.Time) bool {
	if a.state.Status.Revoked {
		return false
	}
	d := a.state.Desired
	if d.BundleID == "" {
		return !a.cfg.RequireState
	}
	exp, e := time.Parse(time.RFC3339Nano, d.Expires)
	if e != nil {
		return false
	}
	grace := time.Duration(d.OfflineGraceSeconds) * time.Second
	if grace <= 0 {
		grace = a.cfg.OfflineGrace
	}
	return now.Before(exp.Add(grace))
}
func (a *Agent) Heartbeat() Heartbeat {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.cfg.Heartbeat != nil {
		h := a.cfg.Heartbeat()
		h.GatewayID = a.cfg.Identity.GatewayID
		h.Tenant = a.cfg.Identity.Tenant
		h.Environment = a.cfg.Identity.Environment
		h.Region = a.cfg.Identity.Region
		h.IdentityDigest = identityDigest(a.cfg.Identity)
		h.StateRevision = a.state.Desired.Revision
		h.ClaimClass = "claim"
		return h
	}
	configDigest := a.state.Status.DesiredDigest
	if configDigest == "" {
		configDigest = identityDigest(a.cfg.Identity)
	}
	stateRevision := a.state.Desired.Revision
	if stateRevision == 0 {
		stateRevision = a.cfg.Identity.Revision
	}
	h := Heartbeat{ProtocolVersion: ProtocolVersion, IdentityDigest: identityDigest(a.cfg.Identity), GatewayID: a.cfg.Identity.GatewayID, Tenant: a.cfg.Identity.Tenant, Environment: a.cfg.Identity.Environment, Region: a.cfg.Identity.Region, SoftwareVersion: a.cfg.Identity.SoftwareVersion, BuildDigest: a.cfg.Identity.BuildDigest, SBOMDigest: a.cfg.Identity.SBOMDigest, PolicyDigest: a.state.Desired.Policy.Digest, ConfigDigest: configDigest, Readiness: "unknown", Health: "unknown", Drift: "unknown", Quarantine: "unknown", StateRevision: stateRevision, ClaimClass: "claim", SentAt: a.cfg.Clock().UTC().Format(time.RFC3339Nano)}
	return h
}

// SendHeartbeat uploads only the bounded Heartbeat projection. It is separate
// from Poll so a control-plane outage cannot delay request handling.
func (a *Agent) SendHeartbeat(ctx context.Context) error {
	client := a.cfg.HTTPClient
	var certs []*securetransport.File[tls.Certificate]
	if client == nil {
		tlsCfg, loaded, err := a.cfg.TLS.TLSConfig()
		if err != nil {
			return err
		}
		certs = loaded
		defer func() {
			for _, f := range certs {
				f.Close()
			}
		}()
		client = &http.Client{Timeout: a.cfg.Timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	}
	body, err := json.Marshal(a.Heartbeat())
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, strings.TrimRight(a.cfg.ControlPlaneURL, "/")+"/v1/fleet/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fleet-Gateway-ID", a.cfg.Identity.GatewayID)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane heartbeat status %d", resp.StatusCode)
	}
	return nil
}

func matchIdentity(i Identity, d DesiredState) error {
	if !selectorMatch(i.Tenant, d.TenantSelectors) || !selectorMatch(i.Environment, d.EnvironmentSelectors) || !selectorMatch(i.Region, d.RegionSelectors) {
		return ErrCrossTenant
	}
	for _, want := range d.RequiredCapabilities {
		found := false
		for _, got := range i.Capabilities {
			if want == got {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: required capability missing", ErrInvalidContract)
		}
	}
	if versionLess(i.SoftwareVersion, d.MinimumGatewayVersion) {
		return fmt.Errorf("%w: gateway version below desired-state minimum", ErrDowngrade)
	}
	return nil
}

// InCohort is the only rollout assignment primitive. It uses verified,
// immutable gateway identity and never accepts a client-supplied cohort.
func InCohort(gatewayID, tenant, environment string, verified bool, percentage int) bool {
	if !verified || percentage <= 0 {
		return false
	}
	if percentage > 100 {
		percentage = 100
	}
	sum := sha256.Sum256([]byte(gatewayID + "\x00" + tenant + "\x00" + environment))
	return (int(sum[0])<<8|int(sum[1]))%100 < percentage
}
func selectorMatch(value string, selectors []string) bool {
	if len(selectors) == 0 {
		return false
	}
	for _, s := range selectors {
		if s == "*" || s == value {
			return true
		}
	}
	return false
}
func identityDigest(i Identity) string { b, _ := canonical(i); return sha256Hex(b) }

func IdentityDigest(i Identity) string { return identityDigest(i) }
func canonical(v any) ([]byte, error)  { return json.Marshal(v) }
func sha256Hex(b []byte) string        { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func isDigest(v string) bool {
	if len(v) != maxDigestLength {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}
func safeLabel(v string, max int) bool {
	if v == "" || len(v) > max || strings.TrimSpace(v) != v {
		return false
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' && r != '/' && r != ':' {
			return false
		}
	}
	return true
}
func validVersion(v string) bool {
	if v == "" {
		return false
	}
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
func versionLess(got, want string) bool {
	if want == "" {
		return false
	}
	parse := func(v string) [3]int {
		var out [3]int
		for n, p := range strings.Split(strings.TrimPrefix(v, "v"), ".") {
			if n > 2 {
				break
			}
			for _, r := range p {
				out[n] = out[n]*10 + int(r-'0')
			}
		}
		return out
	}
	a, b := parse(got), parse(want)
	for n := 0; n < 3; n++ {
		if a[n] != b[n] {
			return a[n] < b[n]
		}
	}
	return false
}
func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
func boundedError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 96 {
		s = s[:96]
	}
	return s
}

// Backoff returns a bounded exponential delay with deterministic jitter when
// a source is supplied. It is kept separate so tests can prove no request
// path waits on fleet control-plane failure.
func Backoff(attempt int, base, max time.Duration, r *rand.Rand) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if base <= 0 {
		base = time.Second
	}
	if max <= 0 {
		max = time.Minute
	}
	d := base
	for n := 0; n < attempt && d < max; n++ {
		d *= 2
		if d > max {
			d = max
		}
	}
	if r == nil {
		return d
	}
	j := time.Duration(r.Int63n(int64(d/4 + 1)))
	return d - d/8 + j
}
