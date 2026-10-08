package fleet

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FakeConfig describes the deterministic in-process/HTTP control plane used
// by contract and Compose tests. It intentionally has no production claims.
type FakeConfig struct {
	Signer           ed25519.PrivateKey
	Issuer           string
	KeyID            string
	TrustDomain      string
	RequireMTLS      bool
	MaxResponseBytes int64
	Clock            func() time.Time
	Audit            AuditSink
}

type GatewayView struct {
	Identity  Identity   `json:"identity"`
	Heartbeat *Heartbeat `json:"heartbeat,omitempty"`
	Revoked   bool       `json:"revoked"`
	Updated   string     `json:"updated,omitempty"`
}
type FleetSummary struct {
	Total        int `json:"total"`
	Enrolled     int `json:"enrolled"`
	Revoked      int `json:"revoked"`
	Ready        int `json:"ready"`
	Degraded     int `json:"degraded"`
	Stale        int `json:"stale"`
	Noncompliant int `json:"noncompliant"`
}
type Inventory struct {
	Version  int           `json:"version"`
	Summary  FleetSummary  `json:"summary"`
	Gateways []GatewayView `json:"gateways"`
	NextPage string        `json:"next_page,omitempty"`
}

type ComplianceReport struct {
	Version       int      `json:"version"`
	Total         int      `json:"total"`
	Compliant     int      `json:"compliant"`
	Noncompliant  int      `json:"noncompliant"`
	Degraded      int      `json:"degraded"`
	Stale         int      `json:"stale"`
	ClaimsOnly    int      `json:"claims_only"`
	ExternalProof int      `json:"external_attestation_verified"`
	Reasons       []string `json:"reasons,omitempty"`
}

type Rollout struct {
	ID               string `json:"rollout_id"`
	Tenant           string `json:"tenant"`
	Environment      string `json:"environment"`
	Region           string `json:"region"`
	DesiredDigest    string `json:"desired_digest"`
	Stage            string `json:"stage"`
	ExpectedRevision uint64 `json:"revision"`
	State            string `json:"state"`
	Eligible         int    `json:"eligible"`
	Assigned         int    `json:"assigned"`
	Healthy          int    `json:"healthy"`
	Failed           int    `json:"failed"`
	ErrorBudgetBPS   int    `json:"error_budget_bps"`
	MaxConcurrency   int    `json:"max_concurrency"`
	CohortPercent    int    `json:"cohort_percent"`
	Created          string `json:"created"`
	Updated          string `json:"updated"`
	Approval         string `json:"approval,omitempty"`
	PausedReason     string `json:"paused_reason,omitempty"`
}
type RolloutRequest struct {
	Tenant           string `json:"tenant"`
	Environment      string `json:"environment"`
	Region           string `json:"region"`
	DesiredDigest    string `json:"desired_digest"`
	Stage            string `json:"stage"`
	CohortPercent    int    `json:"cohort_percent"`
	MaxConcurrency   int    `json:"max_concurrency"`
	ErrorBudgetBPS   int    `json:"error_budget_bps"`
	ExpectedRevision uint64 `json:"expected_revision"`
	Approval         string `json:"approval"`
	Confirm          bool   `json:"confirm"`
}

type FakeControlPlane struct {
	cfg           FakeConfig
	mu            sync.RWMutex
	identity      map[string]Identity
	heartbeats    map[string]Heartbeat
	desired       map[string]DesiredState
	actions       map[string][]Action
	revoked       map[string]bool
	rollouts      map[string]Rollout
	rolloutSeq    uint64
	revision      uint64
	usedBootstrap map[string]bool
}

func NewFakeControlPlane(cfg FakeConfig) (*FakeControlPlane, error) {
	if len(cfg.Signer) != ed25519.PrivateKeySize || cfg.Issuer == "" || cfg.KeyID == "" || cfg.TrustDomain == "" {
		return nil, fmt.Errorf("%w: fake control plane signer configuration", ErrInvalidContract)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = DefaultMaxResponse
	}
	return &FakeControlPlane{cfg: cfg, identity: map[string]Identity{}, heartbeats: map[string]Heartbeat{}, desired: map[string]DesiredState{}, actions: map[string][]Action{}, revoked: map[string]bool{}, rollouts: map[string]Rollout{}, usedBootstrap: map[string]bool{}}, nil
}

func (f *FakeControlPlane) PublishDesired(d DesiredState) (DesiredState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d.Issuer == "" {
		d.Issuer = f.cfg.Issuer
	}
	if d.KeyID == "" {
		d.KeyID = f.cfg.KeyID
	}
	if d.BundleID == "" {
		d.BundleID = fmt.Sprintf("fleet-%d", f.revision+1)
	}
	if d.Revision == 0 {
		d.Revision = f.revision + 1
	}
	if d.Revision <= f.revision {
		return DesiredState{}, ErrDowngrade
	}
	d.FormatVersion = FormatVersion
	d.Signature = nil
	if err := SignDesiredState(&d, f.cfg.Signer); err != nil {
		return DesiredState{}, err
	}
	if err := d.Validate(f.cfg.Clock()); err != nil {
		return DesiredState{}, err
	}
	f.revision = d.Revision
	f.desired["*"] = d
	return d, nil
}
func (f *FakeControlPlane) SetDesiredForGateway(gatewayID string, d DesiredState) (DesiredState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.identity[gatewayID]; !ok {
		return DesiredState{}, ErrCrossTenant
	}
	if d.Issuer == "" {
		d.Issuer = f.cfg.Issuer
	}
	if d.KeyID == "" {
		d.KeyID = f.cfg.KeyID
	}
	if d.BundleID == "" {
		d.BundleID = "fleet-" + gatewayID
	}
	if d.Revision <= f.revision {
		d.Revision = f.revision + 1
	}
	f.revision = d.Revision
	d.Signature = nil
	if err := SignDesiredState(&d, f.cfg.Signer); err != nil {
		return DesiredState{}, err
	}
	if err := d.Validate(time.Time{}); err != nil {
		return DesiredState{}, err
	}
	f.desired[gatewayID] = d
	return d, nil
}

func (f *FakeControlPlane) Enroll(req EnrollmentRequest, peer PeerIdentity) (EnrollmentResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cfg.RequireMTLS && !peer.MTLS {
		return EnrollmentResponse{}, fmt.Errorf("%w: fake endpoint requires mTLS", ErrInvalidContract)
	}
	if peer.TrustDomain == "" {
		peer.TrustDomain = f.cfg.TrustDomain
	}
	if peer.Certificate == "" {
		peer.Certificate = req.CertificateID
	}
	if peer.GatewayID == "" {
		peer.GatewayID = req.GatewayID
	}
	if peer.TrustDomain != f.cfg.TrustDomain || peer.GatewayID != req.GatewayID || peer.Certificate != req.CertificateID {
		return EnrollmentResponse{}, fmt.Errorf("%w: peer identity does not match fleet authority", ErrCrossTenant)
	}
	if old, ok := f.identity[req.GatewayID]; ok {
		if old.Tenant != req.Bootstrap.Tenant || old.Environment != req.Bootstrap.Environment || old.Region != req.Bootstrap.Region {
			return EnrollmentResponse{}, ErrCrossTenant
		}
		return EnrollmentResponse{}, ErrConflict
	}
	if f.usedBootstrap[req.Bootstrap.Nonce] {
		return EnrollmentResponse{}, ErrReplay
	}
	if req.Bootstrap.TrustDomain != f.cfg.TrustDomain {
		return EnrollmentResponse{}, ErrCrossTenant
	}
	if err := req.Bootstrap.Verify(f.cfg.Signer.Public().(ed25519.PublicKey), f.cfg.Clock()); err != nil {
		return EnrollmentResponse{}, err
	}
	if !peer.MTLS && f.cfg.RequireMTLS {
		return EnrollmentResponse{}, ErrInvalidContract
	}
	if !safeLabel(req.GatewayID, maxGatewayID) {
		return EnrollmentResponse{}, ErrInvalidContract
	}
	f.usedBootstrap[req.Bootstrap.Nonce] = true
	f.revision++
	id := Identity{GatewayID: req.GatewayID, Tenant: req.Bootstrap.Tenant, Environment: req.Bootstrap.Environment, Region: req.Bootstrap.Region, SoftwareVersion: req.SoftwareVersion, BuildDigest: req.BuildDigest, SBOMDigest: req.SBOMDigest, Provenance: req.Provenance, Capabilities: sortedCopy(req.Capabilities), TrustDomain: f.cfg.TrustDomain, EnrollmentState: "enrolled", CertificateID: req.CertificateID, KeyID: req.KeyID, Revision: f.revision}
	f.identity[id.GatewayID] = id
	return EnrollmentResponse{Identity: id, TrustKeyIDs: []string{f.cfg.KeyID}, Revision: f.revision, Status: "enrolled", Expires: req.Bootstrap.Expires}, nil
}

func (f *FakeControlPlane) Revoke(gatewayID, tenant string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.identity[gatewayID]
	if !ok {
		return ErrCrossTenant
	}
	if i.Tenant != tenant {
		return ErrCrossTenant
	}
	f.revoked[gatewayID] = true
	return nil
}

// QueueAction is the fake control-plane delivery seam for the strict signed
// action allowlist. Production authorization/signing remains external to the
// fixture; queued actions are still signed and revision-bound before delivery.
func (f *FakeControlPlane) QueueAction(gatewayID string, action Action) (Action, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.identity[gatewayID]
	if !ok || i.Tenant != action.Tenant || action.GatewayID != gatewayID {
		return Action{}, ErrCrossTenant
	}
	if action.Issuer == "" {
		action.Issuer = f.cfg.Issuer
	}
	if action.KeyID == "" {
		action.KeyID = f.cfg.KeyID
	}
	if action.Revision == 0 {
		if d, ok := f.desired[gatewayID]; ok {
			action.Revision = d.Revision
		} else if d, ok := f.desired["*"]; ok {
			action.Revision = d.Revision
		}
	}
	if action.Issued == "" {
		action.Issued = f.cfg.Clock().UTC().Format(time.RFC3339Nano)
	}
	if action.Expires == "" {
		action.Expires = f.cfg.Clock().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano)
	}
	if len(action.Signature) == 0 {
		if err := SignAction(&action, f.cfg.Signer); err != nil {
			return Action{}, err
		}
	}
	if err := action.Validate(f.cfg.Clock()); err != nil {
		return Action{}, fmt.Errorf("queued action invalid: %w", err)
	}
	f.actions[gatewayID] = append(f.actions[gatewayID], action)
	return action, nil
}

func (f *FakeControlPlane) Actions(gatewayID string) []Action {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]Action(nil), f.actions[gatewayID]...)
}
func (f *FakeControlPlane) Heartbeat(h Heartbeat) error {
	if err := h.Validate(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.identity[h.GatewayID]
	if !ok || i.Tenant != h.Tenant {
		return ErrCrossTenant
	}
	if f.revoked[h.GatewayID] {
		return ErrRevoked
	}
	f.heartbeats[h.GatewayID] = h
	if f.cfg.Audit != nil {
		f.cfg.Audit.RecordFleet(AuditEvent{Action: "heartbeat", GatewayID: h.GatewayID, Tenant: h.Tenant, Revision: h.StateRevision, Outcome: "accepted", At: f.cfg.Clock().UTC().Format(time.RFC3339Nano)})
	}
	return nil
}
func (f *FakeControlPlane) Desired(gatewayID string) (DesiredState, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	d, ok := f.desired[gatewayID]
	if !ok {
		d, ok = f.desired["*"]
	}
	if !ok || f.revoked[gatewayID] {
		return DesiredState{}, false
	}
	return d, true
}

func (f *FakeControlPlane) Inventory(limit int, page string) Inventory {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	ids := make([]string, 0, len(f.identity))
	for id := range f.identity {
		ids = append(ids, id)
	}
	sortStrings(ids)
	start := 0
	if page != "" {
		for n, id := range ids {
			if id == page {
				start = n + 1
			}
		}
	}
	out := Inventory{Version: 1}
	for _, id := range ids[start:] {
		if len(out.Gateways) >= limit {
			out.NextPage = id
			break
		}
		i := f.identity[id]
		v := GatewayView{Identity: i, Revoked: f.revoked[id]}
		if h, ok := f.heartbeats[id]; ok {
			v.Heartbeat = &h
			v.Updated = h.SentAt
			out.Summary.Enrolled++
			switch h.Readiness {
			case "ready":
				out.Summary.Ready++
			case "degraded":
				out.Summary.Degraded++
			}
			if h.Drift == "noncompliant" {
				out.Summary.Noncompliant++
			}
		}
		if v.Revoked {
			out.Summary.Revoked++
		}
		out.Gateways = append(out.Gateways, v)
	}
	out.Summary.Total = len(ids)
	return out
}

func (f *FakeControlPlane) CreateRollout(r RolloutRequest) (Rollout, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !r.Confirm {
		return Rollout{}, errors.New("broad rollout requires explicit confirmation")
	}
	if !safeLabel(r.Tenant, 128) || !safeLabel(r.Environment, 128) || !safeLabel(r.Region, 128) || !isDigest(r.DesiredDigest) {
		return Rollout{}, ErrInvalidContract
	}
	if r.CohortPercent < 1 || r.CohortPercent > 100 || r.MaxConcurrency < 1 || r.ErrorBudgetBPS < 0 || r.ErrorBudgetBPS > 10000 {
		return Rollout{}, ErrInvalidContract
	}
	if r.Stage != "shadow" && r.Stage != "canary" && r.Stage != "wave" {
		return Rollout{}, ErrInvalidContract
	}
	if r.ExpectedRevision != 0 && r.ExpectedRevision != f.revision {
		return Rollout{}, ErrConflict
	}
	approved := false
	for _, d := range f.desired {
		if d.Digest() == r.DesiredDigest {
			approved = true
			break
		}
	}
	if !approved {
		return Rollout{}, ErrUnsafeAction
	}
	f.rolloutSeq++
	id := fmt.Sprintf("rollout-%d", f.rolloutSeq)
	ro := Rollout{ID: id, Tenant: r.Tenant, Environment: r.Environment, Region: r.Region, DesiredDigest: r.DesiredDigest, Stage: r.Stage, CohortPercent: r.CohortPercent, ExpectedRevision: r.ExpectedRevision, State: "staged", MaxConcurrency: r.MaxConcurrency, ErrorBudgetBPS: r.ErrorBudgetBPS, Approval: r.Approval, Created: f.cfg.Clock().UTC().Format(time.RFC3339Nano), Updated: f.cfg.Clock().UTC().Format(time.RFC3339Nano)}
	for _, i := range f.identity {
		if i.Tenant == r.Tenant && i.Environment == r.Environment && i.Region == r.Region {
			ro.Eligible++
			if InCohort(i.GatewayID, i.Tenant, r.Environment, true, r.CohortPercent) {
				ro.Assigned++
			}
		}
	}
	f.rollouts[id] = ro
	return ro, nil
}
func (f *FakeControlPlane) Rollout(id string) (Rollout, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	r, ok := f.rollouts[id]
	return r, ok
}
func (f *FakeControlPlane) PauseRollout(id, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rollouts[id]
	if !ok {
		return ErrInvalidContract
	}
	r.State = "paused"
	r.PausedReason = boundedError(errors.New(reason))
	r.Updated = f.cfg.Clock().UTC().Format(time.RFC3339Nano)
	f.rollouts[id] = r
	return nil
}
func (f *FakeControlPlane) PromoteRollout(id string, confirm bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !confirm {
		return errors.New("promotion requires explicit confirmation")
	}
	r, ok := f.rollouts[id]
	if !ok {
		return ErrInvalidContract
	}
	if r.State != "staged" && r.State != "paused" {
		return ErrConflict
	}
	if r.Failed > 0 && r.ErrorBudgetBPS == 0 {
		return errors.New("rollout health budget failed")
	}
	r.State = "promoted"
	r.Updated = f.cfg.Clock().UTC().Format(time.RFC3339Nano)
	f.rollouts[id] = r
	return nil
}

func (f *FakeControlPlane) Compliance(now time.Time) ComplianceReport {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := ComplianceReport{Version: 1, Total: len(f.identity)}
	for id, identity := range f.identity {
		h, ok := f.heartbeats[id]
		if !ok {
			out.Stale++
			continue
		}
		if h.ClaimClass == "external_attested" {
			out.ExternalProof++
		} else {
			out.ClaimsOnly++
		}
		if h.Readiness == "degraded" || h.Health != "healthy" {
			out.Degraded++
		}
		d, hasDesired := f.desired[id]
		if !hasDesired {
			d, hasDesired = f.desired["*"]
		}
		compliant := hasDesired && h.PolicyDigest == d.Policy.Digest && h.ConfigDigest == d.Digest() && h.BuildDigest == identity.BuildDigest && h.SBOMDigest == identity.SBOMDigest && h.Drift == "compliant"
		if compliant {
			out.Compliant++
		} else {
			out.Noncompliant++
		}
		if sent, err := time.Parse(time.RFC3339Nano, h.SentAt); err != nil || now.Sub(sent) > 5*time.Minute {
			out.Stale++
		}
	}
	return out
}

// ServeHTTP is a deterministic fake HTTP control plane. mTLS is represented
// by the test transport/headers; production must bind PeerIdentity to actual
// verified certificates at the TLS listener.
func (f *FakeControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if r.Method == http.MethodGet && len(parts) == 4 && parts[0] == "v1" && parts[1] == "fleet" && parts[2] == "gateways" {
		id, _ := urlPathUnescape(parts[3])
		f.mu.RLock()
		i, ok := f.identity[id]
		h := f.heartbeats[id]
		revoked := f.revoked[id]
		f.mu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, GatewayView{Identity: i, Heartbeat: heartbeatPtr(h), Revoked: revoked})
		return
	}
	if r.Method == http.MethodGet && len(parts) == 5 && parts[0] == "v1" && parts[1] == "fleet" && parts[2] == "gateways" && parts[4] == "desired-state" {
		id, _ := urlPathUnescape(parts[3])
		if f.revoked[id] {
			w.WriteHeader(http.StatusGone)
			return
		}
		d, ok := f.Desired(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		etag := "\"" + d.Digest() + "\""
		w.Header().Set("ETag", etag)
		if strings.Trim(r.Header.Get("If-None-Match"), " ") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, SignedDesiredState{State: d})
		return
	}
	if r.Method == http.MethodGet && len(parts) == 5 && parts[0] == "v1" && parts[1] == "fleet" && parts[2] == "gateways" && parts[4] == "actions" {
		id, _ := urlPathUnescape(parts[3])
		f.mu.RLock()
		actions, ok := f.actions[id]
		revoked := f.revoked[id]
		f.mu.RUnlock()
		if revoked {
			w.WriteHeader(http.StatusGone)
			return
		}
		if !ok || len(actions) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		out := make([]SignedAction, 0, len(actions))
		for _, action := range actions {
			out = append(out, SignedAction{Action: action})
		}
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, out)
		return
	}
	if r.Method == http.MethodPost && path == "v1/fleet/heartbeat" {
		var h Heartbeat
		if !decodeLimited(w, r, f.cfg.MaxResponseBytes, &h) {
			return
		}
		if err := f.Heartbeat(h); err != nil {
			writeFleetError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodGet && path == "v1/fleet/inventory" {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, f.Inventory(limit, r.URL.Query().Get("page")))
		return
	}
	if r.Method == http.MethodGet && path == "v1/fleet/compliance" {
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, f.Compliance(time.Now().UTC()))
		return
	}
	if r.Method == http.MethodPost && path == "v1/fleet/desired/validate" {
		var d DesiredState
		if !decodeLimited(w, r, f.cfg.MaxResponseBytes, &d) {
			return
		}
		if err := d.ValidateUnsigned(f.cfg.Clock()); err != nil {
			writeFleetError(w, err)
			return
		}
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, map[string]any{"valid": true, "digest": d.Digest()})
		return
	}
	if r.Method == http.MethodPost && path == "v1/fleet/desired/publish" {
		var d DesiredState
		if !decodeLimited(w, r, f.cfg.MaxResponseBytes, &d) {
			return
		}
		published, err := f.PublishDesired(d)
		if err != nil {
			writeFleetError(w, err)
			return
		}
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, published)
		return
	}
	if r.Method == http.MethodPost && path == "v1/fleet/rollouts" {
		var req RolloutRequest
		if !decodeLimited(w, r, f.cfg.MaxResponseBytes, &req) {
			return
		}
		ro, err := f.CreateRollout(req)
		if err != nil {
			writeFleetError(w, err)
			return
		}
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, ro)
		return
	}
	if r.Method == http.MethodPost && len(parts) == 5 && parts[0] == "v1" && parts[1] == "fleet" && parts[2] == "rollouts" {
		id, _ := urlPathUnescape(parts[3])
		var req struct {
			Confirm bool   `json:"confirm"`
			Reason  string `json:"reason"`
		}
		if !decodeLimited(w, r, f.cfg.MaxResponseBytes, &req) {
			return
		}
		var err error
		switch parts[4] {
		case "pause":
			err = f.PauseRollout(id, req.Reason)
		case "promote":
			err = f.PromoteRollout(id, req.Confirm)
		default:
			err = ErrUnsafeAction
		}
		if err != nil {
			writeFleetError(w, err)
			return
		}
		ro, _ := f.Rollout(id)
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, ro)
		return
	}
	if r.Method == http.MethodGet && len(parts) == 5 && parts[0] == "v1" && parts[1] == "fleet" && parts[2] == "rollouts" && parts[4] == "status" {
		id, _ := urlPathUnescape(parts[3])
		ro, ok := f.Rollout(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, ro)
		return
	}
	if r.Method == http.MethodPost && len(parts) == 5 && parts[0] == "v1" && parts[1] == "fleet" && parts[2] == "enrollment" && parts[4] == "revoke" {
		id, _ := urlPathUnescape(parts[3])
		var req struct {
			Tenant  string `json:"tenant"`
			Confirm bool   `json:"confirm"`
		}
		if !decodeLimited(w, r, f.cfg.MaxResponseBytes, &req) {
			return
		}
		if !req.Confirm {
			writeFleetError(w, errors.New("revocation requires explicit confirmation"))
			return
		}
		if err := f.Revoke(id, req.Tenant); err != nil {
			writeFleetError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodPost && path == "v1/fleet/enroll" {
		var req EnrollmentRequest
		if !decodeLimited(w, r, f.cfg.MaxResponseBytes, &req) {
			return
		}
		peer := PeerIdentity{MTLS: r.Header.Get("X-Fleet-MTLS") == "verified", GatewayID: r.Header.Get("X-Fleet-Gateway-ID"), TrustDomain: r.Header.Get("X-Fleet-Trust-Domain"), Certificate: r.Header.Get("X-Fleet-Certificate-ID")}
		out, err := f.Enroll(req, peer)
		if err != nil {
			writeFleetError(w, err)
			return
		}
		writeLimitedJSON(w, f.cfg.MaxResponseBytes, out)
		return
	}
	http.NotFound(w, r)
}

func decodeLimited(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	if max <= 0 {
		max = DefaultMaxResponse
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeFleetError(w, ErrInvalidContract)
		return false
	}
	return true
}
func writeLimitedJSON(w http.ResponseWriter, max int64, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		writeFleetError(w, err)
		return
	}
	if int64(len(data)) > max {
		writeFleetError(w, errors.New("fleet response exceeds configured limit"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
func writeFleetError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrReplay) || errors.Is(err, ErrDowngrade) {
		status = http.StatusConflict
	}
	if errors.Is(err, ErrRevoked) {
		status = http.StatusGone
	}
	http.Error(w, `{"error":"fleet contract rejected"}`, status)
}
func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
func urlPathUnescape(v string) (string, error) { return url.QueryUnescape(v) }

func heartbeatPtr(h Heartbeat) *Heartbeat {
	if h.GatewayID == "" {
		return nil
	}
	return &h
}
