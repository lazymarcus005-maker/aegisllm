package fleet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/policydistribution"
)

func testDigest(value string) string { return sha256Hex([]byte(value)) }

func testIdentity() Identity {
	return Identity{GatewayID: "gw-a", Tenant: "tenant-a", Environment: "prod", Region: "ap-southeast-1", SoftwareVersion: "2.5.0", BuildDigest: testDigest("build"), SBOMDigest: testDigest("sbom"), Provenance: testDigest("provenance"), Capabilities: []string{"mcp", "rag"}, TrustDomain: "fleet-a", EnrollmentState: "enrolled", CertificateID: "cert-a", KeyID: "gateway-key", Revision: 1}
}

func testDesired(now time.Time) DesiredState {
	return DesiredState{BundleID: "bundle-1", Revision: 1, Issuer: "fleet-controller", KeyID: "fleet-key", Created: now.Add(-time.Minute).UTC().Format(time.RFC3339Nano), Expires: now.Add(time.Hour).UTC().Format(time.RFC3339Nano), MinimumGatewayVersion: "2.0.0", TenantSelectors: []string{"tenant-a"}, EnvironmentSelectors: []string{"prod"}, RegionSelectors: []string{"ap-southeast-1"}, Policy: ArtifactRef{ID: "enterprise-default", Version: "1", Digest: testDigest("policy")}, Rollout: RolloutConstraints{Stage: "wave", CohortPercent: 100, MaxConcurrency: 1, ErrorBudgetBPS: 100, RequireReady: true}, OfflineGraceSeconds: 60, Required: true}
}

func writeTrustStore(t *testing.T, path, keyID string, pub ed25519.PublicKey) {
	t.Helper()
	doc := struct {
		Keys []policydistribution.TrustKey `json:"keys"`
	}{Keys: []policydistribution.TrustKey{{KeyID: keyID, PublicKey: base64.StdEncoding.EncodeToString(pub)}}}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDesiredStateCanonicalSignatureAndAntiReplay(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	d := testDesired(now)
	d.Revision = 2
	if err := SignDesiredState(&d, priv); err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(pub, now); err != nil {
		t.Fatal(err)
	}
	first := d.Digest()
	d.TenantSelectors = []string{"tenant-a", "tenant-b"}
	if d.Digest() == first {
		t.Fatal("canonical digest ignored selector change")
	}
	d.TenantSelectors = []string{"tenant-a"}
	d.Signature[0] ^= 1
	if err := d.Verify(pub, now); err == nil {
		t.Fatal("forged desired state accepted")
	}
}

func TestFakeEnrollmentDesiredStateHeartbeatAndRollout(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := NewFakeControlPlane(FakeConfig{Signer: priv, Issuer: "fleet-controller", KeyID: "fleet-key", TrustDomain: "fleet-a", RequireMTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	bootstrap := BootstrapMaterial{Nonce: "once", Tenant: "tenant-a", Environment: "prod", Region: "ap-southeast-1", TrustDomain: "fleet-a", KeyID: "fleet-key", Issued: now.Add(-time.Minute).Format(time.RFC3339Nano), Expires: now.Add(time.Minute).Format(time.RFC3339Nano)}
	if err := SignBootstrap(&bootstrap, priv); err != nil {
		t.Fatal(err)
	}
	i := testIdentity()
	req := EnrollmentRequest{GatewayID: i.GatewayID, SoftwareVersion: i.SoftwareVersion, BuildDigest: i.BuildDigest, SBOMDigest: i.SBOMDigest, Provenance: i.Provenance, Capabilities: i.Capabilities, Bootstrap: bootstrap, CertificateID: i.CertificateID, KeyID: i.KeyID}
	if _, err := cp.Enroll(req, PeerIdentity{MTLS: true, GatewayID: i.GatewayID, TrustDomain: "fleet-a", Certificate: i.CertificateID}); err != nil {
		t.Fatal(err)
	}
	if _, err := cp.Enroll(req, PeerIdentity{MTLS: true, GatewayID: i.GatewayID, TrustDomain: "fleet-a", Certificate: i.CertificateID}); err == nil {
		t.Fatal("duplicate identity accepted")
	}
	d := testDesired(now)
	d.Revision = 2
	published, err := cp.PublishDesired(d)
	if err != nil {
		t.Fatal(err)
	}
	d = published
	h := Heartbeat{ProtocolVersion: ProtocolVersion, IdentityDigest: identityDigest(i), GatewayID: i.GatewayID, Tenant: i.Tenant, Environment: i.Environment, Region: i.Region, SoftwareVersion: i.SoftwareVersion, BuildDigest: i.BuildDigest, SBOMDigest: i.SBOMDigest, PolicyDigest: d.Policy.Digest, ConfigDigest: d.Digest(), Readiness: "ready", Health: "healthy", Drift: "compliant", Quarantine: "clear", StateRevision: d.Revision, ClaimClass: "claim", SentAt: now.Format(time.RFC3339Nano)}
	if err := cp.Heartbeat(h); err != nil {
		t.Fatal(err)
	}
	ro, err := cp.CreateRollout(RolloutRequest{Tenant: "tenant-a", Environment: "prod", Region: "ap-southeast-1", DesiredDigest: d.Digest(), Stage: "canary", CohortPercent: 50, MaxConcurrency: 1, ErrorBudgetBPS: 100, Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if ro.Eligible != 1 || ro.Assigned < 0 {
		t.Fatalf("unexpected rollout: %+v", ro)
	}
	if err := cp.PauseRollout(ro.ID, "health budget"); err != nil {
		t.Fatal(err)
	}
	if err := cp.PromoteRollout(ro.ID, true); err != nil {
		t.Fatal(err)
	}
	_ = pub
}

func TestAgentPollsPersistsRestartsAndFailsClosed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := NewFakeControlPlane(FakeConfig{Signer: priv, Issuer: "fleet-controller", KeyID: "fleet-key", TrustDomain: "fleet-a"})
	if err != nil {
		t.Fatal(err)
	}
	i := testIdentity()
	cp.identity[i.GatewayID] = i
	now := time.Now().UTC()
	d := testDesired(now)
	published, err := cp.PublishDesired(d)
	if err != nil {
		t.Fatal(err)
	}
	d = published
	httpServer := httptest.NewServer(cp)
	defer httpServer.Close()
	dir := t.TempDir()
	trust := filepath.Join(dir, "trust.json")
	writeTrustStore(t, trust, "fleet-key", pub)
	state := filepath.Join(dir, "agent.json")
	var applies atomic.Int32
	agent, err := NewAgent(AgentConfig{Identity: i, ControlPlaneURL: httpServer.URL, TrustStorePath: trust, StatePath: state, HTTPClient: httpServer.Client(), Clock: func() time.Time { return now }, Apply: func(DesiredState) error { applies.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if applies.Load() != 1 || !agent.RequestAllowed(now) {
		t.Fatalf("agent did not apply desired state: %+v", agent.Status())
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewAgent(AgentConfig{Identity: i, ControlPlaneURL: httpServer.URL, TrustStorePath: trust, StatePath: state, HTTPClient: httpServer.Client(), Clock: func() time.Time { return now }, Apply: func(DesiredState) error { applies.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.Current(); !ok {
		t.Fatal("last-known-good state was not recovered")
	}
	if err := restarted.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if applies.Load() != 1 {
		t.Fatalf("304 poll reapplied state: %d", applies.Load())
	}
	bad := d
	bad.Revision = 2
	bad.Expires = now.Add(-time.Second).Format(time.RFC3339Nano)
	if _, err := cp.PublishDesired(bad); err == nil {
		t.Fatal("expired desired state published")
	}
	if !restarted.RequestAllowed(now.Add(2 * time.Minute)) {
		t.Fatal("offline grace should still be explicit and bounded by state")
	}
	var actionCalls atomic.Int32
	restarted.cfg.ApplyAction = func(Action) error { actionCalls.Add(1); return nil }
	action := Action{ActionID: "action-1", Kind: ActionRollback, Tenant: i.Tenant, GatewayID: i.GatewayID, Revision: d.Revision, Issuer: "fleet-controller", KeyID: "fleet-key", Issued: now.Add(-time.Second).Format(time.RFC3339Nano), Expires: now.Add(time.Minute).Format(time.RFC3339Nano), TargetDigest: d.Digest()}
	if err := SignAction(&action, priv); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ApplyAction(action, pub, now); err != nil {
		current, _ := restarted.Current()
		t.Fatalf("%v target=%s current=%s action_revision=%d current_revision=%d", err, action.TargetDigest, current.Digest(), action.Revision, current.Revision)
	}
	if err := restarted.ApplyAction(action, pub, now); err != nil {
		t.Fatal(err)
	}
	if actionCalls.Load() != 1 {
		t.Fatalf("signed action was not idempotent: %d", actionCalls.Load())
	}
	if restarted.RequestAllowed(now.Add(2 * time.Hour)) {
		t.Fatal("offline grace expiry did not fail closed")
	}
}

func TestAgentRejectsCrossTenantOversizedAndRemoteCommand(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cp, _ := NewFakeControlPlane(FakeConfig{Signer: priv, Issuer: "fleet-controller", KeyID: "fleet-key", TrustDomain: "fleet-a", MaxResponseBytes: 64})
	i := testIdentity()
	cp.identity[i.GatewayID] = i
	now := time.Now().UTC()
	d := testDesired(now)
	d.TenantSelectors = []string{"tenant-b"}
	if _, err := cp.PublishDesired(d); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(cp)
	defer server.Close()
	dir := t.TempDir()
	trust := filepath.Join(dir, "trust")
	writeTrustStore(t, trust, "fleet-key", pub)
	agent, err := NewAgent(AgentConfig{Identity: i, ControlPlaneURL: server.URL, TrustStorePath: trust, HTTPClient: server.Client(), Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Poll(t.Context()); err == nil {
		t.Fatal("cross-tenant desired state accepted")
	}
	if _, ok := agent.Current(); ok {
		t.Fatal("cross-tenant state became active")
	}
	if err := (Action{FormatVersion: FormatVersion, ActionID: "x", Kind: ActionKind("shell"), Tenant: "tenant-a", GatewayID: "gw-a", Revision: 1, Issuer: "fleet-controller", KeyID: "fleet-key", Issued: now.Format(time.RFC3339Nano), Expires: now.Add(time.Minute).Format(time.RFC3339Nano), Signature: make([]byte, ed25519.SignatureSize)}).Validate(now); err == nil {
		t.Fatal("remote command action accepted")
	}
}

func TestAgentPollsSignedDeclarativeActionsAndFakeDetails(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cp, err := NewFakeControlPlane(FakeConfig{Signer: priv, Issuer: "fleet-controller", KeyID: "fleet-key", TrustDomain: "fleet-a", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	i := testIdentity()
	cp.identity[i.GatewayID] = i
	d, err := cp.PublishDesired(testDesired(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.QueueAction(i.GatewayID, Action{ActionID: "sync-1", Kind: ActionSync, Tenant: i.Tenant, GatewayID: i.GatewayID, Revision: d.Revision}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(cp)
	defer server.Close()
	dir := t.TempDir()
	trust := filepath.Join(dir, "trust")
	writeTrustStore(t, trust, "fleet-key", pub)
	var calls atomic.Int32
	agent, err := NewAgent(AgentConfig{Identity: i, ControlPlaneURL: server.URL, TrustStorePath: trust, HTTPClient: server.Client(), Clock: func() time.Time { return now }, ApplyAction: func(Action) error { calls.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := agent.PollActions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one declarative action, got %d", calls.Load())
	}
	if err := agent.PollActions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("action replay was not idempotent: %d", calls.Load())
	}
	request := httptest.NewRequest("GET", "/v1/fleet/gateways/gw-a", nil)
	response := httptest.NewRecorder()
	cp.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("gateway detail status=%d", response.Code)
	}
	var detail GatewayView
	if err := json.Unmarshal(response.Body.Bytes(), &detail); err != nil || detail.Identity.GatewayID != i.GatewayID {
		t.Fatalf("invalid gateway detail: %v %+v", err, detail)
	}
}
