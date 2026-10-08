package semantic

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/policydistribution"
)

func fixture(t *testing.T, synthetic bool) (*Manager, Artifact, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	trust := filepath.Join(dir, "trust.json")
	data, _ := json.Marshal(policydistribution.TrustStore{Keys: []policydistribution.TrustKey{{KeyID: "k1", PublicKey: base64.StdEncoding.EncodeToString(pub)}}})
	if err := os.WriteFile(trust, data, 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a := Artifact{Metadata: Metadata{FormatVersion: FormatVersion, ModelID: "laya-security", Version: "2026.10.1", Digest: strings.Repeat("a", 64), Detector: "laya", Task: "prompt_security", RuntimeCompatibility: []string{"gateway-1"}, APIVersion: "semantic/v1", DatasetProvenanceDigest: strings.Repeat("b", 64), EvaluationProvenanceDigest: strings.Repeat("c", 64), TrainingWindowStart: now.Add(-time.Hour).Format(time.RFC3339Nano), TrainingWindowEnd: now.Add(-time.Minute).Format(time.RFC3339Nano), Owner: "security", Approval: "approved", ThresholdArtifactID: "security-thresholds", ThresholdArtifactVersion: 3, ThresholdDigest: strings.Repeat("d", 64), Signer: "release", KeyID: "k1", Created: now.Add(-time.Minute).Format(time.RFC3339Nano), Expires: now.Add(time.Hour).Format(time.RFC3339Nano), RolloutState: Registered, Synthetic: synthetic}}
	if err := SignMetadata(&a, priv); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(Config{StatePath: filepath.Join(dir, "state.json"), TrustStorePath: trust, Production: synthetic})
	if err != nil {
		t.Fatal(err)
	}
	return m, a, priv
}

func advance(t *testing.T, m *Manager, a Artifact, to State, rev uint64, id string, confirm bool) Record {
	t.Helper()
	r, err := m.Transition(Request{Artifact: a, Actor: "operator", Provenance: "test", IdempotencyKey: id, ExpectedRevision: rev, Confirm: confirm}, to)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLifecycleSignatureRotationAndTransitions(t *testing.T) {
	m, a, _ := fixture(t, false)
	r, err := m.Register(Request{Artifact: a, Actor: "operator", Provenance: "fixture", IdempotencyKey: "register"})
	if err != nil {
		t.Fatal(err)
	}
	if r.State != Registered {
		t.Fatal(r.State)
	}
	r = advance(t, m, a, Validated, 1, "validate", false)
	if r.State != Validated {
		t.Fatal(r.State)
	}
	r = advance(t, m, a, Shadow, 2, "shadow", false)
	r = advance(t, m, a, Canary, 3, "canary", false)
	r = advance(t, m, a, Promoted, 4, "promote", true)
	if r.State != Promoted {
		t.Fatal(r.State)
	}
	active, ok := m.Active()
	if !ok || active.State != Promoted {
		t.Fatal("active champion missing")
	}
	if _, err := m.Transition(Request{Artifact: a, Actor: "operator", Provenance: "stale", IdempotencyKey: "stale", ExpectedRevision: 1}, Paused); err == nil {
		t.Fatal("stale revision accepted")
	}
	if _, err := m.Transition(Request{Artifact: a, Actor: "operator", Provenance: "no-confirm", IdempotencyKey: "no-confirm"}, Revoked); err == nil {
		t.Fatal("revocation without confirmation accepted")
	}
	if _, err := m.Transition(Request{Artifact: a, Actor: "operator", Provenance: "repeat", IdempotencyKey: "promote"}, Promoted); err != nil {
		t.Fatal("idempotent request failed")
	}
	if len(m.History(0)) != 5 {
		t.Fatalf("history=%d", len(m.History(0)))
	}
}

func TestSyntheticPromotionBlockedInProductionAndActivationAtomic(t *testing.T) {
	m, a, _ := fixture(t, true)
	if _, err := m.Register(Request{Artifact: a, Actor: "operator", Provenance: "fixture", IdempotencyKey: "register"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Transition(Request{Artifact: a, Actor: "operator", Provenance: "validate", IdempotencyKey: "validate"}, Validated); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Transition(Request{Artifact: a, Actor: "operator", Provenance: "promote", IdempotencyKey: "promote", Confirm: true}, Promoted); err == nil {
		t.Fatal("synthetic promotion should be blocked")
	}
	m2, a2, _ := fixture(t, false)
	if _, err := m2.Register(Request{Artifact: a2, Actor: "operator", Provenance: "fixture", IdempotencyKey: "register"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Transition(Request{Artifact: a2, Actor: "operator", Provenance: "validate", IdempotencyKey: "validate"}, Validated); err != nil {
		t.Fatal(err)
	}
	m2.SetActivator(func(Activation) error { return os.ErrInvalid })
	if _, err := m2.Transition(Request{Artifact: a2, Actor: "operator", Provenance: "promote", IdempotencyKey: "promote", Confirm: true}, Promoted); err == nil {
		t.Fatal("activation failure not returned")
	}
	if _, ok := m2.Active(); ok {
		t.Fatal("failed activation changed active state")
	}
}

func TestFutureExpiredAndTamperedArtifactsRejected(t *testing.T) {
	m, a, _ := fixture(t, false)
	a.Metadata.Created = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if err := m.ValidateArtifact(a); err == nil {
		t.Fatal("future artifact accepted")
	}
	m, a, _ = fixture(t, false)
	a.Metadata.Digest = strings.Repeat("e", 64)
	if err := m.ValidateArtifact(a); err == nil {
		t.Fatal("tampered metadata accepted")
	}
}

func TestVerifiedIdentityCohortIsolation(t *testing.T) {
	if InCohort("candidate", "tenant-a", "app", false, 100) {
		t.Fatal("unverified identity entered cohort")
	}
	if !InCohort("candidate", "tenant-a", "app", true, 100) {
		t.Fatal("verified identity missing from full cohort")
	}
	if InCohort("candidate", "tenant-a", "app", true, 0) {
		t.Fatal("zero cohort admitted identity")
	}
	first := InCohort("candidate", "tenant-a", "app", true, 10)
	second := InCohort("candidate", "tenant-a", "app", true, 10)
	if first != second {
		t.Fatal("cohort assignment is not deterministic")
	}
}

func TestAutomatedRollbackUsesOnlyHealthyRetainedParent(t *testing.T) {
	m, first, priv := fixture(t, false)
	if _, err := m.Register(Request{Artifact: first, Actor: "operator", Provenance: "fixture", IdempotencyKey: "r1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Transition(Request{Artifact: first, Actor: "operator", Provenance: "validate", IdempotencyKey: "v1"}, Validated); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Transition(Request{Artifact: first, Actor: "operator", Provenance: "promote", IdempotencyKey: "p1", Confirm: true}, Promoted); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Metadata.ModelID = "laya-security-next"
	second.Metadata.Version = "2026.10.2"
	second.Metadata.Digest = strings.Repeat("e", 64)
	second.Metadata.Created = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	if err := SignMetadata(&second, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Register(Request{Artifact: second, Actor: "operator", Provenance: "fixture", IdempotencyKey: "r2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Transition(Request{Artifact: second, Actor: "operator", Provenance: "validate", IdempotencyKey: "v2"}, Validated); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Transition(Request{Artifact: second, Actor: "operator", Provenance: "promote", IdempotencyKey: "p2", Confirm: true}, Promoted); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyDriftAction(ActionRollback, "sustained", true); err != nil {
		t.Fatal(err)
	}
	active, ok := m.Active()
	if !ok || active.Artifact.Metadata.ModelID != first.Metadata.ModelID {
		t.Fatal("automated rollback did not use retained parent")
	}
	if err := m.ApplyDriftAction(ActionRollback, "unauthorized", false); err == nil {
		t.Fatal("unauthorized automated rollback accepted")
	}
}
