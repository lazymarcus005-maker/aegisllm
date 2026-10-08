// Package semantic contains the signed semantic-model control plane.
//
// It stores model metadata and bounded aggregate evidence only. Model weights,
// prompts, embeddings, labels, and dataset contents are deliberately outside
// this package and must remain in the model/evaluation systems that own them.
package semantic

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aegisllm/gateway/internal/policydistribution"
)

const FormatVersion = 1

type State string

const (
	Registered State = "registered"
	Validated  State = "validated"
	Shadow     State = "shadow"
	Canary     State = "canary"
	Promoted   State = "promoted"
	Paused     State = "paused"
	RolledBack State = "rolled_back"
	Retired    State = "retired"
	Revoked    State = "revoked"
)

type ModelRef struct {
	ID      string `json:"model_id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// InCohort deterministically assigns only verified identity to a bounded
// rollout. The gateway must pass identity derived by auth; no request header
// is consulted here.
func InCohort(seed, tenant, application string, verified bool, percentage int) bool {
	if !verified || percentage <= 0 {
		return false
	}
	if percentage > 100 {
		percentage = 100
	}
	sum := sha256.Sum256([]byte(seed + "\x00" + tenant + "\x00" + application))
	return (int(sum[0])<<8|int(sum[1]))%100 < percentage
}

type PolicyBinding struct {
	PolicyID      string `json:"policy_id"`
	PolicyVersion int    `json:"policy_version"`
	PolicyDigest  string `json:"policy_digest"`
}

// Metadata is the immutable, content-free registry contract. ThresholdDigest
// identifies an external threshold/calibration artifact; neither that file nor
// model weights are copied into gateway state.
type Metadata struct {
	FormatVersion              int             `json:"format_version"`
	ModelID                    string          `json:"model_id"`
	Version                    string          `json:"version"`
	Digest                     string          `json:"digest"`
	Detector                   string          `json:"detector"`
	Task                       string          `json:"task"`
	RuntimeCompatibility       []string        `json:"runtime_compatibility"`
	APIVersion                 string          `json:"api_version"`
	DatasetProvenanceDigest    string          `json:"dataset_provenance_digest"`
	EvaluationProvenanceDigest string          `json:"evaluation_provenance_digest"`
	TrainingWindowStart        string          `json:"training_window_start"`
	TrainingWindowEnd          string          `json:"training_window_end"`
	Owner                      string          `json:"owner"`
	Approval                   string          `json:"approval"`
	ThresholdArtifactID        string          `json:"threshold_artifact_id"`
	ThresholdArtifactVersion   int             `json:"threshold_artifact_version"`
	ThresholdDigest            string          `json:"threshold_digest"`
	Signer                     string          `json:"signer"`
	KeyID                      string          `json:"key_id"`
	Created                    string          `json:"created"`
	Expires                    string          `json:"expires"`
	RolloutState               State           `json:"rollout_state"`
	RollbackParent             *ModelRef       `json:"rollback_parent,omitempty"`
	PolicyBindings             []PolicyBinding `json:"policy_bindings,omitempty"`
	Synthetic                  bool            `json:"synthetic,omitempty"`
}

type Artifact struct {
	Metadata  Metadata `json:"metadata"`
	Signature []byte   `json:"signature"`
}

type Record struct {
	Artifact       Artifact  `json:"artifact"`
	State          State     `json:"state"`
	RollbackParent *ModelRef `json:"rollback_parent,omitempty"`
	Revision       uint64    `json:"revision"`
	RegisteredAt   string    `json:"registered_at"`
	ValidatedAt    string    `json:"validated_at,omitempty"`
	LastActor      string    `json:"last_actor"`
	LastProvenance string    `json:"last_provenance"`
}

type Transition struct {
	Model       ModelRef `json:"model"`
	From        State    `json:"from"`
	To          State    `json:"to"`
	Revision    uint64   `json:"revision"`
	Actor       string   `json:"actor"`
	Provenance  string   `json:"provenance"`
	Idempotency string   `json:"idempotency_key"`
	At          string   `json:"at"`
}

type persistentState struct {
	Revision uint64                `json:"revision"`
	Records  map[string]Record     `json:"records"`
	Active   *ModelRef             `json:"active,omitempty"`
	History  []Transition          `json:"history"`
	Seen     map[string]Transition `json:"seen_idempotency"`
}

type Config struct {
	StatePath      string
	TrustStorePath string
	Production     bool
	MaxRecords     int
	Clock          func() time.Time
	RuntimeVersion string
	SupportedAPI   []string
	Observer       func(Transition)
}

type Request struct {
	Artifact         Artifact
	Actor            string
	Provenance       string
	IdempotencyKey   string
	ExpectedRevision uint64
	Confirm          bool
}

type Manager struct {
	mu       sync.RWMutex
	cfg      Config
	trust    *policydistribution.TrustStore
	state    persistentState
	lastErr  string
	activate func(Activation) error
}

type Activation struct {
	Model            ModelRef
	ThresholdID      string
	ThresholdVersion int
	ThresholdDigest  string
	State            State
}

type RegistryStatus struct {
	Revision  uint64    `json:"revision"`
	Active    *ModelRef `json:"active,omitempty"`
	Records   int       `json:"records"`
	LastError string    `json:"last_error,omitempty"`
}

type RecordView struct {
	Model                      ModelRef  `json:"model"`
	Detector                   string    `json:"detector"`
	Task                       string    `json:"task"`
	RuntimeCompatibility       []string  `json:"runtime_compatibility,omitempty"`
	APIVersion                 string    `json:"api_version"`
	DatasetProvenanceDigest    string    `json:"dataset_provenance_digest"`
	EvaluationProvenanceDigest string    `json:"evaluation_provenance_digest"`
	TrainingWindowStart        string    `json:"training_window_start"`
	TrainingWindowEnd          string    `json:"training_window_end"`
	Owner                      string    `json:"owner"`
	Approval                   string    `json:"approval"`
	ThresholdArtifactID        string    `json:"threshold_artifact_id"`
	ThresholdArtifactVersion   int       `json:"threshold_artifact_version"`
	ThresholdDigest            string    `json:"threshold_digest"`
	Signer                     string    `json:"signer"`
	KeyID                      string    `json:"key_id"`
	Created                    string    `json:"created"`
	Expires                    string    `json:"expires"`
	State                      State     `json:"state"`
	RollbackParent             *ModelRef `json:"rollback_parent,omitempty"`
	Revision                   uint64    `json:"revision"`
	LastActor                  string    `json:"last_actor,omitempty"`
}

var digestPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

var allowedTransitions = map[State]map[State]bool{
	Registered: {Validated: true, Revoked: true},
	Validated:  {Shadow: true, Canary: true, Promoted: true, Revoked: true},
	Shadow:     {Canary: true, Paused: true, Revoked: true},
	Canary:     {Promoted: true, Paused: true, RolledBack: true, Revoked: true},
	Promoted:   {Paused: true, RolledBack: true, Retired: true, Revoked: true},
	Paused:     {Shadow: true, Canary: true, Promoted: true, RolledBack: true, Retired: true, Revoked: true},
	RolledBack: {Retired: true, Revoked: true},
	Retired:    {Revoked: true},
	Revoked:    {},
}

func NewManager(cfg Config) (*Manager, error) {
	if cfg.MaxRecords <= 0 {
		cfg.MaxRecords = 128
	}
	if cfg.MaxRecords > 4096 {
		return nil, errors.New("semantic registry max_records is too large")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.TrustStorePath == "" {
		return nil, errors.New("semantic registry trust store is required")
	}
	m := &Manager{cfg: cfg, trust: policydistribution.NewTrustStore(cfg.TrustStorePath), state: persistentState{Records: map[string]Record{}, Seen: map[string]Transition{}}}
	if cfg.StatePath != "" {
		if err := m.load(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func CanonicalMetadata(m Metadata) ([]byte, error) {
	if m.RuntimeCompatibility == nil {
		m.RuntimeCompatibility = []string{}
	}
	if m.PolicyBindings == nil {
		m.PolicyBindings = []PolicyBinding{}
	}
	return json.Marshal(m)
}

func MetadataDigest(m Metadata) (string, error) {
	b, err := CanonicalMetadata(m)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func SignMetadata(a *Artifact, key ed25519.PrivateKey) error {
	if a == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid semantic metadata signer")
	}
	b, err := CanonicalMetadata(a.Metadata)
	if err != nil {
		return err
	}
	a.Signature = ed25519.Sign(key, b)
	return nil
}

func (a Artifact) Verify(trust *policydistribution.TrustStore, now time.Time) error {
	if err := ValidateMetadata(a.Metadata, now, ""); err != nil {
		return err
	}
	if trust == nil {
		return errors.New("semantic metadata trust store is required")
	}
	key, err := trust.Key(a.Metadata.KeyID, now)
	if err != nil {
		return err
	}
	b, err := CanonicalMetadata(a.Metadata)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, b, a.Signature) {
		return errors.New("semantic metadata signature verification failed")
	}
	return nil
}

func ValidateMetadata(m Metadata, now time.Time, runtimeVersion string) error {
	if m.FormatVersion != FormatVersion || strings.TrimSpace(m.ModelID) == "" || !versionPattern.MatchString(m.ModelID) || !versionPattern.MatchString(m.Version) {
		return errors.New("semantic metadata format, model_id, or version is invalid")
	}
	for name, value := range map[string]string{"model digest": m.Digest, "dataset provenance digest": m.DatasetProvenanceDigest, "evaluation provenance digest": m.EvaluationProvenanceDigest, "threshold digest": m.ThresholdDigest} {
		if !digestPattern.MatchString(value) {
			return fmt.Errorf("semantic metadata %s is invalid", name)
		}
	}
	if strings.TrimSpace(m.Detector) == "" || strings.TrimSpace(m.Task) == "" || strings.TrimSpace(m.APIVersion) == "" || strings.TrimSpace(m.Owner) == "" || strings.TrimSpace(m.Approval) == "" || strings.TrimSpace(m.ThresholdArtifactID) == "" || m.ThresholdArtifactVersion <= 0 || strings.TrimSpace(m.Signer) == "" || strings.TrimSpace(m.KeyID) == "" {
		return errors.New("semantic metadata required fields are missing")
	}
	start, err := time.Parse(time.RFC3339Nano, m.TrainingWindowStart)
	if err != nil {
		return errors.New("semantic training window start is invalid")
	}
	end, err := time.Parse(time.RFC3339Nano, m.TrainingWindowEnd)
	if err != nil || !end.After(start) {
		return errors.New("semantic training window is invalid")
	}
	created, err := time.Parse(time.RFC3339Nano, m.Created)
	if err != nil {
		return errors.New("semantic creation timestamp is invalid")
	}
	expires, err := time.Parse(time.RFC3339Nano, m.Expires)
	if err != nil || !expires.After(created) {
		return errors.New("semantic expiry timestamp is invalid")
	}
	if !now.IsZero() {
		if created.After(now.Add(5 * time.Minute)) {
			return errors.New("semantic artifact is future-dated")
		}
		if !now.Before(expires) {
			return errors.New("semantic artifact is expired")
		}
	}
	if m.RolloutState != Registered && m.RolloutState != Validated && m.RolloutState != Shadow && m.RolloutState != Canary && m.RolloutState != Promoted && m.RolloutState != Paused && m.RolloutState != RolledBack && m.RolloutState != Retired && m.RolloutState != Revoked {
		return errors.New("semantic artifact rollout state is invalid")
	}
	if runtimeVersion != "" && len(m.RuntimeCompatibility) > 0 && !matchesRuntime(runtimeVersion, m.RuntimeCompatibility) {
		return errors.New("semantic model/runtime compatibility mismatch")
	}
	return nil
}

func matchesRuntime(value string, allowed []string) bool {
	for _, item := range allowed {
		if item == "*" || item == value {
			return true
		}
	}
	return false
}

func versionLess(a, b string) bool {
	if a == b {
		return false
	}
	parse := func(v string) []int {
		parts := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '+' })
		out := make([]int, len(parts))
		for i, p := range parts {
			n := 0
			for _, r := range p {
				if r < '0' || r > '9' {
					return nil
				}
				n = n*10 + int(r-'0')
			}
			out[i] = n
		}
		return out
	}
	x, y := parse(a), parse(b)
	if x == nil || y == nil {
		return a < b
	}
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func (m *Manager) SetActivator(fn func(Activation) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activate = fn
}

func (m *Manager) ActivateCurrent() error {
	m.mu.RLock()
	if m.state.Active == nil {
		m.mu.RUnlock()
		return errors.New("no active semantic model")
	}
	r, ok := m.state.Records[key(*m.state.Active)]
	fn := m.activate
	m.mu.RUnlock()
	if !ok || fn == nil {
		return errors.New("active semantic model is unavailable")
	}
	return fn(Activation{Model: refOf(r), ThresholdID: r.Artifact.Metadata.ThresholdArtifactID, ThresholdVersion: r.Artifact.Metadata.ThresholdArtifactVersion, ThresholdDigest: r.Artifact.Metadata.ThresholdDigest, State: r.State})
}
func (m *Manager) ValidateArtifact(a Artifact) error {
	if err := ValidateMetadata(a.Metadata, m.cfg.Clock().UTC(), m.cfg.RuntimeVersion); err != nil {
		return err
	}
	return a.Verify(m.trust, m.cfg.Clock().UTC())
}
func (m *Manager) Status() RegistryStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var active *ModelRef
	if m.state.Active != nil {
		v := *m.state.Active
		active = &v
	}
	return RegistryStatus{Revision: m.state.Revision, Active: active, Records: len(m.state.Records), LastError: m.lastErr}
}
func (m *Manager) Revision() uint64  { m.mu.RLock(); defer m.mu.RUnlock(); return m.state.Revision }
func (m *Manager) LastError() string { m.mu.RLock(); defer m.mu.RUnlock(); return m.lastErr }

func key(ref ModelRef) string { return ref.ID + "\x00" + ref.Version + "\x00" + ref.Digest }
func refOf(r Record) ModelRef {
	return ModelRef{ID: r.Artifact.Metadata.ModelID, Version: r.Artifact.Metadata.Version, Digest: r.Artifact.Metadata.Digest}
}

func (m *Manager) Register(req Request) (Record, error) {
	if req.Actor == "" || req.Provenance == "" || req.IdempotencyKey == "" {
		return Record{}, errors.New("actor, provenance, and idempotency key are required")
	}
	if req.Artifact.Metadata.RolloutState != Registered {
		return Record{}, errors.New("new semantic artifact must be registered")
	}
	if err := ValidateMetadata(req.Artifact.Metadata, m.cfg.Clock().UTC(), m.cfg.RuntimeVersion); err != nil {
		return Record{}, err
	}
	if err := req.Artifact.Verify(m.trust, m.cfg.Clock().UTC()); err != nil {
		return Record{}, err
	}
	return m.mutate(req, Registered)
}

func (m *Manager) Transition(req Request, to State) (Record, error) {
	if to == Promoted || to == Revoked || to == RolledBack {
		m.mu.RLock()
		_, alreadyApplied := m.state.Seen[req.IdempotencyKey]
		m.mu.RUnlock()
		if !req.Confirm && !alreadyApplied {
			return Record{}, errors.New("explicit confirmation is required")
		}
	}
	return m.mutate(req, to)
}

func (m *Manager) mutate(req Request, to State) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.state.Seen[req.IdempotencyKey]; ok {
		rec, exists := m.state.Records[key(old.Model)]
		if exists {
			return rec, nil
		}
		return Record{}, nil
	}
	if req.ExpectedRevision != 0 && req.ExpectedRevision != m.state.Revision {
		return Record{}, errors.New("semantic registry stale revision")
	}
	ref := ModelRef{ID: req.Artifact.Metadata.ModelID, Version: req.Artifact.Metadata.Version, Digest: req.Artifact.Metadata.Digest}
	for _, existingRecord := range m.state.Records {
		existingRef := refOf(existingRecord)
		if existingRef.ID == ref.ID && existingRef.Version == ref.Version && existingRef.Digest != ref.Digest {
			return Record{}, errors.New("semantic model version is already bound to another digest")
		}
	}
	record, exists := m.state.Records[key(ref)]
	previous := record
	previousActive := m.state.Active
	previousRevision := m.state.Revision
	previousHistoryLen := len(m.state.History)
	if !exists {
		if to != Registered {
			return Record{}, errors.New("semantic model is not registered")
		}
		if len(m.state.Records) >= m.cfg.MaxRecords {
			return Record{}, errors.New("semantic registry capacity reached")
		}
		record = Record{Artifact: req.Artifact, State: Registered, Revision: 1, RegisteredAt: m.cfg.Clock().UTC().Format(time.RFC3339Nano)}
	} else {
		oldMeta, oldErr := CanonicalMetadata(record.Artifact.Metadata)
		newMeta, newErr := CanonicalMetadata(req.Artifact.Metadata)
		if oldErr != nil || newErr != nil || !bytes.Equal(oldMeta, newMeta) {
			return Record{}, errors.New("semantic model metadata is immutable")
		}
		if !allowedTransitions[record.State][to] {
			return Record{}, fmt.Errorf("invalid semantic transition %s to %s", record.State, to)
		}
		record.State, record.Revision = to, record.Revision+1
	}
	if to == Registered && exists {
		return Record{}, errors.New("semantic model is already registered")
	}
	if to == Validated {
		record.ValidatedAt = m.cfg.Clock().UTC().Format(time.RFC3339Nano)
	}
	if to == Promoted {
		if err := m.validateForPromotion(record); err != nil {
			return Record{}, err
		}
		if m.state.Active != nil && m.state.Active.ID == ref.ID && versionLess(ref.Version, m.state.Active.Version) {
			return Record{}, errors.New("semantic model downgrade is not permitted")
		}
		if m.state.Active != nil && key(*m.state.Active) != key(ref) {
			record.RollbackParent = m.state.Active
		}
		m.state.Active = &ref
	}
	if to == RolledBack {
		if err := m.validateRollbackTarget(record); err != nil {
			return Record{}, err
		}
		m.state.Active = &ref
	}
	record.LastActor, record.LastProvenance = req.Actor, req.Provenance
	if !exists {
		m.state.Records[key(ref)] = record
	}
	m.state.Revision++
	transition := Transition{Model: ref, To: to, Revision: m.state.Revision, Actor: req.Actor, Provenance: req.Provenance, Idempotency: req.IdempotencyKey, At: m.cfg.Clock().UTC().Format(time.RFC3339Nano)}
	if exists {
		transition.From = previous.State
		m.state.Records[key(ref)] = record
	}
	m.state.Seen[req.IdempotencyKey] = transition
	m.state.History = append(m.state.History, transition)
	if to == Promoted || to == RolledBack {
		if m.activate != nil {
			if err := m.activate(Activation{Model: ref, ThresholdID: record.Artifact.Metadata.ThresholdArtifactID, ThresholdVersion: record.Artifact.Metadata.ThresholdArtifactVersion, ThresholdDigest: record.Artifact.Metadata.ThresholdDigest, State: to}); err != nil {
				if exists {
					m.state.Records[key(ref)] = previous
				} else {
					delete(m.state.Records, key(ref))
				}
				m.state.Active = previousActive
				m.state.Revision = previousRevision
				m.state.History = m.state.History[:previousHistoryLen]
				delete(m.state.Seen, req.IdempotencyKey)
				return Record{}, err
			}
		}
	}
	if err := m.persistLocked(); err != nil {
		return Record{}, err
	}
	if m.cfg.Observer != nil {
		m.cfg.Observer(transition)
	}
	return record, nil
}

func (m *Manager) validateForPromotion(r Record) error {
	if err := ValidateMetadata(r.Artifact.Metadata, m.cfg.Clock().UTC(), m.cfg.RuntimeVersion); err != nil {
		return err
	}
	if err := r.Artifact.Verify(m.trust, m.cfg.Clock().UTC()); err != nil {
		return err
	}
	if r.Artifact.Metadata.Synthetic && m.cfg.Production {
		return errors.New("synthetic semantic artifact cannot be promoted in production")
	}
	if r.Artifact.Metadata.Approval == "" {
		return errors.New("semantic approval is required")
	}
	return nil
}
func (m *Manager) validateRollbackTarget(r Record) error {
	if r.State == Revoked || r.State == Retired || r.State == Paused {
		return errors.New("rollback target is not healthy")
	}
	return m.validateForPromotion(r)
}

func (m *Manager) Get(ref ModelRef) (Record, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.state.Records[key(ref)]
	return r, ok
}
func (m *Manager) List(limit int) []Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > m.cfg.MaxRecords {
		limit = m.cfg.MaxRecords
	}
	out := make([]Record, 0, len(m.state.Records))
	for _, r := range m.state.Records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Artifact.Metadata.ModelID < out[j].Artifact.Metadata.ModelID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
func View(r Record) RecordView {
	md := r.Artifact.Metadata
	return RecordView{Model: refOf(r), Detector: md.Detector, Task: md.Task, RuntimeCompatibility: append([]string(nil), md.RuntimeCompatibility...), APIVersion: md.APIVersion, DatasetProvenanceDigest: md.DatasetProvenanceDigest, EvaluationProvenanceDigest: md.EvaluationProvenanceDigest, TrainingWindowStart: md.TrainingWindowStart, TrainingWindowEnd: md.TrainingWindowEnd, Owner: md.Owner, Approval: md.Approval, ThresholdArtifactID: md.ThresholdArtifactID, ThresholdArtifactVersion: md.ThresholdArtifactVersion, ThresholdDigest: md.ThresholdDigest, Signer: md.Signer, KeyID: md.KeyID, Created: md.Created, Expires: md.Expires, State: r.State, RollbackParent: r.RollbackParent, Revision: r.Revision, LastActor: r.LastActor}
}
func (m *Manager) Active() (Record, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state.Active == nil {
		return Record{}, false
	}
	r, ok := m.state.Records[key(*m.state.Active)]
	return r, ok
}
func (m *Manager) History(limit int) []Transition {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := append([]Transition(nil), m.state.History...)
	if limit <= 0 || limit > len(out) {
		limit = len(out)
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func (m *Manager) BindPolicy(binding PolicyBinding, ref ModelRef) error {
	if binding.PolicyID == "" || binding.PolicyVersion <= 0 || !digestPattern.MatchString(binding.PolicyDigest) {
		return errors.New("semantic policy binding is invalid")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.state.Records[key(ref)]
	if !ok || r.State != Promoted {
		return errors.New("policy cannot reference an unpromoted semantic model")
	}
	for _, b := range r.Artifact.Metadata.PolicyBindings {
		if b == binding {
			return nil
		}
	}
	return errors.New("semantic model is not bound to policy snapshot")
}

// ApplyDriftAction is the only automated mutation entrypoint. Policy
// authorization is explicit, and rollback always targets the retained parent
// recorded during champion promotion; callers cannot choose an arbitrary
// model from an untrusted drift signal.
func (m *Manager) ApplyDriftAction(action Action, reason string, policyAuthorized bool) error {
	if !policyAuthorized || strings.TrimSpace(reason) == "" {
		return errors.New("drift action is not policy-authorized")
	}
	if action != ActionRollback {
		return fmt.Errorf("drift action %q has no registry mutation", action)
	}
	m.mu.RLock()
	if m.state.Active == nil {
		m.mu.RUnlock()
		return errors.New("no active semantic champion")
	}
	current, ok := m.state.Records[key(*m.state.Active)]
	parent := current.RollbackParent
	rev := m.state.Revision
	m.mu.RUnlock()
	if !ok || parent == nil {
		return errors.New("safe rollback target is unavailable")
	}
	target, ok := m.Get(*parent)
	if !ok {
		return errors.New("safe rollback target is not retained")
	}
	return func() error {
		_, err := m.Transition(Request{Artifact: target.Artifact, Actor: "drift-monitor", Provenance: "drift:" + reason, IdempotencyKey: "drift-rollback:" + parent.ID + ":" + parent.Version + ":" + parent.Digest, ExpectedRevision: rev, Confirm: true}, RolledBack)
		return err
	}()
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.cfg.StatePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m.state); err != nil {
		return fmt.Errorf("semantic registry state: %w", err)
	}
	if m.state.Records == nil {
		m.state.Records = map[string]Record{}
	}
	if m.state.Seen == nil {
		m.state.Seen = map[string]Transition{}
	}
	for _, record := range m.state.Records {
		if err := ValidateMetadata(record.Artifact.Metadata, time.Time{}, m.cfg.RuntimeVersion); err != nil {
			return fmt.Errorf("semantic registry record invalid: %w", err)
		}
	}
	if m.state.Active != nil {
		record, ok := m.state.Records[key(*m.state.Active)]
		if !ok || record.State != Promoted {
			return errors.New("semantic registry active champion is invalid")
		}
		if err := m.ValidateArtifact(record.Artifact); err != nil {
			return fmt.Errorf("semantic registry active champion rejected: %w", err)
		}
	}
	return nil
}
func (m *Manager) persistLocked() error {
	if m.cfg.StatePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.cfg.StatePath), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.cfg.StatePath + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.cfg.StatePath)
}
