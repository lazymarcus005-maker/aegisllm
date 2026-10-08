// Package quarantine implements the policy-bound incident containment plane.
//
// The package is deliberately content-free: signals carry bounded reason
// codes and digests of trusted evidence, never prompts, documents, secrets,
// credentials, or caller-controlled labels. State keys are digests and every
// mutation is revision checked.
package quarantine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	ReasonSecretExfiltration    = "secret_exfiltration" // #nosec G101 -- bounded incident reason code, not a credential.
	ReasonDetectorEvasion       = "detector_evasion"
	ReasonRAGCrossScope         = "rag_cross_scope_access"
	ReasonToolPolicyViolation   = "tool_policy_violation"
	ReasonTokenReidentification = "token_reidentification_abuse"
	ReasonAuthAnomaly           = "auth_anomaly"
	ReasonProviderIntegrity     = "provider_integrity_failure"
	ReasonOperatorAction        = "operator_action"

	LevelObserve     = "observe"
	LevelThrottle    = "throttle"
	LevelIsolate     = "isolate"
	LevelDisable     = "disable"
	LevelHumanReview = "require_human_review"

	ScopeSession     = "session"
	ScopeUser        = "user"
	ScopeApplication = "application"
	ScopeTenant      = "tenant"
	ScopeTool        = "tool"
	ScopeServer      = "server"
	ScopeProvider    = "provider"
	ScopeRoute       = "route"
)

var (
	ErrNotFound         = errors.New("quarantine state not found")
	ErrConflict         = errors.New("quarantine revision conflict")
	ErrStoreUnavailable = errors.New("quarantine state store unavailable")
	ErrInvalidSignal    = errors.New("invalid trusted quarantine signal")
	ErrConfirmation     = errors.New("explicit confirmation is required")
	ErrCrossTenant      = errors.New("cross-tenant quarantine is not permitted")
	ErrStateLimit       = errors.New("quarantine state capacity exceeded")
)

var validReasons = map[string]bool{
	ReasonSecretExfiltration: true, ReasonDetectorEvasion: true,
	ReasonRAGCrossScope: true, ReasonToolPolicyViolation: true,
	ReasonTokenReidentification: true, ReasonAuthAnomaly: true,
	ReasonProviderIntegrity: true, ReasonOperatorAction: true,
}
var validLevels = map[string]bool{LevelObserve: true, LevelThrottle: true, LevelIsolate: true, LevelDisable: true, LevelHumanReview: true}
var validScopes = map[string]bool{ScopeSession: true, ScopeUser: true, ScopeApplication: true, ScopeTenant: true, ScopeTool: true, ScopeServer: true, ScopeProvider: true, ScopeRoute: true}

type Policy struct {
	Enabled      bool
	MaxTTL       time.Duration
	ProbationTTL time.Duration
	MaxStates    int
	Default      Rule
	Rules        []Rule
}

type Rule struct {
	Reason     string
	Level      string
	Scope      string
	Threshold  int
	Window     time.Duration
	Cooldown   time.Duration
	TTL        time.Duration
	AllowBroad bool
}

func DefaultPolicy() Policy {
	return Policy{Enabled: true, MaxTTL: time.Hour, ProbationTTL: 10 * time.Minute, MaxStates: 10000,
		Default: Rule{Reason: "default", Level: LevelObserve, Scope: ScopeSession, Threshold: 3, Window: time.Minute, Cooldown: time.Minute, TTL: 10 * time.Minute}}
}

func (p Policy) Validate() error {
	if p.MaxTTL <= 0 || p.MaxTTL > 24*time.Hour || p.ProbationTTL <= 0 || p.ProbationTTL > 24*time.Hour || p.MaxStates <= 0 {
		return errors.New("quarantine policy bounds are invalid")
	}
	if err := validateRule(p.Default, true); err != nil {
		return fmt.Errorf("quarantine default: %w", err)
	}
	seen := map[string]bool{}
	for i, r := range p.Rules {
		if !validReasons[r.Reason] {
			return fmt.Errorf("quarantine rule %d has invalid reason", i)
		}
		if seen[r.Reason] {
			return fmt.Errorf("duplicate quarantine rule %q", r.Reason)
		}
		seen[r.Reason] = true
		if err := validateRule(r, false); err != nil {
			return fmt.Errorf("quarantine rule %d: %w", i, err)
		}
	}
	return nil
}

func validateRule(r Rule, allowDefault bool) error {
	if !validLevels[r.Level] || !validScopes[r.Scope] || r.Threshold <= 0 || r.Threshold > 1000 || r.Window <= 0 || r.Window > 24*time.Hour || r.Cooldown < 0 || r.Cooldown > 24*time.Hour || r.TTL <= 0 || r.TTL > 24*time.Hour {
		return errors.New("level, scope, threshold, window, cooldown, or TTL is invalid")
	}
	if (r.Scope == ScopeTenant || r.Scope == ScopeProvider) && !r.AllowBroad && r.Threshold < 3 {
		return errors.New("broad quarantine requires threshold >= 3 and allow_broad")
	}
	if allowDefault && r.Reason != "default" {
		return errors.New("default rule reason must be default")
	}
	return nil
}

type Snapshot struct {
	ID      string
	Version int
	Hash    string
}

type Identity struct{ Tenant, Application, Subject, Session string }
type Resource struct{ Tool, Server, Provider, Route, Endpoint string }
type EvidenceRef struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

type Signal struct {
	Reason         string
	Identity       Identity
	Resource       Resource
	Evidence       []EvidenceRef
	Policy         Snapshot
	IdempotencyKey string
	Trusted        bool
	At             time.Time
}

type Status string

const (
	StatusActive       Status = "active"
	StatusAcknowledged Status = "acknowledged"
	StatusProbation    Status = "probation"
	StatusReleased     Status = "released"
)

type State struct {
	ID             string            `json:"quarantine_id"`
	KeyDigest      string            `json:"-"`
	TenantDigest   string            `json:"tenant_digest"`
	Scope          string            `json:"scope"`
	TargetDigest   string            `json:"target_digest,omitempty"`
	ScopeKeys      map[string]string `json:"scope_keys,omitempty"`
	Level          string            `json:"level"`
	Reason         string            `json:"reason_code"`
	Evidence       []EvidenceRef     `json:"evidence_refs,omitempty"`
	Policy         Snapshot          `json:"policy_snapshot"`
	Actor          string            `json:"actor,omitempty"`
	Provenance     string            `json:"provenance"`
	StartedAt      time.Time         `json:"started_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	ProbationUntil time.Time         `json:"probation_until,omitempty"`
	Revision       uint64            `json:"revision"`
	SignalCount    int               `json:"signal_count"`
	WindowStarted  time.Time         `json:"window_started"`
	LastSignalAt   time.Time         `json:"last_signal_at"`
	Status         Status            `json:"status"`
	SeenSignals    []string          `json:"-"`
}

type Store interface {
	Get(context.Context, string) (State, error)
	Put(context.Context, string, uint64, State) error
	List(context.Context) ([]State, error)
	Healthy(context.Context) error
}

type MemoryStore struct {
	mu     sync.RWMutex
	states map[string]State
	failed atomic.Bool
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{states: map[string]State{}} }
func (s *MemoryStore) unavailable() error {
	if s.failed.Load() {
		return ErrStoreUnavailable
	}
	return nil
}
func (s *MemoryStore) SetFailure(failed bool)        { s.failed.Store(failed) }
func (s *MemoryStore) Healthy(context.Context) error { return s.unavailable() }
func (s *MemoryStore) Get(_ context.Context, key string) (State, error) {
	if err := s.unavailable(); err != nil {
		return State{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.states[key]
	if !ok {
		return State{}, ErrNotFound
	}
	return cloneState(v), nil
}
func (s *MemoryStore) Put(_ context.Context, key string, expected uint64, value State) error {
	if err := s.unavailable(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.states[key]
	if expected == 0 {
		if ok {
			return ErrConflict
		}
	} else if !ok || current.Revision != expected {
		return ErrConflict
	}
	s.states[key] = cloneState(value)
	return nil
}
func (s *MemoryStore) List(_ context.Context) ([]State, error) {
	if err := s.unavailable(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]State, 0, len(s.states))
	for _, v := range s.states {
		out = append(out, cloneState(v))
	}
	return out, nil
}

type RedisStore struct {
	client redis.UniversalClient
	prefix string
}

func NewRedisStore(client redis.UniversalClient, prefix string) (*RedisStore, error) {
	if client == nil {
		return nil, errors.New("redis client is required")
	}
	if strings.TrimSpace(prefix) == "" {
		prefix = "quarantine"
	}
	return &RedisStore{client: client, prefix: prefix}, nil
}
func (s *RedisStore) key(k string) string { return s.prefix + ":" + k }
func (s *RedisStore) Healthy(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}
func (s *RedisStore) Get(ctx context.Context, key string) (State, error) {
	var v State
	b, err := s.client.Get(ctx, s.key(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, ErrStoreUnavailable
	}
	if json.Unmarshal(b, &v) != nil {
		return v, ErrStoreUnavailable
	}
	v.KeyDigest = key
	return v, nil
}
func (s *RedisStore) Put(ctx context.Context, key string, expected uint64, value State) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	redisKey := s.key(key)
	err = s.client.Watch(ctx, func(tx *redis.Tx) error {
		current, err := tx.Get(ctx, redisKey).Bytes()
		exists := err == nil
		if err != nil && !errors.Is(err, redis.Nil) {
			return ErrStoreUnavailable
		}
		if expected == 0 && exists {
			return ErrConflict
		}
		if expected > 0 {
			if !exists {
				return ErrConflict
			}
			var prior State
			if json.Unmarshal(current, &prior) != nil || prior.Revision != expected {
				return ErrConflict
			}
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.Set(ctx, redisKey, b, 0); return nil })
		return err
	}, redisKey)
	if errors.Is(err, redis.TxFailedErr) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	return nil
}
func (s *RedisStore) List(ctx context.Context) ([]State, error) {
	var out []State
	iter := s.client.Scan(ctx, 0, s.prefix+":*", 100).Iterator()
	for iter.Next(ctx) {
		v, err := s.Get(ctx, strings.TrimPrefix(iter.Val(), s.prefix+":"))
		if err == nil {
			out = append(out, v)
		} else if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	if err := iter.Err(); err != nil {
		return nil, ErrStoreUnavailable
	}
	return out, nil
}

type Decision struct {
	Allowed  bool
	Throttle bool
	Code     string
	StateID  string
	Scope    string
	Level    string
}
type Summary struct {
	Active, Acknowledged, Probation, Released int
	ByReason                                  map[string]int
	ByScope                                   map[string]int
}
type Gate func(Resource) bool

type Manager struct {
	store      Store
	policy     atomic.Pointer[Policy]
	clock      func() time.Time
	failClosed bool
	gate       Gate
	idCounter  atomic.Uint64
	observerMu sync.RWMutex
	observer   func(State)
}

func NewManager(store Store, p Policy, failClosed bool) (*Manager, error) {
	if store == nil {
		return nil, errors.New("quarantine store is required")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	m := &Manager{store: store, clock: time.Now, failClosed: failClosed}
	m.policy.Store(&p)
	return m, nil
}
func (m *Manager) SetClock(clock func() time.Time) {
	if clock != nil {
		m.clock = clock
	}
}
func (m *Manager) SetPolicy(p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	m.policy.Store(&p)
	return nil
}
func (m *Manager) SetHealthGate(g Gate) { m.gate = g }
func (m *Manager) SetObserver(observer func(State)) {
	m.observerMu.Lock()
	m.observer = observer
	m.observerMu.Unlock()
}
func (m *Manager) notify(state State) {
	m.observerMu.RLock()
	observer := m.observer
	m.observerMu.RUnlock()
	if observer != nil {
		observer(cloneState(state))
	}
}
func (m *Manager) Ready(ctx context.Context) error { return m.store.Healthy(ctx) }
func (m *Manager) policyFor(reason string) Rule {
	p := m.policy.Load()
	if p == nil {
		return DefaultPolicy().Default
	}
	for _, r := range p.Rules {
		if r.Reason == reason {
			return r
		}
	}
	return p.Default
}

func digest(value string) string       { h := sha256.Sum256([]byte(value)); return hex.EncodeToString(h[:]) }
func canonical(parts ...string) string { return strings.Join(parts, "\x00") }
func identityDigest(v string) string {
	if v == "" {
		return ""
	}
	return digest(v)
}

// TenantDigest exposes the non-reversible tenant binding used for operator
// authorization checks; callers never receive or persist the raw tenant here.
func TenantDigest(tenant string) string { return identityDigest(tenant) }
func signalDigest(s Signal) string {
	if s.IdempotencyKey != "" {
		return digest(s.IdempotencyKey)
	}
	return digest(canonical(s.Reason, s.Identity.Tenant, s.Identity.Application, s.Identity.Subject, s.Identity.Session, s.Resource.Tool, s.Resource.Server, s.Resource.Provider, s.Resource.Route))
}
func keyFor(id Identity, r Resource, scope string) (string, string) {
	tenant := identityDigest(id.Tenant)
	target := ""
	switch scope {
	case ScopeSession:
		target = digest(canonical(id.Application, id.Subject, id.Session))
	case ScopeUser:
		target = digest(canonical(id.Application, id.Subject))
	case ScopeApplication:
		target = digest(id.Application)
	case ScopeTenant:
		target = tenant
	case ScopeTool:
		target = digest(r.Tool)
	case ScopeServer:
		target = digest(r.Server)
	case ScopeProvider:
		target = digest(r.Provider)
	case ScopeRoute:
		target = digest(r.Route)
	}
	return digest(canonical(tenant, scope, target)), target
}
func scopeKeys(id Identity, r Resource) map[string]string {
	out := map[string]string{}
	for _, scope := range []string{ScopeSession, ScopeUser, ScopeApplication, ScopeTenant, ScopeTool, ScopeServer, ScopeProvider, ScopeRoute} {
		key, _ := keyFor(id, r, scope)
		out[scope] = key
	}
	return out
}
func validIdentity(i Identity) bool { return strings.TrimSpace(i.Tenant) != "" }
func validEvidence(e []EvidenceRef) bool {
	if len(e) > 8 {
		return false
	}
	for _, v := range e {
		if v.Kind == "" || len(v.Kind) > 32 || len(v.Digest) != 64 {
			return false
		}
		if _, err := hex.DecodeString(v.Digest); err != nil {
			return false
		}
	}
	return true
}

func (m *Manager) Observe(ctx context.Context, sig Signal) (State, bool, error) {
	for attempt := 0; attempt < 8; attempt++ {
		state, created, err := m.observeOnce(ctx, sig)
		if !errors.Is(err, ErrConflict) {
			return state, created, err
		}
	}
	return State{}, false, ErrConflict
}

func (m *Manager) observeOnce(ctx context.Context, sig Signal) (State, bool, error) {
	if p := m.policy.Load(); p == nil || !p.Enabled {
		return State{}, false, nil
	}
	if !sig.Trusted || !validReasons[sig.Reason] || !validIdentity(sig.Identity) || !validEvidence(sig.Evidence) {
		return State{}, false, ErrInvalidSignal
	}
	rule := m.policyFor(sig.Reason)
	if !validLevels[rule.Level] {
		return State{}, false, nil
	}
	if rule.Level == LevelObserve {
		return State{}, false, nil
	}
	now := sig.At
	if now.IsZero() {
		now = m.clock().UTC()
	}
	key, target := keyFor(sig.Identity, sig.Resource, rule.Scope)
	tenant := identityDigest(sig.Identity.Tenant)
	state, err := m.store.Get(ctx, key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return State{}, false, err
	}
	exists := err == nil
	if !exists {
		if states, listErr := m.store.List(ctx); listErr != nil {
			return State{}, false, listErr
		} else if len(states) >= m.policy.Load().MaxStates {
			return State{}, false, ErrStateLimit
		}
	}
	if exists && contains(state.SeenSignals, signalDigest(sig)) {
		return state, false, nil
	}
	if !exists {
		state = State{ID: m.newID(), KeyDigest: key, TenantDigest: tenant, Scope: rule.Scope, TargetDigest: target, ScopeKeys: scopeKeys(sig.Identity, sig.Resource), Level: rule.Level, Reason: sig.Reason, Evidence: boundedEvidence(sig.Evidence), Policy: sig.Policy, Actor: digest("system"), Provenance: "trusted_server", StartedAt: now, WindowStarted: now, Status: StatusActive}
	}
	if !exists || now.Sub(state.WindowStarted) > rule.Window {
		state.SignalCount = 0
		state.WindowStarted = now
	}
	if rule.Cooldown > 0 && exists && state.SignalCount >= rule.Threshold && now.Sub(state.LastSignalAt) < rule.Cooldown {
		state.SeenSignals = appendBounded(state.SeenSignals, signalDigest(sig), 32)
		state.Revision++
		state.LastSignalAt = now
		if err = m.store.Put(ctx, key, state.Revision-1, state); err != nil {
			return State{}, false, err
		}
		return state, false, nil
	}
	state.SignalCount++
	state.LastSignalAt = now
	state.SeenSignals = appendBounded(state.SeenSignals, signalDigest(sig), 32)
	state.Evidence = boundedEvidence(append(state.Evidence, sig.Evidence...))
	state.Policy = sig.Policy
	if state.SignalCount < rule.Threshold {
		if !exists {
			state.Revision = 1
		} else {
			state.Revision++
		}
		if err = m.store.Put(ctx, key, func() uint64 {
			if exists {
				return state.Revision - 1
			}
			return 0
		}(), state); err != nil {
			return State{}, false, err
		}
		return state, false, nil
	}
	if exists && state.Status == StatusActive && state.ExpiresAt.After(now) {
		state.Revision++
		if err = m.store.Put(ctx, key, state.Revision-1, state); err != nil {
			return State{}, false, err
		}
		return state, false, nil
	}
	p := m.policy.Load()
	ttl := rule.TTL
	if ttl > p.MaxTTL {
		ttl = p.MaxTTL
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	state.ExpiresAt = now.Add(ttl)
	state.Status = StatusActive
	state.Level = rule.Level
	state.Revision++
	if !exists {
		state.Revision = 1
	}
	if err = m.store.Put(ctx, key, func() uint64 {
		if exists {
			return state.Revision - 1
		}
		return 0
	}(), state); err != nil {
		return State{}, false, err
	}
	m.notify(state)
	return state, true, nil
}

func (m *Manager) newID() string {
	n := m.idCounter.Add(1)
	return fmt.Sprintf("qtn-%d-%d", m.clock().UnixNano(), n)
}
func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
func appendBounded(xs []string, v string, max int) []string {
	if contains(xs, v) {
		return xs
	}
	xs = append(xs, v)
	if len(xs) > max {
		xs = xs[len(xs)-max:]
	}
	return xs
}
func boundedEvidence(xs []EvidenceRef) []EvidenceRef {
	out := make([]EvidenceRef, 0, 8)
	seen := map[string]bool{}
	for _, v := range xs {
		if len(out) >= 8 {
			break
		}
		v.Kind = bounded(v.Kind, 32)
		if !validEvidence([]EvidenceRef{v}) || seen[v.Kind+v.Digest] {
			continue
		}
		seen[v.Kind+v.Digest] = true
		out = append(out, v)
	}
	return out
}
func bounded(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func (m *Manager) Check(ctx context.Context, id Identity, r Resource) (Decision, error) {
	if !validIdentity(id) {
		// Unauthenticated development/shadow probes cannot be mapped to a
		// quarantine key. Authentication is enforced before protected
		// production routes; allowing this no-identity check here prevents the
		// containment feature from turning an explicitly configured local probe
		// into a blanket outage. Untrusted callers still cannot create signals.
		return Decision{Allowed: true}, nil
	}
	pairs := []struct {
		scope    string
		resource Resource
	}{{ScopeTenant, r}, {ScopeApplication, r}, {ScopeUser, r}, {ScopeSession, r}, {ScopeTool, r}, {ScopeServer, r}, {ScopeProvider, r}, {ScopeRoute, r}}
	best := Decision{Allowed: true}
	rank := map[string]int{ScopeTenant: 8, ScopeApplication: 7, ScopeUser: 6, ScopeSession: 5, ScopeProvider: 4, ScopeServer: 4, ScopeTool: 4, ScopeRoute: 4}
	for _, pair := range pairs {
		if pair.scope == ScopeSession && id.Session == "" {
			continue
		}
		if pair.scope == ScopeUser && id.Subject == "" {
			continue
		}
		if pair.scope == ScopeApplication && id.Application == "" {
			continue
		}
		if pair.scope == ScopeTool && r.Tool == "" {
			continue
		}
		if pair.scope == ScopeServer && r.Server == "" {
			continue
		}
		if pair.scope == ScopeProvider && r.Provider == "" {
			continue
		}
		if pair.scope == ScopeRoute && r.Route == "" {
			continue
		}
		key, _ := keyFor(id, pair.resource, pair.scope)
		st, err := m.store.Get(ctx, key)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			if m.failClosed {
				return Decision{Allowed: false, Code: "QUARANTINE_STATE_UNAVAILABLE"}, err
			}
			continue
		}
		now := m.clock().UTC()
		if st.Status == StatusReleased || st.Scope != pair.scope {
			continue
		}
		if st.Status == StatusProbation {
			if now.Before(st.ProbationUntil) || m.gate == nil || !m.gate(r) {
				if stronger(Decision{Level: st.Level, Scope: st.Scope}, best, rank) {
					best = Decision{Allowed: false, Code: "QUARANTINE_PROBATION", StateID: st.ID, Scope: st.Scope, Level: st.Level}
				}
			}
			continue
		}
		if st.ExpiresAt.IsZero() || now.Before(st.ExpiresAt) {
			candidate := Decision{Allowed: false, Code: "QUARANTINED", StateID: st.ID, Scope: st.Scope, Level: st.Level}
			if st.Level == LevelThrottle {
				candidate.Throttle = true
				candidate.Code = "QUARANTINE_THROTTLED"
			}
			if st.Level == LevelObserve {
				candidate.Allowed = true
			}
			if !candidate.Allowed && stronger(candidate, best, rank) {
				best = candidate
			}
			continue
		}
		if pair.scope == ScopeProvider || pair.scope == ScopeRoute || pair.scope == ScopeTool || pair.scope == ScopeServer {
			st.Status = StatusProbation
			st.ProbationUntil = now.Add(m.policy.Load().ProbationTTL)
			st.Revision++
			_ = m.store.Put(ctx, key, st.Revision-1, st)
			best = Decision{Allowed: false, Code: "QUARANTINE_PROBATION", StateID: st.ID, Scope: st.Scope, Level: st.Level}
		}
	}
	return best, nil
}

func stronger(candidate, current Decision, rank map[string]int) bool {
	strength := func(level string) int {
		switch level {
		case LevelDisable, LevelHumanReview:
			return 4
		case LevelIsolate:
			return 3
		case LevelThrottle:
			return 2
		case LevelObserve:
			return 1
		}
		return 0
	}
	if strength(candidate.Level) != strength(current.Level) {
		return strength(candidate.Level) > strength(current.Level)
	}
	return rank[candidate.Scope] >= rank[current.Scope]
}

func (m *Manager) ListSummary(ctx context.Context) (Summary, error) {
	states, err := m.store.List(ctx)
	if err != nil {
		return Summary{}, err
	}
	out := Summary{ByReason: map[string]int{}, ByScope: map[string]int{}}
	for _, s := range states {
		switch s.Status {
		case StatusActive:
			out.Active++
		case StatusAcknowledged:
			out.Acknowledged++
		case StatusProbation:
			out.Probation++
		case StatusReleased:
			out.Released++
		}
		if s.Status != StatusReleased {
			out.ByReason[s.Reason]++
			out.ByScope[s.Scope]++
		}
	}
	return out, nil
}
func (m *Manager) Inspect(ctx context.Context, id string) (State, error) {
	if id == "" || len(id) > 64 {
		return State{}, ErrNotFound
	}
	states, err := m.store.List(ctx)
	if err != nil {
		return State{}, err
	}
	for _, s := range states {
		if s.ID == id {
			s.SeenSignals = nil
			return s, nil
		}
	}
	return State{}, ErrNotFound
}
func (m *Manager) mutate(ctx context.Context, id string, expected uint64, actor string, fn func(*State) error) (State, error) {
	states, err := m.store.List(ctx)
	if err != nil {
		return State{}, err
	}
	for _, s := range states {
		if s.ID != id {
			continue
		}
		if s.Revision != expected {
			return State{}, ErrConflict
		}
		if err = fn(&s); err != nil {
			return State{}, err
		}
		s.Actor = digest(actor)
		s.Revision++
		if err = m.store.Put(ctx, s.KeyDigest, expected, s); err != nil {
			return State{}, err
		}
		s.SeenSignals = nil
		m.notify(s)
		return s, nil
	}
	return State{}, ErrNotFound
}
func (m *Manager) Acknowledge(ctx context.Context, id string, rev uint64, actor string) (State, error) {
	return m.mutate(ctx, id, rev, actor, func(s *State) error {
		if s.Status != StatusActive {
			return errors.New("quarantine is not active")
		}
		s.Status = StatusAcknowledged
		return nil
	})
}
func (m *Manager) Extend(ctx context.Context, id string, rev uint64, ttl time.Duration, actor string) (State, error) {
	p := m.policy.Load()
	if ttl <= 0 || ttl > p.MaxTTL {
		return State{}, errors.New("extension TTL is invalid")
	}
	return m.mutate(ctx, id, rev, actor, func(s *State) error { s.ExpiresAt = m.clock().UTC().Add(ttl); s.Status = StatusActive; return nil })
}
func (m *Manager) Narrow(ctx context.Context, id string, rev uint64, scope string, actor string) (State, error) {
	if !validScopes[scope] || scope == ScopeTenant {
		return State{}, errors.New("narrow scope is invalid")
	}
	states, err := m.store.List(ctx)
	if err != nil {
		return State{}, err
	}
	for _, current := range states {
		if current.ID != id {
			continue
		}
		if current.Revision != rev {
			return State{}, ErrConflict
		}
		newKey, ok := current.ScopeKeys[scope]
		if !ok || newKey == "" {
			return State{}, errors.New("quarantine cannot be narrowed without a bound target")
		}
		current.Status = StatusReleased
		current.ExpiresAt = m.clock().UTC()
		current.Actor = digest(actor)
		current.Revision++
		if err := m.store.Put(ctx, current.KeyDigest, rev, current); err != nil {
			return State{}, err
		}
		replacement := cloneState(current)
		replacement.ID = m.newID()
		replacement.KeyDigest = newKey
		replacement.Scope = scope
		replacement.Status = StatusActive
		replacement.ExpiresAt = m.clock().UTC().Add(m.policy.Load().MaxTTL)
		replacement.Revision = 1
		if err := m.store.Put(ctx, newKey, 0, replacement); err != nil {
			return State{}, err
		}
		m.notify(replacement)
		return replacement, nil
	}
	return State{}, ErrNotFound
}
func (m *Manager) Release(ctx context.Context, id string, rev uint64, actor, reason string) (State, error) {
	if strings.TrimSpace(reason) == "" {
		return State{}, errors.New("release reason is required")
	}
	return m.mutate(ctx, id, rev, actor, func(s *State) error { s.Status = StatusReleased; s.ExpiresAt = m.clock().UTC(); return nil })
}
func (m *Manager) Emergency(ctx context.Context, id Identity, r Resource, scope, level, actor, reason string, confirm bool) (State, error) {
	if !confirm {
		return State{}, ErrConfirmation
	}
	if id.Tenant == "" || actor == "" || strings.TrimSpace(reason) == "" || !validScopes[scope] || !validLevels[level] {
		return State{}, ErrInvalidSignal
	}
	if scope == ScopeTenant || scope == ScopeProvider {
		if !confirm {
			return State{}, ErrConfirmation
		}
	}
	key, target := keyFor(id, r, scope)
	now := m.clock().UTC()
	p := m.policy.Load()
	st := State{ID: m.newID(), KeyDigest: key, TenantDigest: identityDigest(id.Tenant), Scope: scope, TargetDigest: target, ScopeKeys: scopeKeys(id, r), Level: level, Reason: ReasonOperatorAction, Policy: Snapshot{}, Actor: digest(actor), Provenance: "operator", StartedAt: now, ExpiresAt: now.Add(p.MaxTTL), Revision: 1, Status: StatusActive, SignalCount: 1, WindowStarted: now, LastSignalAt: now, Evidence: []EvidenceRef{{Kind: "operator_reason", Digest: digest(reason)}}}
	if err := m.store.Put(ctx, key, 0, st); err != nil {
		return State{}, err
	}
	m.notify(st)
	return st, nil
}

func cloneState(v State) State {
	v.Evidence = append([]EvidenceRef(nil), v.Evidence...)
	v.SeenSignals = append([]string(nil), v.SeenSignals...)
	if v.ScopeKeys != nil {
		keys := v.ScopeKeys
		v.ScopeKeys = map[string]string{}
		for key, value := range keys {
			v.ScopeKeys[key] = value
		}
	}
	return v
}
func (s Summary) SortedReasons() []string {
	keys := make([]string, 0, len(s.ByReason))
	for k := range s.ByReason {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
