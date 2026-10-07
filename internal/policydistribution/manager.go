package policydistribution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
)

type State struct {
	HighestSequence uint64 `json:"highest_sequence"`
	BundleHash      string `json:"bundle_hash"`
}

type Authorization struct {
	Version        int    `json:"version"`
	Action         string `json:"action"`
	TargetSequence uint64 `json:"target_sequence"`
	TargetHash     string `json:"target_hash"`
	Reason         string `json:"reason"`
	Role           string `json:"role"`
	Issuer         string `json:"issuer"`
	KeyID          string `json:"key_id"`
	Issued         string `json:"issued"`
	Signature      []byte `json:"-"`
}

type Config struct {
	BundleDir              string
	BundlePath             string
	ControlPlaneURL        string
	TrustStorePath         string
	StatePath              string
	PollInterval           time.Duration
	Timeout                time.Duration
	MaxBundleBytes         int64
	GatewayVersion         string
	Environment            string
	Tenant                 string
	Retain                 int
	CanaryPercent          int
	CanarySoak             time.Duration
	HTTPClient             *http.Client
	TLS                    securetransport.ClientTLSOptions
	RequireRemoteSignature bool
}

type Observer interface {
	RecordDistribution(event, reason, keyID string)
}

type Status struct {
	Active              Metadata  `json:"active"`
	Candidate           *Metadata `json:"candidate,omitempty"`
	HighestSequence     uint64    `json:"highest_sequence"`
	CanaryPercent       int       `json:"canary_percent"`
	CanarySoak          string    `json:"canary_soak,omitempty"`
	CanaryDisagreements uint64    `json:"canary_disagreements"`
	LastError           string    `json:"last_error,omitempty"`
}

type Metadata struct {
	BundleID      string `json:"bundle_id"`
	Sequence      uint64 `json:"sequence"`
	BundleHash    string `json:"bundle_hash"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion int    `json:"policy_version"`
	Issuer        string `json:"issuer"`
	KeyID         string `json:"key_id"`
}

type Manager struct {
	cfg                 Config
	trust               *TrustStore
	active              atomic.Pointer[Snapshot]
	candidate           atomic.Pointer[Snapshot]
	mu                  sync.Mutex
	state               State
	history             []*Snapshot
	etag                string
	lastErr             string
	observer            Observer
	canary              map[string]uint64
	canaryDisagreements uint64
	apply               func(*Snapshot) error
	applyCandidate      func(*Snapshot) error
	candidateSince      time.Time
}

func NewManager(cfg Config, observer Observer) (*Manager, error) {
	if cfg.Retain <= 0 {
		cfg.Retain = 3
	}
	if cfg.MaxBundleBytes <= 0 {
		cfg.MaxBundleBytes = 16 << 20
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.CanaryPercent < 0 || cfg.CanaryPercent > 100 {
		return nil, errors.New("canary percentage must be between 0 and 100")
	}
	if cfg.ControlPlaneURL != "" && !strings.EqualFold(strings.Split(cfg.ControlPlaneURL, ":")[0], "https") {
		return nil, errors.New("control plane URL must use HTTPS")
	}
	m := &Manager{cfg: cfg, trust: NewTrustStore(cfg.TrustStorePath), observer: observer, canary: map[string]uint64{}}
	if cfg.StatePath != "" {
		if err := m.loadState(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Manager) SetObserver(o Observer)            { m.mu.Lock(); m.observer = o; m.mu.Unlock() }
func (m *Manager) SetApply(fn func(*Snapshot) error) { m.mu.Lock(); m.apply = fn; m.mu.Unlock() }
func (m *Manager) SetCandidateApply(fn func(*Snapshot) error) {
	m.mu.Lock()
	m.applyCandidate = fn
	m.mu.Unlock()
}
func (m *Manager) Current() *Snapshot   { return m.active.Load() }
func (m *Manager) Candidate() *Snapshot { return m.candidate.Load() }

func (m *Manager) LoadInitial(ctx context.Context) error {
	b, err := m.fetch(ctx)
	if err != nil {
		return err
	}
	s, err := m.verifyAndGate(b)
	if err != nil {
		return err
	}
	if err := m.activate(s, false); err != nil {
		return err
	}
	return nil
}

func (m *Manager) Poll(ctx context.Context) error {
	if m.cfg.ControlPlaneURL == "" {
		b, err := m.fetch(ctx)
		if err != nil {
			m.reject("fetch", err)
			return err
		}
		s, err := m.verifyAndGate(b)
		if err != nil {
			m.reject("verify", err)
			return err
		}
		if m.Current() == nil {
			return m.activate(s, false)
		}
		return m.SetCandidate(s)
	}
	b, notModified, err := m.fetchHTTP(ctx)
	if err != nil {
		m.reject("fetch", err)
		return err
	}
	if notModified {
		return nil
	}
	s, err := m.verifyAndGate(b)
	if err != nil {
		m.reject("verify", err)
		return err
	}
	if m.Current() == nil {
		return m.activate(s, false)
	}
	return m.SetCandidate(s)
}

func (m *Manager) SetCandidate(s *Snapshot) error {
	if s == nil || s.Bundle == nil {
		return errors.New("candidate is empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkSequence(s.Bundle.Manifest.Sequence, s.BundleHash); err != nil {
		m.lastErr = err.Error()
		return err
	}
	m.candidate.Store(s)
	m.candidateSince = time.Now().UTC()
	if m.applyCandidate != nil {
		if err := m.applyCandidate(s); err != nil {
			return err
		}
	}
	m.lastErr = ""
	m.recordLocked("candidate", "ready", s.Bundle.Manifest.KeyID)
	return nil
}

func (m *Manager) Promote(reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("promotion reason is required")
	}
	s := m.candidate.Load()
	if s == nil {
		return errors.New("no candidate is ready")
	}
	if m.cfg.CanaryPercent > 0 && m.cfg.CanarySoak > 0 && time.Since(m.candidateSince) < m.cfg.CanarySoak {
		return errors.New("canary soak time has not elapsed")
	}
	return m.activate(s, true)
}

func (m *Manager) PromoteAuthorized(reason, role string) error {
	if role != "aegis.operator" {
		return errors.New("operator role is required")
	}
	return m.Promote(reason)
}

func (m *Manager) Rollback(auth Authorization, trust *TrustStore) error {
	if auth.Version != 1 || auth.Action != "rollback" || strings.TrimSpace(auth.Reason) == "" || auth.Role != "aegis.operator" || auth.Issuer == "" || auth.Issued == "" {
		return errors.New("signed operator rollback authorization is required")
	}
	if trust == nil {
		trust = m.trust
	}
	key, err := trust.Key(auth.KeyID, time.Now().UTC())
	if err != nil {
		return err
	}
	canon := auth
	canon.Signature = nil
	data, err := json.Marshal(canon)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, data, auth.Signature) {
		return errors.New("rollback authorization signature verification failed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.history) - 1; i >= 0; i-- {
		s := m.history[i]
		if s.Bundle.Manifest.Sequence == auth.TargetSequence && s.BundleHash == auth.TargetHash {
			if m.apply != nil {
				if err := m.apply(s); err != nil {
					return err
				}
			}
			m.active.Store(s)
			m.candidate.Store(nil)
			if m.applyCandidate != nil {
				_ = m.applyCandidate(nil)
			}
			m.recordLocked("rollback", "operator_authorized", auth.KeyID)
			return nil
		}
	}
	return errors.New("rollback target is not retained")
}

func (m *Manager) IsCanary(id, tenant, application string) bool {
	s := m.candidate.Load()
	if s == nil || m.cfg.CanaryPercent <= 0 {
		return false
	}
	seed := id + "\x00" + tenant + "\x00" + application
	sum := sha256.Sum256([]byte(seed))
	n := int(sum[0])<<8 | int(sum[1])
	return n%100 < m.cfg.CanaryPercent
}

func (m *Manager) ObserveCanary(id string, disagreement bool) {
	if disagreement {
		m.mu.Lock()
		m.canary[id]++
		m.canaryDisagreements++
		m.mu.Unlock()
		m.record("canary_disagreement", "candidate", "")
	}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := Status{CanaryPercent: m.cfg.CanaryPercent, HighestSequence: m.state.HighestSequence, LastError: m.lastErr, CanaryDisagreements: m.canaryDisagreements}
	if m.cfg.CanarySoak > 0 {
		status.CanarySoak = m.cfg.CanarySoak.String()
	}
	if s := m.active.Load(); s != nil {
		status.Active = metadata(s)
	}
	if s := m.candidate.Load(); s != nil {
		v := metadata(s)
		status.Candidate = &v
	}
	return status
}

func (m *Manager) fetch(ctx context.Context) (*Bundle, error) {
	if m.cfg.ControlPlaneURL != "" {
		b, _, err := m.fetchHTTP(ctx)
		return b, err
	}
	path := m.cfg.BundlePath
	if path != "" {
		return ReadDirectory(path)
	}
	if m.cfg.BundleDir == "" {
		return nil, errors.New("bundle source is not configured")
	}
	if bundle, err := ReadDirectory(m.cfg.BundleDir); err == nil {
		return bundle, nil
	}
	entries, err := os.ReadDir(m.cfg.BundleDir)
	if err != nil {
		return nil, err
	}
	var best *Bundle
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		bundle, readErr := ReadDirectory(filepath.Join(m.cfg.BundleDir, entry.Name()))
		if readErr != nil {
			continue
		}
		if best == nil || bundle.Manifest.Sequence > best.Manifest.Sequence {
			best = bundle
		}
	}
	if best == nil {
		return nil, errors.New("no signed bundle found in bundle directory")
	}
	return best, nil
}

func (m *Manager) fetchHTTP(ctx context.Context) (*Bundle, bool, error) {
	if m.cfg.ControlPlaneURL == "" {
		return nil, false, errors.New("control plane URL is not configured")
	}
	client := m.cfg.HTTPClient
	var files []*securetransport.File[tls.Certificate]
	if client == nil {
		tlsConfig, certFiles, err := m.cfg.TLS.TLSConfig()
		if err != nil {
			return nil, false, err
		}
		files = certFiles
		client = &http.Client{Timeout: m.cfg.Timeout, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	}
	defer func() {
		for _, f := range files {
			if f != nil {
				f.Close()
			}
		}
	}()
	requestCtx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, m.cfg.ControlPlaneURL, nil)
	if err != nil {
		return nil, false, err
	}
	m.mu.Lock()
	etag := m.etag
	m.mu.Unlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("control plane returned status %d", resp.StatusCode)
	}
	if resp.ContentLength > m.cfg.MaxBundleBytes {
		return nil, false, errors.New("bundle exceeds configured size")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, m.cfg.MaxBundleBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > m.cfg.MaxBundleBytes {
		return nil, false, errors.New("bundle exceeds configured size")
	}
	// Control planes serve the same deterministic directory representation as a
	// tar-free JSON envelope, keeping extraction bounded and path-safe.
	var envelope struct {
		Manifest  Manifest          `json:"manifest"`
		Signature string            `json:"signature"`
		Files     map[string]string `json:"files"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, false, errors.New("control plane bundle is malformed")
	}
	b := &Bundle{Manifest: envelope.Manifest, Files: map[string][]byte{}}
	if b.Signature, err = decodeBase64(envelope.Signature); err != nil {
		return nil, false, err
	}
	for name, encoded := range envelope.Files {
		raw, decodeErr := decodeBase64(encoded)
		if decodeErr != nil {
			return nil, false, fmt.Errorf("bundle file %s is malformed", name)
		}
		b.Files[name] = raw
	}
	if value := resp.Header.Get("ETag"); value != "" {
		m.mu.Lock()
		m.etag = value
		m.mu.Unlock()
	}
	return b, false, nil
}

func (m *Manager) verifyAndGate(b *Bundle) (*Snapshot, error) {
	if err := b.Validate(time.Now().UTC()); err != nil {
		return nil, err
	}
	key, err := m.trust.Key(b.Manifest.KeyID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := b.Verify(key, time.Now().UTC()); err != nil {
		return nil, err
	}
	s, err := b.Snapshot()
	if err != nil {
		return nil, err
	}
	if m.cfg.GatewayVersion != "" && versionLess(m.cfg.GatewayVersion, b.Manifest.MinimumGatewayVersion) {
		return nil, errors.New("gateway version is below bundle minimum")
	}
	if b.Manifest.MinimumGatewayVersion != "" && !validVersion(b.Manifest.MinimumGatewayVersion) {
		return nil, errors.New("bundle minimum gateway version is invalid")
	}
	if !selectorMatch(m.cfg.Environment, b.Manifest.TargetEnvironments) || !selectorMatch(m.cfg.Tenant, b.Manifest.TargetTenants) {
		return nil, errors.New("bundle target selector does not match gateway")
	}
	if s.Questions != nil && b.Manifest.SchemaVersion != "" && s.Questions.Schema != b.Manifest.SchemaVersion {
		return nil, errors.New("question schema provenance mismatch")
	}
	return s, nil
}

func (m *Manager) activate(s *Snapshot, promoted bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkSequence(s.Bundle.Manifest.Sequence, s.BundleHash); err != nil {
		return err
	}
	if old := m.active.Load(); old != nil {
		m.history = append(m.history, old)
		if len(m.history) > m.cfg.Retain {
			m.history = m.history[len(m.history)-m.cfg.Retain:]
		}
	}
	if m.apply != nil {
		if err := m.apply(s); err != nil {
			return err
		}
	}
	if m.applyCandidate != nil {
		_ = m.applyCandidate(nil)
	}
	m.active.Store(s)
	m.candidate.Store(nil)
	m.state = State{HighestSequence: s.Bundle.Manifest.Sequence, BundleHash: s.BundleHash}
	if err := m.persistStateLocked(); err != nil {
		return err
	}
	m.recordLocked("activate", map[bool]string{true: "promoted", false: "initial"}[promoted], s.Bundle.Manifest.KeyID)
	return nil
}

func (m *Manager) checkSequence(seq uint64, hash string) error {
	if seq < m.state.HighestSequence {
		return errors.New("bundle sequence is lower than durable highest accepted sequence")
	}
	if seq == m.state.HighestSequence && hash != m.state.BundleHash {
		return errors.New("conflicting bundle replay at accepted sequence")
	}
	if current := m.active.Load(); current != nil && seq <= current.Bundle.Manifest.Sequence && hash != current.BundleHash {
		return errors.New("bundle rollback requires signed operator authorization")
	}
	return nil
}

func (m *Manager) loadState() error {
	data, err := os.ReadFile(m.cfg.StatePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &m.state)
}
func (m *Manager) persistStateLocked() error {
	if m.cfg.StatePath == "" {
		return nil
	}
	data, _ := json.Marshal(m.state)
	return atomicWrite(m.cfg.StatePath, append(data, '\n'), 0600)
}
func (m *Manager) reject(event string, err error) {
	m.mu.Lock()
	m.lastErr = err.Error()
	key := ""
	if m.active.Load() != nil {
		key = m.active.Load().Bundle.Manifest.KeyID
	}
	m.mu.Unlock()
	m.record(event, "rejected", key)
}
func (m *Manager) record(event, reason, key string) {
	m.mu.Lock()
	o := m.observer
	m.mu.Unlock()
	if o != nil {
		o.RecordDistribution(event, reason, key)
	}
}
func (m *Manager) recordLocked(event, reason, key string) {
	if m.observer != nil {
		m.observer.RecordDistribution(event, reason, key)
	}
}
func metadata(s *Snapshot) Metadata {
	return Metadata{BundleID: s.Bundle.Manifest.BundleID, Sequence: s.Bundle.Manifest.Sequence, BundleHash: s.BundleHash, PolicyID: s.Policy.ID, PolicyVersion: s.Policy.Version, Issuer: s.Bundle.Manifest.Issuer, KeyID: s.Bundle.Manifest.KeyID}
}
func selectorMatch(value string, selectors []string) bool {
	if len(selectors) == 0 {
		return true
	}
	if value == "" {
		return false
	}
	for _, s := range selectors {
		if s == "*" || s == value {
			return true
		}
	}
	return false
}
func validVersion(value string) bool {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	parts := strings.Split(value, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
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
	parse := func(s string) [3]int {
		var v [3]int
		p := strings.Split(strings.TrimPrefix(s, "v"), ".")
		for i := 0; i < len(p) && i < 3; i++ {
			fmt.Sscanf(p[i], "%d", &v[i])
		}
		return v
	}
	a, b := parse(got), parse(want)
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
func decodeBase64(s string) ([]byte, error) {
	const prefix = "base64:"
	if strings.HasPrefix(s, prefix) {
		s = s[len(prefix):]
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid base64 bundle data")
	}
	return b, nil
}
