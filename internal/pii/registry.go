package pii

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
	"gopkg.in/yaml.v3"
)

const RegistrySchema = "aegisllm.pii-ner/v1"

// ProviderConfig is the strict, versioned operator contract for one NER
// provider. Credentials are references only and never values.
type ProviderConfig struct {
	ID                      string                        `yaml:"id"`
	Type                    string                        `yaml:"type"`
	URL                     string                        `yaml:"url"`
	Languages               []string                      `yaml:"languages"`
	EntityMappings          map[string]string             `yaml:"entity_mappings"`
	MinConfidence           map[string]float64            `yaml:"min_confidence"`
	MinConfidenceByLanguage map[string]map[string]float64 `yaml:"min_confidence_by_language,omitempty"`
	Priority                int                           `yaml:"priority"`
	Timeout                 time.Duration                 `yaml:"timeout"`
	MaxChars                int                           `yaml:"max_chars"`
	ChunkOverlap            int                           `yaml:"chunk_overlap"`
	MaxConcurrent           int                           `yaml:"max_concurrent"`
	Breaker                 int                           `yaml:"breaker_threshold"`
	BreakerOpen             time.Duration                 `yaml:"breaker_open_interval"`
	FailBehavior            string                        `yaml:"fail_behavior"`
	AuthFile                string                        `yaml:"auth_file,omitempty"`
	TLS                     ProviderTLS                   `yaml:"tls,omitempty"`
}

type ProviderTLS struct {
	CAFile          string `yaml:"ca_file,omitempty"`
	CertificateFile string `yaml:"certificate_file,omitempty"`
	KeyFile         string `yaml:"key_file,omitempty"`
	ServerName      string `yaml:"server_name,omitempty"`
}

type Registry struct {
	Schema    string           `yaml:"schema"`
	Version   int              `yaml:"version"`
	Providers []ProviderConfig `yaml:"providers"`
}

// LoadRegistry uses KnownFields so a typo cannot silently weaken production
// PII coverage. The returned registry is safe to retain after the input is
// released.
func LoadRegistry(data []byte) (*Registry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var reg Registry
	if err := dec.Decode(&reg); err != nil {
		return nil, errors.New("PII NER registry is malformed")
	}
	if err := ValidateRegistry(&reg, "development"); err != nil {
		return nil, err
	}
	return &reg, nil
}

func LoadRegistryForProfile(data []byte, profile string) (*Registry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var reg Registry
	if err := dec.Decode(&reg); err != nil {
		return nil, errors.New("PII NER registry is malformed")
	}
	if err := ValidateRegistry(&reg, profile); err != nil {
		return nil, err
	}
	return &reg, nil
}

func LoadRegistryFile(path, profile string) (*Registry, error) {
	data, err := securetransport.ReadTrustedFile(path)
	if err != nil {
		return nil, errors.New("PII NER registry unavailable")
	}
	return LoadRegistryForProfile(data, profile)
}

func ValidateRegistry(reg *Registry, profile string) error {
	if reg == nil || reg.Schema != RegistrySchema || reg.Version != 1 {
		return errors.New("PII NER registry schema/version is invalid")
	}
	if len(reg.Providers) == 0 {
		return errors.New("PII NER registry requires a provider")
	}
	if len(reg.Providers) > 32 {
		return errors.New("PII NER registry has too many providers")
	}
	seen := map[string]bool{}
	for i := range reg.Providers {
		p := &reg.Providers[i]
		if strings.TrimSpace(p.ID) == "" || seen[p.ID] {
			return fmt.Errorf("PII NER provider %d has a duplicate or empty id", i)
		}
		seen[p.ID] = true
		if p.Type != "presidio_http" && p.Type != "aegis_ner_http" {
			return fmt.Errorf("PII NER provider %s has an unsupported type", p.ID)
		}
		if len(p.Languages) > 16 || len(p.EntityMappings) > 128 {
			return fmt.Errorf("PII NER provider %s coverage is too large", p.ID)
		}
		for _, language := range p.Languages {
			if len(language) == 0 || len(language) > 16 {
				return fmt.Errorf("PII NER provider %s language is invalid", p.ID)
			}
		}
		u, err := url.Parse(p.URL)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("PII NER provider %s URL is invalid", p.ID)
		}
		if profile == "production" && (u.Scheme != "https" || !privateProviderHost(u.Hostname())) {
			return fmt.Errorf("PII NER provider %s must use private verified TLS", p.ID)
		}
		if p.Priority < 0 || p.Timeout <= 0 || p.MaxChars <= 0 || p.MaxConcurrent <= 0 || p.Breaker <= 0 || p.BreakerOpen <= 0 {
			return fmt.Errorf("PII NER provider %s limits are invalid", p.ID)
		}
		if p.MaxChars > 1<<20 || p.ChunkOverlap < 0 || p.ChunkOverlap >= p.MaxChars || p.Timeout > 60*time.Second {
			return fmt.Errorf("PII NER provider %s limits exceed bounds", p.ID)
		}
		if p.FailBehavior != "strict" && p.FailBehavior != "deterministic_only" {
			return fmt.Errorf("PII NER provider %s fail_behavior is invalid", p.ID)
		}
		if profile == "production" && p.FailBehavior == "deterministic_only" {
			return fmt.Errorf("PII NER provider %s cannot silently fall back in production", p.ID)
		}
		if (p.TLS.CertificateFile == "") != (p.TLS.KeyFile == "") {
			return fmt.Errorf("PII NER provider %s TLS certificate and key must be paired", p.ID)
		}
		if profile == "production" && p.AuthFile == "" && p.TLS.CertificateFile == "" { /* mTLS is optional when service auth is network-bound */
		}
		for entity, threshold := range p.MinConfidence {
			if strings.TrimSpace(entity) == "" || threshold < 0 || threshold > 1 {
				return fmt.Errorf("PII NER provider %s confidence policy is invalid", p.ID)
			}
		}
		for language, entities := range p.MinConfidenceByLanguage {
			if strings.TrimSpace(language) == "" {
				return fmt.Errorf("PII NER provider %s confidence language is invalid", p.ID)
			}
			for entity, threshold := range entities {
				if strings.TrimSpace(entity) == "" || threshold < 0 || threshold > 1 {
					return fmt.Errorf("PII NER provider %s confidence policy is invalid", p.ID)
				}
			}
		}
	}
	return nil
}

func privateProviderHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".svc") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}

// ProviderRegistry builds a deterministic, priority-ordered router from a
// validated registry. Last-known-good replacement is atomic.
type ProviderRegistry struct {
	current atomic.Pointer[providerSnapshot]
	mu      sync.Mutex
}

// RegistryManager owns an atomic last-known-good provider snapshot. Reload is
// transactional: malformed replacements are rejected before the active
// snapshot changes.
type RegistryManager struct {
	path        string
	profile     string
	current     atomic.Pointer[ProviderRegistry]
	mu          sync.Mutex
	lastFailure string
}

func NewRegistryManager(path, profile string) (*RegistryManager, error) {
	m := &RegistryManager{path: path, profile: profile}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *RegistryManager) Reload() error {
	reg, err := LoadRegistryFile(m.path, m.profile)
	if err != nil {
		m.mu.Lock()
		m.lastFailure = "registry reload failed"
		m.mu.Unlock()
		return err
	}
	provider, err := NewProviderRegistry(reg)
	if err != nil {
		m.mu.Lock()
		m.lastFailure = "provider reload failed"
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	old := m.current.Load()
	m.current.Store(provider)
	m.lastFailure = ""
	m.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

func (m *RegistryManager) Provider() *ProviderRegistry {
	if m == nil {
		return nil
	}
	return m.current.Load()
}
func (m *RegistryManager) LastFailure() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastFailure
}
func (m *RegistryManager) Close() {
	if p := m.Provider(); p != nil {
		p.Close()
	}
}

type providerSnapshot struct {
	version   int
	providers []*remoteSpanProvider
}

func NewProviderRegistry(reg *Registry) (*ProviderRegistry, error) {
	r := &ProviderRegistry{}
	if err := r.Reload(reg); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *ProviderRegistry) Reload(reg *Registry) error {
	if err := ValidateRegistry(reg, "development"); err != nil {
		return err
	}
	providers := make([]*remoteSpanProvider, 0, len(reg.Providers))
	for _, cfg := range reg.Providers {
		hc := HTTPProviderConfig{ID: cfg.ID, Priority: cfg.Priority, FailBehavior: cfg.FailBehavior, URL: cfg.URL, Languages: cfg.Languages, EntityMappings: cfg.EntityMappings, MinConfidence: cfg.MinConfidence, MinConfidenceByLanguage: cfg.MinConfidenceByLanguage, Timeout: cfg.Timeout, MaxChars: cfg.MaxChars, ChunkOverlap: cfg.ChunkOverlap, MaxConcurrent: cfg.MaxConcurrent, Breaker: cfg.Breaker, BreakerOpen: cfg.BreakerOpen, AuthFile: cfg.AuthFile, TLS: securetransport.ClientTLSOptions{CAFile: cfg.TLS.CAFile, CertificateFile: cfg.TLS.CertificateFile, KeyFile: cfg.TLS.KeyFile, ServerName: cfg.TLS.ServerName, MinVersion: 0, PollInterval: securetransport.DefaultPollInterval}}
		var p *remoteSpanProvider
		var err error
		if cfg.Type == "presidio_http" {
			p, err = NewPresidioHTTPAdapter(hc)
		} else {
			p, err = NewAegisNERAdapter(hc)
		}
		if err != nil {
			return err
		}
		providers = append(providers, p)
	}
	sort.SliceStable(providers, func(i, j int) bool { return providers[i].cfg.Priority > providers[j].cfg.Priority })
	r.mu.Lock()
	old := r.current.Load()
	r.current.Store(&providerSnapshot{version: reg.Version, providers: providers})
	r.mu.Unlock()
	if old != nil {
		for _, p := range old.providers {
			p.Close()
		}
	}
	return nil
}

func (r *ProviderRegistry) Name() string { return "pii-ner-registry" }
func (r *ProviderRegistry) Spans(text string) []EntitySpan {
	spans, _ := r.SpansContext(context.Background(), text)
	return spans
}
func (r *ProviderRegistry) SpansContext(ctx context.Context, text string) ([]EntitySpan, error) {
	snap := r.current.Load()
	if snap == nil {
		return nil, errors.New("PII NER registry unavailable")
	}
	var out []EntitySpan
	var lastErr error
	lang := DetectLanguage(text)
	for _, p := range snap.providers {
		if !p.supportsLanguage(lang) {
			continue
		}
		got, err := p.SpansContext(ctx, text)
		if err != nil {
			lastErr = err
			if p.cfg.FailBehavior == "strict" {
				return nil, err
			}
			continue
		}
		out = append(out, got...)
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}
func (r *ProviderRegistry) Status() []ProviderStatus {
	snap := r.current.Load()
	if snap == nil {
		return nil
	}
	out := make([]ProviderStatus, 0, len(snap.providers))
	for _, p := range snap.providers {
		out = append(out, p.Status())
	}
	return out
}

func (r *ProviderRegistry) SetMetrics(metrics ProviderMetrics) {
	snap := r.current.Load()
	if snap == nil {
		return
	}
	for _, p := range snap.providers {
		p.SetMetrics(metrics)
	}
}
func (r *ProviderRegistry) Close() {
	snap := r.current.Load()
	if snap != nil {
		for _, p := range snap.providers {
			p.Close()
		}
	}
}
