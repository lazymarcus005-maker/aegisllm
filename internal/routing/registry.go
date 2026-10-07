// Package routing contains the policy-independent upstream registry and the
// deterministic, health-aware route selector. It intentionally has no HTTP
// client or credential handling; those remain at the gateway transport
// boundary.
package routing

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegisllm/gateway/internal/core"
	"gopkg.in/yaml.v3"
)

const Schema = "aegisllm.upstreams/v1"

type Class string

const (
	ClassLocal Class = "local"
	ClassCloud Class = "cloud"
)

// Capabilities are deliberately a fixed vocabulary. This keeps route
// selection and metrics bounded even when a caller sends an arbitrary path.
type Capabilities struct {
	Chat        bool                    `yaml:"chat"`
	Responses   bool                    `yaml:"responses"`
	Messages    bool                    `yaml:"messages"`
	Embeddings  bool                    `yaml:"embeddings"`
	Streaming   bool                    `yaml:"streaming"`
	Tools       bool                    `yaml:"tools"`
	Conformance *ConformanceDeclaration `yaml:"conformance,omitempty"`
}

// ConformanceDeclaration binds advanced behavior to an operator-reviewed
// report artifact. It contains no credentials or report contents.
type ConformanceDeclaration struct {
	SchemaVersion string `yaml:"schema_version"`
	ReportSHA256  string `yaml:"report_sha256"`
	Profile       string `yaml:"profile,omitempty"`
	Streaming     bool   `yaml:"streaming,omitempty"`
	Tools         bool   `yaml:"tools,omitempty"`
	Responses     bool   `yaml:"responses,omitempty"`
	Messages      bool   `yaml:"messages,omitempty"`
	Chat          bool   `yaml:"chat,omitempty"`
}

func (c Capabilities) Supports(family, capability string, stream, tools bool) bool {
	return c.supports(family, capability, stream, tools, false)
}

func (c Capabilities) SupportsWithConformance(family, capability string, stream, tools, gate bool) bool {
	return c.supports(family, capability, stream, tools, gate)
}

func (c Capabilities) supports(family, capability string, stream, tools, gate bool) bool {
	if gate {
		if c.Conformance == nil || c.Conformance.SchemaVersion == "" || !validSHA256(c.Conformance.ReportSHA256) {
			return false
		}
		if stream && !c.Conformance.Streaming || tools && !c.Conformance.Tools {
			return false
		}
		switch capability {
		case "chat":
			if !c.Conformance.Chat {
				return false
			}
		case "responses":
			if !c.Conformance.Responses {
				return false
			}
		case "messages":
			if !c.Conformance.Messages {
				return false
			}
		}
	}
	if stream && !c.Streaming {
		return false
	}
	if tools && !c.Tools {
		return false
	}
	switch capability {
	case "chat":
		return c.Chat
	case "responses":
		return c.Responses
	case "messages":
		return c.Messages
	case "embeddings":
		return c.Embeddings
	default:
		// Generic endpoints are intentionally conservative: they must match
		// the declared wire family, not merely an enabled upstream.
		switch family {
		case "anthropic":
			return c.Messages
		case "openai":
			return c.Chat || c.Responses || c.Embeddings
		default:
			return c.Chat || c.Responses || c.Messages
		}
	}
}

type Auth struct {
	Mode       string `yaml:"mode"`
	SecretFile string `yaml:"secret_file,omitempty"`
	HeaderName string `yaml:"header_name,omitempty"`
}

type TLS struct {
	CAFile          string `yaml:"ca_file,omitempty"`
	CertificateFile string `yaml:"certificate_file,omitempty"`
	KeyFile         string `yaml:"key_file,omitempty"`
	ServerName      string `yaml:"server_name,omitempty"`
	MinVersion      string `yaml:"min_version,omitempty"`
	MaxVersion      string `yaml:"max_version,omitempty"`
}

type Health struct {
	Endpoint string        `yaml:"endpoint"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

type Breaker struct {
	Threshold    int           `yaml:"threshold"`
	OpenInterval time.Duration `yaml:"open_interval"`
}

// Upstream is the sanitized, validated shape used by the transport layer.
// Auth and TLS fields contain file names only; secret values are never
// accepted by this package.
type Upstream struct {
	ID           string            `yaml:"id"`
	Class        Class             `yaml:"class"`
	Provider     string            `yaml:"provider"`
	Family       string            `yaml:"family"`
	BaseURL      string            `yaml:"base_url"`
	PathPrefix   string            `yaml:"path_prefix,omitempty"`
	ModelAllow   []string          `yaml:"model_allow,omitempty"`
	ModelDeny    []string          `yaml:"model_deny,omitempty"`
	Aliases      map[string]string `yaml:"aliases,omitempty"`
	Priority     int               `yaml:"priority"`
	Weight       int               `yaml:"weight"`
	Enabled      bool              `yaml:"enabled"`
	Auth         Auth              `yaml:"auth,omitempty"`
	TLS          TLS               `yaml:"tls,omitempty"`
	Health       Health            `yaml:"health"`
	Breaker      Breaker           `yaml:"breaker"`
	Capabilities Capabilities      `yaml:"capabilities"`
}

type FallbackChain struct {
	ID     string   `yaml:"id"`
	Routes []string `yaml:"routes"`
}

type Registry struct {
	Schema         string          `yaml:"schema"`
	Version        int             `yaml:"version"`
	Upstreams      []Upstream      `yaml:"upstreams"`
	FallbackChains []FallbackChain `yaml:"fallback_chains,omitempty"`
}

// Constraint is supplied by policy authoring. Empty fields mean “no extra
// restriction”; an empty fallback is intentional and means no failover.
type Constraint struct {
	Routes        []string `yaml:"routes,omitempty"`
	Classes       []string `yaml:"classes,omitempty"`
	Providers     []string `yaml:"providers,omitempty"`
	FallbackChain string   `yaml:"fallback_chain,omitempty"`
}

type Input struct {
	Action              core.Action
	RequestedModel      string
	Family              string
	Capability          string
	Streaming           bool
	Tools               bool
	VerifiedTenant      string
	VerifiedApplication string
	VerifiedProvider    string
	RequestedProvider   string
	Constraint          Constraint
	AllowFailover       bool
}

type Selection struct {
	Route          Upstream
	RequestedModel string
	RoutedModel    string
	Reason         string
	Failover       bool
}

type RouteStatus struct {
	ID           string            `json:"id"`
	Class        Class             `json:"class"`
	Provider     string            `json:"provider"`
	Family       string            `json:"family"`
	Enabled      bool              `json:"enabled"`
	Healthy      bool              `json:"healthy"`
	Breaker      string            `json:"breaker"`
	Capabilities Capabilities      `json:"capabilities"`
	ModelAllow   []string          `json:"model_allow,omitempty"`
	ModelDeny    []string          `json:"model_deny,omitempty"`
	Aliases      map[string]string `json:"aliases,omitempty"`
}

type routeState struct {
	healthy bool
	breaker *breaker
}

type Snapshot struct {
	Registry Registry
	states   map[string]*routeState
}

type Manager struct {
	current         atomic.Pointer[Snapshot]
	mu              sync.Mutex
	path            string
	conformanceGate bool
}

func (m *Manager) SetConformanceGate(enabled bool) {
	if m != nil {
		m.conformanceGate = enabled
	}
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func LoadFile(file string) (*Registry, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.New("upstream registry unavailable")
	}
	return Load(data)
}

func Load(data []byte) (*Registry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var reg Registry
	if err := dec.Decode(&reg); err != nil {
		return nil, errors.New("upstream registry is malformed")
	}
	if err := Validate(&reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

func Validate(reg *Registry) error {
	if reg == nil || reg.Schema != Schema || reg.Version != 1 {
		return fmt.Errorf("upstream registry schema must be %s version 1", Schema)
	}
	if len(reg.Upstreams) == 0 {
		return errors.New("upstream registry requires at least one upstream")
	}
	seen := map[string]bool{}
	for i := range reg.Upstreams {
		u := &reg.Upstreams[i]
		if strings.TrimSpace(u.ID) == "" || !validRouteID(u.ID) || seen[u.ID] {
			return errors.New("upstream registry route ids must be non-empty and unique")
		}
		seen[u.ID] = true
		if u.Class != ClassLocal && u.Class != ClassCloud {
			return fmt.Errorf("upstream %s has invalid class", safeID(u.ID))
		}
		if strings.TrimSpace(u.Provider) == "" || strings.TrimSpace(u.Family) == "" {
			return fmt.Errorf("upstream %s requires provider and family", safeID(u.ID))
		}
		parsed, err := url.Parse(u.BaseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("upstream %s has invalid base_url", safeID(u.ID))
		}
		if u.Priority < 0 || u.Weight < 0 {
			return fmt.Errorf("upstream %s priority and weight must be non-negative", safeID(u.ID))
		}
		if u.Weight == 0 {
			u.Weight = 1
		}
		if u.Auth.Mode == "" {
			u.Auth.Mode = "none"
		}
		if u.Auth.Mode != "none" && u.Auth.Mode != "bearer" && u.Auth.Mode != "header" {
			return fmt.Errorf("upstream %s has invalid auth mode", safeID(u.ID))
		}
		if u.Auth.Mode != "none" && strings.TrimSpace(u.Auth.SecretFile) == "" {
			return fmt.Errorf("upstream %s requires auth.secret_file", safeID(u.ID))
		}
		if u.Auth.Mode == "header" && strings.TrimSpace(u.Auth.HeaderName) == "" {
			return fmt.Errorf("upstream %s requires auth.header_name", safeID(u.ID))
		}
		if (u.TLS.MinVersion != "" && u.TLS.MinVersion != "1.2" && u.TLS.MinVersion != "1.3" && u.TLS.MinVersion != "tls1.2" && u.TLS.MinVersion != "tls1.3" && u.TLS.MinVersion != "tls12" && u.TLS.MinVersion != "tls13") ||
			(u.TLS.MaxVersion != "" && u.TLS.MaxVersion != "1.2" && u.TLS.MaxVersion != "1.3" && u.TLS.MaxVersion != "tls1.2" && u.TLS.MaxVersion != "tls1.3" && u.TLS.MaxVersion != "tls12" && u.TLS.MaxVersion != "tls13") {
			return fmt.Errorf("upstream %s has invalid TLS version", safeID(u.ID))
		}
		if u.Health.Endpoint == "" {
			u.Health.Endpoint = "/health"
		}
		if !strings.HasPrefix(u.Health.Endpoint, "/") || strings.Contains(u.Health.Endpoint, "?") {
			return fmt.Errorf("upstream %s has invalid health endpoint", safeID(u.ID))
		}
		if u.Health.Interval <= 0 {
			u.Health.Interval = 10 * time.Second
		}
		if u.Health.Timeout <= 0 {
			u.Health.Timeout = 2 * time.Second
		}
		if u.Breaker.Threshold <= 0 {
			u.Breaker.Threshold = 3
		}
		if u.Breaker.OpenInterval <= 0 {
			u.Breaker.OpenInterval = 30 * time.Second
		}
		for _, pattern := range append(append([]string{}, u.ModelAllow...), u.ModelDeny...) {
			if strings.TrimSpace(pattern) == "" || !validGlob(pattern) {
				return fmt.Errorf("upstream %s has invalid model pattern", safeID(u.ID))
			}
		}
		for alias, model := range u.Aliases {
			if strings.TrimSpace(alias) == "" || strings.TrimSpace(model) == "" || !validModelID(alias) || !validModelID(model) {
				return fmt.Errorf("upstream %s has invalid model alias", safeID(u.ID))
			}
		}
		if u.Capabilities == (Capabilities{}) {
			return fmt.Errorf("upstream %s requires capabilities", safeID(u.ID))
		}
		if declaration := u.Capabilities.Conformance; declaration != nil {
			if declaration.SchemaVersion != "aegisllm.conformance/v1" || !validSHA256(declaration.ReportSHA256) || strings.TrimSpace(declaration.Profile) == "" {
				return fmt.Errorf("upstream %s has invalid conformance declaration", safeID(u.ID))
			}
		}
	}
	for i, chain := range reg.FallbackChains {
		if chain.ID == "" || len(chain.Routes) == 0 {
			return fmt.Errorf("fallback_chains[%d] requires id and routes", i)
		}
		seenChain := map[string]bool{}
		for _, id := range chain.Routes {
			if !seen[id] || seenChain[id] {
				return fmt.Errorf("fallback chain %s references unknown or duplicate route", safeID(chain.ID))
			}
			seenChain[id] = true
		}
	}
	return nil
}

func NewManager(reg *Registry) (*Manager, error) {
	if err := Validate(reg); err != nil {
		return nil, err
	}
	m := &Manager{}
	m.current.Store(makeSnapshot(reg, nil))
	return m, nil
}

func NewManagerFile(file string) (*Manager, error) {
	reg, err := LoadFile(file)
	if err != nil {
		return nil, err
	}
	m, err := NewManager(reg)
	if err == nil {
		m.path = file
	}
	return m, err
}

// Snapshot returns a defensive copy of the immutable registry data. Runtime
// breaker state is intentionally not exposed for mutation by callers.
func (m *Manager) Snapshot() *Snapshot {
	current := m.current.Load()
	if current == nil {
		return nil
	}
	return &Snapshot{Registry: *cloneRegistry(&current.Registry)}
}

func (m *Manager) Reload() error {
	if m == nil || m.path == "" {
		return errors.New("upstream registry reload is not configured")
	}
	reg, err := LoadFile(m.path)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current.Store(makeSnapshot(reg, m.current.Load()))
	return nil
}

func (m *Manager) SetHealth(id string, healthy bool) {
	s := m.current.Load()
	if s == nil {
		return
	}
	if state := s.states[id]; state != nil {
		state.breaker.setHealth(healthy)
	}
}

func (m *Manager) Record(id string, success bool) {
	s := m.current.Load()
	if s == nil || s.states[id] == nil {
		return
	}
	s.states[id].breaker.record(success)
}

func (m *Manager) Candidates(in Input) ([]Selection, error) {
	s := m.current.Load()
	if s == nil {
		return nil, errors.New("ROUTE_UNAVAILABLE")
	}
	ids := candidateIDs(s.Registry, in.Constraint)
	if in.Action == core.ActionForceLocalModel {
		// This filter is unconditional. A configured cloud fallback is never
		// consulted for this action.
		in.Constraint.Classes = []string{string(ClassLocal)}
		ids = candidateIDs(s.Registry, in.Constraint)
	}
	var modelRejected, capabilityRejected, providerRejected bool
	var out []Selection
	for _, id := range ids {
		u, ok := findRoute(s.Registry.Upstreams, id)
		if !ok || !u.Enabled || !s.states[id].breaker.available() {
			continue
		}
		if len(in.Constraint.Classes) > 0 && !slices.Contains(in.Constraint.Classes, string(u.Class)) {
			providerRejected = true
			continue
		}
		if len(in.Constraint.Providers) > 0 && !slices.Contains(in.Constraint.Providers, u.Provider) {
			providerRejected = true
			continue
		}
		if in.VerifiedProvider != "" && in.VerifiedProvider != u.Provider && in.VerifiedProvider != string(u.Class) {
			providerRejected = true
			continue
		}
		if in.Action != core.ActionForceLocalModel && in.VerifiedProvider == "" && in.RequestedProvider != "" && in.RequestedProvider != u.Provider && in.RequestedProvider != string(u.Class) {
			providerRejected = true
			continue
		}
		if in.Family != "" && u.Family != "*" && u.Family != in.Family {
			capabilityRejected = true
			continue
		}
		if !u.Capabilities.SupportsWithConformance(in.Family, in.Capability, in.Streaming, in.Tools, m.conformanceGate) {
			capabilityRejected = true
			continue
		}
		routed := in.RequestedModel
		if alias, ok := u.Aliases[in.RequestedModel]; ok {
			routed = alias
		}
		if !modelAllowed(u, in.RequestedModel, routed) {
			modelRejected = true
			continue
		}
		out = append(out, Selection{Route: u, RequestedModel: in.RequestedModel, RoutedModel: routed, Reason: reasonFor(in.Action)})
	}
	if len(out) > 0 {
		return out, nil
	}
	switch {
	case modelRejected:
		return nil, errors.New("ROUTE_MODEL_REJECTED")
	case capabilityRejected:
		return nil, errors.New("ROUTE_CAPABILITY_REJECTED")
	case in.Action == core.ActionForceLocalModel:
		return nil, errors.New("ROUTE_LOCAL_UNAVAILABLE")
	case providerRejected:
		return nil, errors.New("ROUTE_PROVIDER_REJECTED")
	default:
		return nil, errors.New("ROUTE_UNAVAILABLE")
	}
}

func (m *Manager) Status() []RouteStatus {
	s := m.current.Load()
	if s == nil {
		return nil
	}
	out := make([]RouteStatus, 0, len(s.Registry.Upstreams))
	for _, u := range s.Registry.Upstreams {
		st := RouteStatus{ID: u.ID, Class: u.Class, Provider: u.Provider, Family: u.Family, Enabled: u.Enabled, Capabilities: u.Capabilities,
			ModelAllow: append([]string(nil), u.ModelAllow...), ModelDeny: append([]string(nil), u.ModelDeny...), Aliases: cloneMap(u.Aliases)}
		if state := s.states[u.ID]; state != nil {
			st.Healthy = u.Enabled && state.breaker.healthy()
			st.Breaker = state.breaker.state()
		}
		out = append(out, st)
	}
	slices.SortFunc(out, func(a, b RouteStatus) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func candidateIDs(reg Registry, c Constraint) []string {
	if c.FallbackChain != "" {
		for _, chain := range reg.FallbackChains {
			if chain.ID == c.FallbackChain {
				return append([]string(nil), chain.Routes...)
			}
		}
		return nil
	}
	if len(c.Routes) > 0 {
		return append([]string(nil), c.Routes...)
	}
	var out []string
	for _, u := range reg.Upstreams {
		if len(c.Classes) > 0 && !slices.Contains(c.Classes, string(u.Class)) {
			continue
		}
		if len(c.Providers) > 0 && !slices.Contains(c.Providers, u.Provider) {
			continue
		}
		out = append(out, u.ID)
	}
	slices.SortStableFunc(out, func(a, b string) int {
		ua, _ := findRoute(reg.Upstreams, a)
		ub, _ := findRoute(reg.Upstreams, b)
		if ua.Priority != ub.Priority {
			return ua.Priority - ub.Priority
		}
		return strings.Compare(a, b)
	})
	return out
}

func makeSnapshot(reg *Registry, old *Snapshot) *Snapshot {
	copyReg := cloneRegistry(reg)
	states := map[string]*routeState{}
	for _, u := range copyReg.Upstreams {
		if old != nil && old.states[u.ID] != nil {
			states[u.ID] = old.states[u.ID]
		} else {
			states[u.ID] = &routeState{healthy: true, breaker: newBreaker(u.Breaker.Threshold, u.Breaker.OpenInterval)}
		}
	}
	return &Snapshot{Registry: *copyReg, states: states}
}

func cloneRegistry(in *Registry) *Registry {
	out := *in
	out.Upstreams = append([]Upstream(nil), in.Upstreams...)
	for i := range out.Upstreams {
		out.Upstreams[i].ModelAllow = append([]string(nil), in.Upstreams[i].ModelAllow...)
		out.Upstreams[i].ModelDeny = append([]string(nil), in.Upstreams[i].ModelDeny...)
		out.Upstreams[i].Aliases = cloneMap(in.Upstreams[i].Aliases)
	}
	out.FallbackChains = append([]FallbackChain(nil), in.FallbackChains...)
	for i := range out.FallbackChains {
		out.FallbackChains[i].Routes = append([]string(nil), in.FallbackChains[i].Routes...)
	}
	return &out
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func findRoute(routes []Upstream, id string) (Upstream, bool) {
	for _, u := range routes {
		if u.ID == id {
			return u, true
		}
	}
	return Upstream{}, false
}

func modelAllowed(u Upstream, requested, routed string) bool {
	if requested == "" {
		return true
	}
	for _, pattern := range u.ModelDeny {
		if matchGlob(pattern, requested) || matchGlob(pattern, routed) {
			return false
		}
	}
	if len(u.ModelAllow) == 0 {
		return true
	}
	for _, pattern := range u.ModelAllow {
		if matchGlob(pattern, requested) || matchGlob(pattern, routed) {
			return true
		}
	}
	return false
}

func validGlob(v string) bool {
	return strings.IndexFunc(v, func(r rune) bool { return r == '\\' || r < 0x20 }) < 0
}
func validModelID(v string) bool           { return validGlob(v) && !strings.ContainsAny(v, "?*") }
func validRouteID(v string) bool           { return validModelID(v) && len(v) <= 64 }
func matchGlob(pattern, value string) bool { ok, _ := path.Match(pattern, value); return ok }
func reasonFor(a core.Action) string {
	if a == core.ActionForceLocalModel {
		return "force_local_policy"
	}
	return "configured_route"
}
func safeID(id string) string {
	if len(id) > 64 {
		return id[:64]
	}
	return regexp.MustCompile(`[^A-Za-z0-9_.:-]`).ReplaceAllString(id, "_")
}

type breaker struct {
	mu                  sync.Mutex
	failures, threshold int
	openUntil           time.Time
	cooldown            time.Duration
	healthyFlag         bool
}

func newBreaker(t int, d time.Duration) *breaker {
	return &breaker{threshold: t, cooldown: d, healthyFlag: true}
}
func (b *breaker) available() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.healthyFlag && (b.failures < b.threshold || time.Now().After(b.openUntil))
}
func (b *breaker) setHealth(v bool) {
	b.mu.Lock()
	b.healthyFlag = v
	if v {
		b.failures = 0
		b.openUntil = time.Time{}
	} else {
		b.openUntil = time.Now().Add(b.cooldown)
	}
	b.mu.Unlock()
}
func (b *breaker) healthy() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.healthyFlag }
func (b *breaker) record(ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		b.failures = 0
		b.openUntil = time.Time{}
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.openUntil = time.Now().Add(b.cooldown)
	}
}
func (b *breaker) state() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.healthyFlag || time.Now().Before(b.openUntil) {
		return "open"
	}
	if b.failures >= b.threshold {
		return "half_open"
	}
	return "closed"
}
