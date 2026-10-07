package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/routing"
	"github.com/aegisllm/gateway/internal/securetransport"
)

// RoutedProxy binds immutable registry entries to transport clients. Registry
// selection is separate from transport construction so reloads cannot mutate
// a route while a request is using it.
type RoutedProxy struct {
	manager *routing.Manager
	cfg     Config
	mu      sync.Mutex
	routes  map[string]*Proxy
	stop    chan struct{}
	done    chan struct{}
	metrics interface {
		ObserveRouteHealth(string, string, string, bool)
	}
}

func NewRoutedProxy(cfg Config, manager *routing.Manager) (*RoutedProxy, error) {
	if manager == nil {
		return nil, errors.New("route manager is required")
	}
	p := &RoutedProxy{manager: manager, cfg: cfg, routes: map[string]*Proxy{}, stop: make(chan struct{}), done: make(chan struct{})}
	manager.SetConformanceGate(cfg.ConformanceCapabilityGate)
	for _, u := range manager.Snapshot().Registry.Upstreams {
		if _, err := p.proxyFor(u); err != nil {
			p.Close()
			return nil, fmt.Errorf("route %s is invalid", u.ID)
		}
	}
	go p.healthLoop()
	return p, nil
}

func (p *RoutedProxy) proxyFor(u routing.Upstream) (*Proxy, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing := p.routes[u.ID]; existing != nil {
		return existing, nil
	}
	proxy, err := NewProxy(Config{
		UpstreamBaseURL: u.BaseURL, UpstreamAuthMode: u.Auth.Mode,
		UpstreamAPIKeyFile: func() string {
			if u.Auth.Mode == "bearer" {
				return u.Auth.SecretFile
			}
			return ""
		}(),
		UpstreamAuthHeaderName: u.Auth.HeaderName,
		UpstreamAuthHeaderValueFile: func() string {
			if u.Auth.Mode == "header" {
				return u.Auth.SecretFile
			}
			return ""
		}(),
		UpstreamTLSCAFile: u.TLS.CAFile, UpstreamTLSCertFile: u.TLS.CertificateFile, UpstreamTLSKeyFile: u.TLS.KeyFile,
		UpstreamTLSServerName: u.TLS.ServerName, TLSMinVersion: routeTLSMin(u.TLS.MinVersion, p.cfg.TLSMinVersion), TLSMaxVersion: routeTLSMax(u.TLS.MaxVersion, p.cfg.TLSMaxVersion),
		TLSReloadInterval: p.cfg.TLSReloadInterval, UpstreamDialTimeout: p.cfg.UpstreamDialTimeout,
		UpstreamTLSHandshakeTimeout: p.cfg.UpstreamTLSHandshakeTimeout, UpstreamResponseHeaderTimeout: p.cfg.UpstreamResponseHeaderTimeout,
		UpstreamRequestTimeout: p.cfg.UpstreamRequestTimeout, UpstreamIdleConnTimeout: p.cfg.UpstreamIdleConnTimeout,
		UpstreamMaxIdleConns: p.cfg.UpstreamMaxIdleConns, UpstreamBreakerThreshold: u.Breaker.Threshold, UpstreamBreakerOpenInterval: u.Breaker.OpenInterval,
	})
	if err != nil {
		return nil, err
	}
	p.routes[u.ID] = proxy
	return proxy, nil
}

func routeTLSMin(value string, fallback uint16) uint16 {
	if value == "" {
		return fallback
	}
	return parseTLSVersion(value)
}

func routeTLSMax(value string, fallback uint16) uint16 {
	if value == "" {
		return fallback
	}
	return parseTLSVersion(value)
}

func (p *RoutedProxy) Forward(r *http.Request, body []byte, in routing.Input) (*http.Response, routing.Selection, error) {
	candidates, err := p.manager.Candidates(in)
	if err != nil {
		return nil, routing.Selection{}, err
	}
	for i, candidate := range candidates {
		if i > 0 && !in.AllowFailover {
			break
		}
		proxy, err := p.proxyFor(candidate.Route)
		if err != nil {
			continue
		}
		forwardBody := body
		if candidate.RoutedModel != candidate.RequestedModel && candidate.RequestedModel != "" {
			var rewriteErr error
			forwardBody, rewriteErr = rewriteRoutedModel(body, candidate.RequestedModel, candidate.RoutedModel)
			if rewriteErr != nil {
				return nil, routing.Selection{}, rewriteErr
			}
		}
		resp, ferr := proxy.ForwardWithPathPrefix(r, forwardBody, candidate.Route.PathPrefix)
		if ferr == nil {
			candidate.Failover = i > 0
			p.manager.Record(candidate.Route.ID, resp.StatusCode < http.StatusInternalServerError)
			return resp, candidate, nil
		}
		p.manager.Record(candidate.Route.ID, false)
		// POST failover is permitted only for a clear dial failure, where no
		// request bytes have been handed to an upstream connection. EOFs,
		// timeouts, and write errors are treated as uncertain delivery.
		if r.Method == http.MethodPost && !safeToRetryBeforeDelivery(ferr) {
			return nil, routing.Selection{}, ferr
		}
	}
	if in.Action == core.ActionForceLocalModel {
		return nil, routing.Selection{}, errors.New("ROUTE_LOCAL_UNAVAILABLE")
	}
	return nil, routing.Selection{}, errors.New("ROUTE_UNAVAILABLE")
}

func safeToRetryBeforeDelivery(err error) bool {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return false
	}
	var netErr interface {
		Error() string
		Timeout() bool
	}
	if !errors.As(urlErr.Err, &netErr) {
		return false
	}
	return strings.EqualFold(urlErr.Op, "Get") || strings.Contains(strings.ToLower(urlErr.Err.Error()), "dial")
}

func (p *RoutedProxy) Status() []routing.RouteStatus { return p.manager.Status() }
func (p *RoutedProxy) Manager() *routing.Manager     { return p.manager }

func (p *RoutedProxy) SetRouteMetrics(metrics interface {
	ObserveRouteHealth(string, string, string, bool)
}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics = metrics
}

func (p *RoutedProxy) observeHealth(id, class, state string, healthy bool) {
	p.mu.Lock()
	metrics := p.metrics
	p.mu.Unlock()
	if metrics != nil {
		metrics.ObserveRouteHealth(id, class, state, healthy)
	}
}

func (p *RoutedProxy) SetSecureMaterialMetrics(metrics securetransport.Metrics) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, proxy := range p.routes {
		proxy.SetSecureMaterialMetrics(metrics)
	}
}

func (p *RoutedProxy) MaterialStatuses() map[string]func() securetransport.Status {
	out := map[string]func() securetransport.Status{}
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, proxy := range p.routes {
		for name, status := range proxy.MaterialStatuses() {
			out["route_"+id+"_"+name] = status
		}
	}
	return out
}

func (p *RoutedProxy) Reload() error {
	if err := p.manager.Reload(); err != nil {
		return err
	}
	for _, upstream := range p.manager.Snapshot().Registry.Upstreams {
		if _, err := p.proxyFor(upstream); err != nil {
			return errors.New("route transport unavailable")
		}
	}
	return nil
}

func (p *RoutedProxy) Readiness() string {
	for _, status := range p.manager.Status() {
		if status.Enabled && status.Healthy && status.Breaker != "open" {
			return ""
		}
	}
	return "no healthy enabled upstream route"
}

func (p *RoutedProxy) healthLoop() {
	defer close(p.done)
	for {
		select {
		case <-time.After(p.healthInterval()):
			p.checkHealth()
		case <-p.stop:
			return
		}
	}
}

func (p *RoutedProxy) healthInterval() time.Duration {
	interval := 10 * time.Second
	if s := p.manager.Snapshot(); s != nil {
		for _, u := range s.Registry.Upstreams {
			if u.Health.Interval < interval {
				interval = u.Health.Interval
			}
		}
	}
	return interval
}

func (p *RoutedProxy) checkHealth() {
	s := p.manager.Snapshot()
	if s == nil {
		return
	}
	for _, u := range s.Registry.Upstreams {
		if !u.Enabled {
			p.manager.SetHealth(u.ID, false)
			p.observeHealth(u.ID, string(u.Class), "disabled", false)
			continue
		}
		proxy, err := p.proxyFor(u)
		if err != nil {
			p.manager.SetHealth(u.ID, false)
			p.observeHealth(u.ID, string(u.Class), "unavailable", false)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), u.Health.Timeout)
		target := *proxy.baseURL
		target.Path = joinPath(target.Path, u.Health.Endpoint)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if reqErr == nil {
			resp, callErr := proxy.client.Do(req)
			if callErr == nil {
				resp.Body.Close()
				healthy := resp.StatusCode < 500
				p.manager.SetHealth(u.ID, healthy)
				state := "healthy"
				if !healthy {
					state = "unhealthy"
				}
				p.observeHealth(u.ID, string(u.Class), state, healthy)
			} else {
				p.manager.SetHealth(u.ID, false)
				p.observeHealth(u.ID, string(u.Class), "unavailable", false)
			}
		} else {
			p.manager.SetHealth(u.ID, false)
			p.observeHealth(u.ID, string(u.Class), "unavailable", false)
		}
		cancel()
	}
}

func (p *RoutedProxy) Close() {
	if p == nil {
		return
	}
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
	if p.done != nil {
		select {
		case <-p.done:
		case <-time.After(time.Second):
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, proxy := range p.routes {
		proxy.Close()
	}
	p.routes = map[string]*Proxy{}
}

func capabilityFor(path string, stream, tools bool) string {
	switch {
	case strings.Contains(path, "embeddings"):
		return "embeddings"
	case strings.Contains(path, "responses") || strings.HasSuffix(path, "/response"):
		return "responses"
	case strings.Contains(path, "messages") || strings.HasSuffix(path, "/message"):
		return "messages"
	default:
		return "chat"
	}
}

func routeInput(env *core.InspectionEnvelope, path string, action core.Action, c routing.Constraint) routing.Input {
	stream := env.Metadata["stream"] == "true"
	tools := len(env.Tools) > 0
	provider := ""
	if env.Metadata["verified_provider"] == "true" {
		provider = env.Target.Provider
	}
	return routing.Input{Action: action, RequestedModel: env.Target.Model, Family: env.Metadata["endpoint_family"], Capability: capabilityFor(path, stream, tools), Streaming: stream, Tools: tools,
		VerifiedTenant: env.Tenant, VerifiedApplication: env.Application, VerifiedProvider: provider, RequestedProvider: env.Target.Provider, Constraint: c,
		AllowFailover: len(c.Routes) > 0 || c.FallbackChain != ""}
}

func rewriteRoutedModel(raw []byte, requested, routed string) ([]byte, error) {
	if requested == routed || requested == "" {
		return raw, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.New("routed model rewrite failed")
	}
	modelJSON, _ := json.Marshal(routed)
	doc["model"] = modelJSON
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, errors.New("routed model rewrite failed")
	}
	return out, nil
}
