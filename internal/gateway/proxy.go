package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/securetransport"
)

var ErrUpstreamBreakerOpen = decision.ErrCircuitOpen

// Proxy forwards policy-approved requests to the upstream LLM Gateway (FR-002).
// Upstream credentials come exclusively from configuration — inbound client
// credentials are never forwarded.
type Proxy struct {
	baseURL *url.URL
	client  *http.Client
	cfg     Config
	breaker *decision.CircuitBreaker
	apiKey  *securetransport.File[string]
	header  *securetransport.File[string]
	certs   []*securetransport.File[tls.Certificate]
}

// NewProxy validates configuration and builds the upstream proxy.
func NewProxy(cfg Config) (*Proxy, error) {
	cfg = cfg.withRuntimeDefaults()
	if cfg.UpstreamBaseURL == "" {
		return nil, fmt.Errorf("UPSTREAM_BASE_URL is required")
	}
	u, err := url.Parse(cfg.UpstreamBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid UPSTREAM_BASE_URL")
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid UPSTREAM_BASE_URL")
	}
	switch cfg.UpstreamAuthMode {
	case "none":
	case "bearer":
		if cfg.UpstreamAPIKey == "" && cfg.UpstreamAPIKeyFile == "" {
			return nil, fmt.Errorf("UPSTREAM_API_KEY is required when UPSTREAM_AUTH_MODE=bearer")
		}
	case "header":
		if cfg.UpstreamAuthHeaderName == "" || (cfg.UpstreamAuthHeaderValue == "" && cfg.UpstreamAuthHeaderValueFile == "") {
			return nil, fmt.Errorf("UPSTREAM_AUTH_HEADER_NAME and UPSTREAM_AUTH_HEADER_VALUE are required when UPSTREAM_AUTH_MODE=header")
		}
	default:
		return nil, fmt.Errorf("unsupported UPSTREAM_AUTH_MODE: %s", cfg.UpstreamAuthMode)
	}
	tlsConfig, certs, err := (securetransport.ClientTLSOptions{
		CAFile: cfg.UpstreamTLSCAFile, CertificateFile: cfg.UpstreamTLSCertFile, KeyFile: cfg.UpstreamTLSKeyFile,
		ServerName: cfg.UpstreamTLSServerName, MinVersion: cfg.TLSMinVersion, MaxVersion: cfg.TLSMaxVersion,
		PollInterval: cfg.TLSReloadInterval,
	}).TLSConfig()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: cfg.UpstreamDialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   cfg.UpstreamTLSHandshakeTimeout,
		ResponseHeaderTimeout: cfg.UpstreamResponseHeaderTimeout,
		IdleConnTimeout:       cfg.UpstreamIdleConnTimeout,
		MaxIdleConns:          cfg.UpstreamMaxIdleConns,
		MaxIdleConnsPerHost:   cfg.UpstreamMaxIdleConns,
		TLSClientConfig:       tlsConfig,
	}
	p := &Proxy{
		baseURL: u, client: &http.Client{Transport: transport, Timeout: cfg.UpstreamRequestTimeout}, cfg: cfg,
		breaker: decision.NewCircuitBreaker(cfg.UpstreamBreakerThreshold, cfg.UpstreamBreakerOpenInterval), certs: certs,
	}
	if cfg.UpstreamAPIKeyFile != "" {
		p.apiKey, err = securetransport.SecretFile(cfg.UpstreamAPIKeyFile, cfg.TLSReloadInterval, nil)
		if err != nil {
			p.Close()
			return nil, errors.New("UPSTREAM_API_KEY_FILE is invalid")
		}
	}
	if cfg.UpstreamAuthHeaderValueFile != "" {
		p.header, err = securetransport.SecretFile(cfg.UpstreamAuthHeaderValueFile, cfg.TLSReloadInterval, nil)
		if err != nil {
			p.Close()
			return nil, errors.New("UPSTREAM_AUTH_HEADER_VALUE_FILE is invalid")
		}
	}
	return p, nil
}

// Forward sends the raw request body to the upstream gateway at the same path.
func (p *Proxy) Forward(r *http.Request, body []byte) (*http.Response, error) {
	if !p.breaker.Allow() {
		return nil, ErrUpstreamBreakerOpen
	}
	target := *p.baseURL
	path := r.URL.Path
	if prefix := strings.TrimSuffix(p.cfg.UpstreamChatPathPrefix, "/"); prefix != "" && (path == prefix || strings.HasPrefix(path, prefix+"/")) {
		path = strings.TrimPrefix(path, prefix)
		if path == "" {
			path = "/"
		}
	}
	target.Path = joinPath(p.baseURL.Path, path)

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	// Forward only protocol headers. In particular, client Authorization and
	// identity headers never cross the trust boundary; upstream credentials are
	// applied below from gateway configuration only.
	for _, h := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	switch p.cfg.UpstreamAuthMode {
	case "bearer":
		value := p.cfg.UpstreamAPIKey
		if p.apiKey != nil {
			value, err = p.apiKey.Get()
			if err != nil {
				return nil, errors.New("upstream credential unavailable")
			}
		}
		req.Header.Set("Authorization", "Bearer "+value)
	case "header":
		value := p.cfg.UpstreamAuthHeaderValue
		if p.header != nil {
			value, err = p.header.Get()
			if err != nil {
				return nil, errors.New("upstream credential unavailable")
			}
		}
		req.Header.Set(p.cfg.UpstreamAuthHeaderName, value)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.breaker.Record(false)
		return nil, err
	}
	// A 5xx is a dependency failure for breaker purposes, but the response is
	// returned so the server can apply its normal bounded-body handling.
	p.breaker.Record(resp.StatusCode < http.StatusInternalServerError)
	return resp, nil
}

func (p *Proxy) Close() {
	if p == nil {
		return
	}
	if p.apiKey != nil {
		p.apiKey.Close()
	}
	if p.header != nil {
		p.header.Close()
	}
	for _, file := range p.certs {
		file.Close()
	}
	if transport, ok := p.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (p *Proxy) MaterialStatuses() map[string]func() securetransport.Status {
	result := map[string]func() securetransport.Status{}
	if p == nil {
		return result
	}
	if p.apiKey != nil {
		result["upstream_credential"] = p.apiKey.Status
	}
	if p.header != nil {
		result["upstream_header_credential"] = p.header.Status
	}
	for i, file := range p.certs {
		result[fmt.Sprintf("upstream_client_certificate_%d", i+1)] = file.Status
	}
	return result
}

func (p *Proxy) SetSecureMaterialMetrics(metrics securetransport.Metrics) {
	if p == nil {
		return
	}
	if p.apiKey != nil {
		p.apiKey.SetMetrics(metrics)
	}
	if p.header != nil {
		p.header.SetMetrics(metrics)
	}
	for _, file := range p.certs {
		file.SetMetrics(metrics)
	}
}

func (p *Proxy) Readiness() string {
	if p == nil || p.breaker == nil {
		return ""
	}
	if p.breaker.State() == "open" {
		return "breaker open"
	}
	return ""
}

func (p *Proxy) RecordFailure() {
	if p != nil && p.breaker != nil {
		p.breaker.Record(false)
	}
}

func upstreamTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func joinPath(base, path string) string {
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(path, "/")
}
