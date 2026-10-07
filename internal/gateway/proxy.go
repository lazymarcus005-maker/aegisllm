package gateway

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Proxy forwards policy-approved requests to the upstream LLM Gateway (FR-002).
// Upstream credentials come exclusively from configuration — inbound client
// credentials are never forwarded.
type Proxy struct {
	baseURL *url.URL
	client  *http.Client
	cfg     Config
}

// NewProxy validates configuration and builds the upstream proxy.
func NewProxy(cfg Config) (*Proxy, error) {
	if cfg.UpstreamBaseURL == "" {
		return nil, fmt.Errorf("UPSTREAM_BASE_URL is required")
	}
	u, err := url.Parse(cfg.UpstreamBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid UPSTREAM_BASE_URL: %w", err)
	}
	switch cfg.UpstreamAuthMode {
	case "none":
	case "bearer":
		if cfg.UpstreamAPIKey == "" {
			return nil, fmt.Errorf("UPSTREAM_API_KEY is required when UPSTREAM_AUTH_MODE=bearer")
		}
	case "header":
		if cfg.UpstreamAuthHeaderName == "" || cfg.UpstreamAuthHeaderValue == "" {
			return nil, fmt.Errorf("UPSTREAM_AUTH_HEADER_NAME and UPSTREAM_AUTH_HEADER_VALUE are required when UPSTREAM_AUTH_MODE=header")
		}
	default:
		return nil, fmt.Errorf("unsupported UPSTREAM_AUTH_MODE: %s", cfg.UpstreamAuthMode)
	}
	return &Proxy{baseURL: u, client: &http.Client{}, cfg: cfg}, nil
}

// Forward sends the raw request body to the upstream gateway at the same path.
func (p *Proxy) Forward(r *http.Request, body []byte) (*http.Response, error) {
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
	for _, h := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	switch p.cfg.UpstreamAuthMode {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+p.cfg.UpstreamAPIKey)
	case "header":
		req.Header.Set(p.cfg.UpstreamAuthHeaderName, p.cfg.UpstreamAuthHeaderValue)
	}
	return p.client.Do(req)
}

func joinPath(base, path string) string {
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(path, "/")
}
