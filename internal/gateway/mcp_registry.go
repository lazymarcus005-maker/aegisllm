package gateway

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
	"gopkg.in/yaml.v3"
)

// MCPRegistry is the versioned, operator-controlled MCP trust registry.
// Values are configuration metadata only; credential_ref is always opaque.
type MCPRegistry struct {
	Schema  string            `yaml:"schema"`
	Version int               `yaml:"version"`
	Servers []MCPServerConfig `yaml:"servers"`
}

type MCPServerConfig struct {
	ID                  string              `yaml:"id"`
	URL                 string              `yaml:"url"`
	TLS                 MCPTLSConfig        `yaml:"tls,omitempty"`
	Capabilities        map[string]bool     `yaml:"capabilities,omitempty"`
	AllowedToolPatterns []string            `yaml:"allowed_tool_patterns,omitempty"`
	AllowedTools        []string            `yaml:"allowed_tools,omitempty"`
	AllowedMethods      []string            `yaml:"allowed_methods,omitempty"`
	ToolSchemaPolicy    MCPToolSchemaPolicy `yaml:"tool_schema_policy,omitempty"`
	CredentialRef       string              `yaml:"credential_ref,omitempty"`
	CredentialProfile   string              `yaml:"credential_profile,omitempty"`
	Timeout             string              `yaml:"timeout,omitempty"`
	Concurrency         int                 `yaml:"concurrency,omitempty"`
	Breaker             MCPBreakerConfig    `yaml:"breaker,omitempty"`
	Enabled             bool                `yaml:"enabled"`
	Health              MCPHealthConfig     `yaml:"health,omitempty"`
}

type MCPTLSConfig struct {
	CAFile          string `yaml:"ca_file,omitempty"`
	CertificateFile string `yaml:"certificate_file,omitempty"`
	KeyFile         string `yaml:"key_file,omitempty"`
	ServerName      string `yaml:"server_name,omitempty"`
	MinVersion      string `yaml:"min_version,omitempty"`
	MaxVersion      string `yaml:"max_version,omitempty"`
}

type MCPToolSchemaPolicy struct {
	MaxBytes int    `yaml:"max_bytes,omitempty"`
	MaxDepth int    `yaml:"max_depth,omitempty"`
	TTL      string `yaml:"ttl,omitempty"`
}

type MCPBreakerConfig struct {
	Threshold    int    `yaml:"threshold,omitempty"`
	OpenInterval string `yaml:"open_interval,omitempty"`
}

type MCPHealthConfig struct {
	Endpoint string `yaml:"endpoint,omitempty"`
	Interval string `yaml:"interval,omitempty"`
	Timeout  string `yaml:"timeout,omitempty"`
}

type mcpRegistryManager struct {
	file *securetransport.File[MCPRegistry]
}

func newMCPRegistry(path string, interval time.Duration, allowInsecure ...bool) (*mcpRegistryManager, error) {
	allowHTTP := len(allowInsecure) > 0 && allowInsecure[0]
	f, err := securetransport.NewFile(path, interval, func(data []byte) (MCPRegistry, time.Time, error) {
		var reg MCPRegistry
		if err := yaml.Unmarshal(data, &reg); err != nil {
			return MCPRegistry{}, time.Time{}, errors.New("MCP registry is invalid")
		}
		if err := validateMCPRegistryMode(reg, allowHTTP); err != nil {
			return MCPRegistry{}, time.Time{}, err
		}
		return reg, time.Time{}, nil
	}, nil)
	if err != nil {
		return nil, err
	}
	return &mcpRegistryManager{file: f}, nil
}

func validateMCPRegistryMode(reg MCPRegistry, allowHTTP bool) error {
	if reg.Schema != "aegisllm.mcp/v1" || reg.Version != 1 || len(reg.Servers) == 0 {
		return errors.New("MCP registry version or servers are invalid")
	}
	seen := map[string]bool{}
	for _, server := range reg.Servers {
		if !safeMCPValue(server.ID) || seen[server.ID] || strings.TrimSpace(server.URL) == "" {
			return errors.New("MCP server identity is invalid")
		}
		seen[server.ID] = true
		u, err := url.Parse(server.URL)
		if err != nil || u.User != nil || u.Host == "" || u.Fragment != "" {
			return errors.New("MCP server URL is invalid")
		}
		if !strings.EqualFold(u.Scheme, "https") && !allowHTTP {
			return errors.New("MCP server URL must use HTTPS")
		}
		for key := range u.Query() {
			low := strings.ToLower(key)
			if strings.Contains(low, "secret") || strings.Contains(low, "token") || strings.Contains(low, "password") || strings.Contains(low, "key") || low == "auth" {
				return errors.New("MCP server URL contains inline credential material")
			}
		}
		if server.Concurrency < 0 || server.Breaker.Threshold < 0 {
			return errors.New("MCP server resilience limits are invalid")
		}
		if server.ToolSchemaPolicy.MaxBytes < 0 || server.ToolSchemaPolicy.MaxDepth < 0 {
			return errors.New("MCP tool schema limits are invalid")
		}
		if server.TLS.CertificateFile != "" || server.TLS.KeyFile != "" {
			if server.TLS.CertificateFile == "" || server.TLS.KeyFile == "" {
				return errors.New("MCP TLS certificate and key must be paired")
			}
		}
	}
	return nil
}

func safeMCPValue(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return false
		}
	}
	return true
}

func (m *mcpRegistryManager) snapshot() (MCPRegistry, error) {
	if m == nil || m.file == nil {
		return MCPRegistry{}, errors.New("MCP registry unavailable")
	}
	return m.file.Get()
}

func (m *mcpRegistryManager) server(id string) (MCPServerConfig, error) {
	reg, err := m.snapshot()
	if err != nil {
		return MCPServerConfig{}, err
	}
	for _, server := range reg.Servers {
		if server.ID == id {
			return server, nil
		}
	}
	return MCPServerConfig{}, errors.New("MCP server unavailable")
}

func (m *mcpRegistryManager) close() {
	if m != nil && m.file != nil {
		m.file.Close()
	}
}

func (m *mcpRegistryManager) status() securetransport.Status {
	if m == nil || m.file == nil {
		return securetransport.Status{}
	}
	return m.file.Status()
}

func (m *mcpRegistryManager) setMetrics(metrics securetransport.Metrics) {
	if m != nil && m.file != nil {
		m.file.SetMetrics(metrics)
	}
}

func (s MCPServerConfig) timeout(fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(s.Timeout); err == nil && d > 0 {
		return d
	}
	return fallback
}

func (s MCPServerConfig) schemaLimits() (int, int, time.Duration) {
	bytes, depth, ttl := s.ToolSchemaPolicy.MaxBytes, s.ToolSchemaPolicy.MaxDepth, 5*time.Minute
	if bytes <= 0 {
		bytes = 256 * 1024
	}
	if depth <= 0 {
		depth = 16
	}
	if d, err := time.ParseDuration(s.ToolSchemaPolicy.TTL); err == nil && d > 0 {
		ttl = d
	}
	return bytes, depth, ttl
}

func (s MCPServerConfig) allowedMethod(method string) bool {
	allowed := s.AllowedMethods
	if len(allowed) == 0 {
		allowed = []string{"initialize", "notifications/initialized", "ping", "tools/list", "tools/call"}
	}
	for _, candidate := range allowed {
		if candidate == method {
			return true
		}
	}
	return false
}

func (s MCPServerConfig) allowedTools() []string {
	if len(s.AllowedToolPatterns) > 0 {
		return s.AllowedToolPatterns
	}
	return s.AllowedTools
}

func (s MCPServerConfig) credentialRef() string {
	if s.CredentialRef != "" {
		return s.CredentialRef
	}
	return s.CredentialProfile
}
