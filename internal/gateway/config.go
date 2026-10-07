package gateway

import (
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/auth"
	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/policy"
)

// DeploymentProfile selects the operational safety contract for the gateway.
type DeploymentProfile string

const (
	ProfileDevelopment DeploymentProfile = "development"
	ProfileShadow      DeploymentProfile = "shadow"
	ProfileProduction  DeploymentProfile = "production"
)

// Security modes (FR-018).
const (
	ModeOff     = "off"
	ModeShadow  = "shadow"
	ModeEnforce = "enforce"
)

// Config holds all gateway runtime configuration, sourced from the
// environment (see .env.example).
type Config struct {
	DeploymentProfile             DeploymentProfile
	ListenAddr                    string
	UpstreamBaseURL               string
	UpstreamAuthMode              string // none | bearer | header
	UpstreamAPIKey                string
	UpstreamAuthHeaderName        string
	UpstreamAuthHeaderValue       string
	UpstreamChatPathPrefix        string
	UpstreamDialTimeout           time.Duration
	UpstreamTLSHandshakeTimeout   time.Duration
	UpstreamResponseHeaderTimeout time.Duration
	UpstreamRequestTimeout        time.Duration
	UpstreamIdleConnTimeout       time.Duration
	UpstreamMaxIdleConns          int
	MaxBodyBytes                  int64
	MaxResponseBytes              int64
	MaxPromptChars                int
	MaxStreamDuration             time.Duration
	RequestsPerSecond             float64
	RateBurst                     int
	MaxConcurrentRequests         int
	MaxConcurrentLaya             int
	LimiterMaxKeys                int
	LimiterKeyIdleTimeout         time.Duration
	UpstreamBreakerThreshold      int
	UpstreamBreakerOpenInterval   time.Duration
	ServerReadHeaderTimeout       time.Duration
	ServerReadTimeout             time.Duration
	ServerIdleTimeout             time.Duration
	ServerShutdownTimeout         time.Duration
	SecurityMode                  string // off | shadow | enforce
	HeaderApplication             string
	HeaderTenant                  string
	HeaderUser                    string
	HeaderTargetProvider          string
	DefaultTargetProvider         string
	PolicyFile                    string
	QuestionsFile                 string
	ThresholdsFile                string
	TokenVaultKey                 string
	TokenVaultRedisURL            string
	TelemetryHMACKey              string
	AuthMode                      string // off | jwt
	JWTPublicKeyFile              string
	JWTHMACSecret                 string
	JWTIssuer                     string
	JWTAudience                   string
	JWTTenantClaim                string
	JWTApplicationClaim           string
	JWTSubjectClaim               string
	JWTRolesClaim                 string
	JWTProviderClaim              string
	AllowUnauthenticatedShadow    bool
}

// LoadConfig reads configuration from the process environment.
func LoadConfig() Config {
	return configFrom(os.Getenv)
}

func configFrom(get func(string) string) Config {
	profileValue := getenvDefault(get, "DEPLOYMENT_PROFILE", string(ProfileDevelopment))
	profile, err := ParseDeploymentProfile(profileValue)
	if err != nil {
		// Preserve the invalid value so ValidateConfig can report it at startup.
		profile = DeploymentProfile(profileValue)
	}
	return Config{
		DeploymentProfile:             profile,
		ListenAddr:                    getenvDefault(get, "LISTEN_ADDR", ":8080"),
		UpstreamBaseURL:               get("UPSTREAM_BASE_URL"),
		UpstreamAuthMode:              getenvDefault(get, "UPSTREAM_AUTH_MODE", "none"),
		UpstreamAPIKey:                get("UPSTREAM_API_KEY"),
		UpstreamAuthHeaderName:        getenvDefault(get, "UPSTREAM_AUTH_HEADER_NAME", "X-Upstream-Api-Key"),
		UpstreamAuthHeaderValue:       get("UPSTREAM_AUTH_HEADER_VALUE"),
		UpstreamChatPathPrefix:        get("UPSTREAM_CHAT_PATH_PREFIX"),
		UpstreamDialTimeout:           getenvDuration(get, "UPSTREAM_DIAL_TIMEOUT", 5*time.Second),
		UpstreamTLSHandshakeTimeout:   getenvDuration(get, "UPSTREAM_TLS_HANDSHAKE_TIMEOUT", 5*time.Second),
		UpstreamResponseHeaderTimeout: getenvDuration(get, "UPSTREAM_RESPONSE_HEADER_TIMEOUT", 30*time.Second),
		UpstreamRequestTimeout:        getenvDuration(get, "UPSTREAM_REQUEST_TIMEOUT", 2*time.Minute),
		UpstreamIdleConnTimeout:       getenvDuration(get, "UPSTREAM_IDLE_CONN_TIMEOUT", 90*time.Second),
		UpstreamMaxIdleConns:          getenvInt(get, "UPSTREAM_MAX_IDLE_CONNS", 100),
		MaxBodyBytes:                  getenvInt64(get, "MAX_BODY_BYTES", 1<<20),
		MaxResponseBytes:              getenvInt64(get, "MAX_RESPONSE_BYTES", 4<<20),
		MaxPromptChars:                getenvInt(get, "MAX_PROMPT_CHARS", 64*1024),
		MaxStreamDuration:             getenvDuration(get, "MAX_STREAM_DURATION", 5*time.Minute),
		RequestsPerSecond:             getenvFloat(get, "REQUESTS_PER_SECOND", 10),
		RateBurst:                     getenvInt(get, "RATE_BURST", 20),
		MaxConcurrentRequests:         getenvInt(get, "MAX_CONCURRENT_REQUESTS", 16),
		MaxConcurrentLaya:             getenvInt(get, "MAX_CONCURRENT_LAYA", 4),
		LimiterMaxKeys:                getenvInt(get, "LIMITER_MAX_KEYS", 10000),
		LimiterKeyIdleTimeout:         getenvDuration(get, "LIMITER_KEY_IDLE_TIMEOUT", 10*time.Minute),
		UpstreamBreakerThreshold:      getenvInt(get, "UPSTREAM_BREAKER_FAILURE_THRESHOLD", 3),
		UpstreamBreakerOpenInterval:   getenvDuration(get, "UPSTREAM_BREAKER_OPEN_INTERVAL", 30*time.Second),
		ServerReadHeaderTimeout:       getenvDuration(get, "SERVER_READ_HEADER_TIMEOUT", 10*time.Second),
		ServerReadTimeout:             getenvDuration(get, "SERVER_READ_TIMEOUT", 30*time.Second),
		ServerIdleTimeout:             getenvDuration(get, "SERVER_IDLE_TIMEOUT", 2*time.Minute),
		ServerShutdownTimeout:         getenvDuration(get, "SERVER_SHUTDOWN_TIMEOUT", 10*time.Second),
		SecurityMode:                  getenvDefault(get, "SECURITY_MODE", ModeOff),
		HeaderApplication:             getenvDefault(get, "HEADER_APPLICATION", "X-Application-Id"),
		HeaderTenant:                  getenvDefault(get, "HEADER_TENANT", "X-Tenant-Id"),
		HeaderUser:                    getenvDefault(get, "HEADER_USER", "X-User-Id"),
		HeaderTargetProvider:          getenvDefault(get, "HEADER_TARGET_PROVIDER", "X-Target-Provider"),
		DefaultTargetProvider:         getenvDefault(get, "DEFAULT_TARGET_PROVIDER", "cloud"),
		PolicyFile:                    getenvDefault(get, "POLICY_FILE", "policies/enterprise-default.yaml"),
		QuestionsFile:                 getenvDefault(get, "QUESTIONS_FILE", "questions/security-v1.yaml"),
		ThresholdsFile:                getenvDefault(get, "THRESHOLDS_FILE", "policies/thresholds-security-v1.yaml"),
		TokenVaultKey:                 get("TOKEN_VAULT_KEY"),
		TokenVaultRedisURL:            get("TOKEN_VAULT_REDIS_URL"),
		TelemetryHMACKey:              get("TELEMETRY_HMAC_KEY"),
		AuthMode:                      getenvDefault(get, "AUTH_MODE", auth.ModeOff),
		JWTPublicKeyFile:              get("JWT_PUBLIC_KEY_FILE"),
		JWTHMACSecret:                 get("JWT_HMAC_SECRET"),
		JWTIssuer:                     get("JWT_ISSUER"),
		JWTAudience:                   get("JWT_AUDIENCE"),
		JWTTenantClaim:                getenvDefault(get, "JWT_TENANT_CLAIM", "tenant_id"),
		JWTApplicationClaim:           getenvDefault(get, "JWT_APPLICATION_CLAIM", "azp"),
		JWTSubjectClaim:               getenvDefault(get, "JWT_SUBJECT_CLAIM", "sub"),
		JWTRolesClaim:                 getenvDefault(get, "JWT_ROLES_CLAIM", "roles"),
		JWTProviderClaim:              getenvDefault(get, "JWT_PROVIDER_CLAIM", "provider"),
		AllowUnauthenticatedShadow:    strings.EqualFold(get("ALLOW_UNAUTHENTICATED_SHADOW"), "true"),
	}
}

// ParseDeploymentProfile parses the public DEPLOYMENT_PROFILE values.
func ParseDeploymentProfile(value string) (DeploymentProfile, error) {
	if value == "" {
		return ProfileDevelopment, nil
	}
	profile := DeploymentProfile(strings.ToLower(strings.TrimSpace(value)))
	switch profile {
	case ProfileDevelopment, ProfileShadow, ProfileProduction:
		return profile, nil
	default:
		return "", errors.New("DEPLOYMENT_PROFILE must be one of: development, shadow, production")
	}
}

func (c Config) profile() DeploymentProfile {
	if c.DeploymentProfile == "" {
		return ProfileDevelopment
	}
	return c.DeploymentProfile
}

// ValidateConfig checks the deployment safety contract before server startup.
// Production validation intentionally discards parser details so malformed
// config cannot echo secret-bearing or raw file content into logs.
func ValidateConfig(cfg Config) error {
	profile, err := ParseDeploymentProfile(string(cfg.profile()))
	if err != nil {
		return err
	}
	if !validSecurityMode(cfg.SecurityMode) {
		return errors.New("SECURITY_MODE must be one of: off, shadow, enforce")
	}
	if profile == ProfileShadow && cfg.SecurityMode != ModeShadow {
		return errors.New("shadow deployment requires SECURITY_MODE=shadow")
	}
	if err := validateAuthConfig(cfg, profile); err != nil {
		return err
	}
	if profile != ProfileProduction {
		return nil
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		return err
	}
	if cfg.SecurityMode != ModeEnforce {
		return errors.New("production requires SECURITY_MODE=enforce")
	}
	if cfg.AuthMode != auth.ModeJWT {
		return errors.New("production requires AUTH_MODE=jwt")
	}
	if strings.TrimSpace(cfg.JWTIssuer) == "" {
		return errors.New("production requires JWT_ISSUER")
	}
	if strings.TrimSpace(cfg.JWTAudience) == "" {
		return errors.New("production requires JWT_AUDIENCE")
	}
	if strings.TrimSpace(cfg.JWTPublicKeyFile) == "" || strings.TrimSpace(cfg.JWTHMACSecret) != "" {
		return errors.New("production requires an asymmetric JWT_PUBLIC_KEY_FILE")
	}
	if len(cfg.TokenVaultKey) != 64 {
		return errors.New("TOKEN_VAULT_KEY must be 64 hex chars")
	}
	if _, err := hex.DecodeString(cfg.TokenVaultKey); err != nil {
		return errors.New("TOKEN_VAULT_KEY must be 64 hex chars")
	}
	if strings.TrimSpace(cfg.TokenVaultRedisURL) == "" {
		return errors.New("TOKEN_VAULT_REDIS_URL is required")
	}
	if !validDependencyURL(cfg.TokenVaultRedisURL) {
		return errors.New("TOKEN_VAULT_REDIS_URL is invalid")
	}
	if strings.TrimSpace(cfg.TelemetryHMACKey) == "" {
		return errors.New("TELEMETRY_HMAC_KEY is required")
	}
	if strings.TrimSpace(cfg.UpstreamBaseURL) == "" {
		return errors.New("UPSTREAM_BASE_URL is required")
	}
	upstream, ok := parseDependencyURL(cfg.UpstreamBaseURL)
	if !ok {
		return errors.New("UPSTREAM_BASE_URL is invalid")
	}
	if isMockUpstream(upstream.Hostname()) {
		return errors.New("UPSTREAM_BASE_URL must not reference a mock upstream")
	}
	if err := validatePolicyFile(cfg.PolicyFile); err != nil {
		return err
	}
	if err := validateQuestionsFile(cfg.QuestionsFile); err != nil {
		return err
	}
	if err := validateThresholdsFile(cfg.ThresholdsFile); err != nil {
		return err
	}
	return nil
}

// withRuntimeDefaults keeps programmatic development/test configurations
// compatible with the environment-backed defaults without weakening the
// production validation contract.
func (c Config) withRuntimeDefaults() Config {
	defaults := configFrom(func(string) string { return "" })
	if c.UpstreamDialTimeout <= 0 {
		c.UpstreamDialTimeout = defaults.UpstreamDialTimeout
	}
	if c.UpstreamTLSHandshakeTimeout <= 0 {
		c.UpstreamTLSHandshakeTimeout = defaults.UpstreamTLSHandshakeTimeout
	}
	if c.UpstreamResponseHeaderTimeout <= 0 {
		c.UpstreamResponseHeaderTimeout = defaults.UpstreamResponseHeaderTimeout
	}
	if c.UpstreamRequestTimeout <= 0 {
		c.UpstreamRequestTimeout = defaults.UpstreamRequestTimeout
	}
	if c.UpstreamIdleConnTimeout <= 0 {
		c.UpstreamIdleConnTimeout = defaults.UpstreamIdleConnTimeout
	}
	if c.UpstreamMaxIdleConns <= 0 {
		c.UpstreamMaxIdleConns = defaults.UpstreamMaxIdleConns
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = defaults.MaxBodyBytes
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = defaults.MaxResponseBytes
	}
	if c.MaxPromptChars <= 0 {
		c.MaxPromptChars = defaults.MaxPromptChars
	}
	if c.MaxStreamDuration <= 0 {
		c.MaxStreamDuration = defaults.MaxStreamDuration
	}
	if c.RequestsPerSecond <= 0 {
		c.RequestsPerSecond = defaults.RequestsPerSecond
	}
	if c.RateBurst <= 0 {
		c.RateBurst = defaults.RateBurst
	}
	if c.MaxConcurrentRequests <= 0 {
		c.MaxConcurrentRequests = defaults.MaxConcurrentRequests
	}
	if c.MaxConcurrentLaya <= 0 {
		c.MaxConcurrentLaya = defaults.MaxConcurrentLaya
	}
	if c.LimiterMaxKeys <= 0 {
		c.LimiterMaxKeys = defaults.LimiterMaxKeys
	}
	if c.LimiterKeyIdleTimeout <= 0 {
		c.LimiterKeyIdleTimeout = defaults.LimiterKeyIdleTimeout
	}
	if c.UpstreamBreakerThreshold <= 0 {
		c.UpstreamBreakerThreshold = defaults.UpstreamBreakerThreshold
	}
	if c.UpstreamBreakerOpenInterval <= 0 {
		c.UpstreamBreakerOpenInterval = defaults.UpstreamBreakerOpenInterval
	}
	if c.ServerReadHeaderTimeout <= 0 {
		c.ServerReadHeaderTimeout = defaults.ServerReadHeaderTimeout
	}
	if c.ServerReadTimeout <= 0 {
		c.ServerReadTimeout = defaults.ServerReadTimeout
	}
	if c.ServerIdleTimeout <= 0 {
		c.ServerIdleTimeout = defaults.ServerIdleTimeout
	}
	if c.ServerShutdownTimeout <= 0 {
		c.ServerShutdownTimeout = defaults.ServerShutdownTimeout
	}
	return c
}

func validateRuntimeConfig(cfg Config) error {
	positiveDurations := []struct {
		name  string
		value time.Duration
	}{
		{"UPSTREAM_DIAL_TIMEOUT", cfg.UpstreamDialTimeout},
		{"UPSTREAM_TLS_HANDSHAKE_TIMEOUT", cfg.UpstreamTLSHandshakeTimeout},
		{"UPSTREAM_RESPONSE_HEADER_TIMEOUT", cfg.UpstreamResponseHeaderTimeout},
		{"UPSTREAM_REQUEST_TIMEOUT", cfg.UpstreamRequestTimeout},
		{"UPSTREAM_IDLE_CONN_TIMEOUT", cfg.UpstreamIdleConnTimeout},
		{"MAX_STREAM_DURATION", cfg.MaxStreamDuration},
		{"LIMITER_KEY_IDLE_TIMEOUT", cfg.LimiterKeyIdleTimeout},
		{"UPSTREAM_BREAKER_OPEN_INTERVAL", cfg.UpstreamBreakerOpenInterval},
		{"SERVER_READ_HEADER_TIMEOUT", cfg.ServerReadHeaderTimeout},
		{"SERVER_READ_TIMEOUT", cfg.ServerReadTimeout},
		{"SERVER_IDLE_TIMEOUT", cfg.ServerIdleTimeout},
		{"SERVER_SHUTDOWN_TIMEOUT", cfg.ServerShutdownTimeout},
	}
	for _, item := range positiveDurations {
		if item.value <= 0 {
			return errors.New(item.name + " must be positive")
		}
	}
	if cfg.MaxBodyBytes <= 0 || cfg.MaxResponseBytes <= 0 || cfg.MaxPromptChars <= 0 {
		return errors.New("MAX_BODY_BYTES, MAX_RESPONSE_BYTES, and MAX_PROMPT_CHARS must be positive")
	}
	if cfg.UpstreamMaxIdleConns <= 0 || cfg.RateBurst <= 0 || cfg.MaxConcurrentRequests <= 0 || cfg.MaxConcurrentLaya <= 0 || cfg.LimiterMaxKeys <= 0 || cfg.UpstreamBreakerThreshold <= 0 {
		return errors.New("connection, limiter, Laya, and breaker limits must be positive")
	}
	if cfg.RequestsPerSecond <= 0 {
		return errors.New("REQUESTS_PER_SECOND must be positive")
	}
	return nil
}

func validateAuthConfig(cfg Config, profile DeploymentProfile) error {
	mode := strings.ToLower(strings.TrimSpace(cfg.AuthMode))
	if mode == "" {
		mode = auth.ModeOff
	}
	if mode != auth.ModeOff && mode != auth.ModeJWT {
		return errors.New("AUTH_MODE must be one of: off, jwt")
	}
	if profile == ProfileProduction && mode == auth.ModeOff {
		return errors.New("production rejects AUTH_MODE=off")
	}
	if profile == ProfileShadow && mode == auth.ModeOff && !cfg.AllowUnauthenticatedShadow {
		return errors.New("shadow requires AUTH_MODE=jwt unless ALLOW_UNAUTHENTICATED_SHADOW=true")
	}
	if mode == auth.ModeOff {
		return nil
	}
	if strings.TrimSpace(cfg.JWTIssuer) == "" {
		return errors.New("AUTH_MODE=jwt requires JWT_ISSUER")
	}
	if strings.TrimSpace(cfg.JWTAudience) == "" {
		return errors.New("AUTH_MODE=jwt requires JWT_AUDIENCE")
	}
	if strings.TrimSpace(cfg.JWTPublicKeyFile) != "" && strings.TrimSpace(cfg.JWTHMACSecret) != "" {
		return errors.New("configure only one JWT verification key")
	}
	if strings.TrimSpace(cfg.JWTHMACSecret) != "" && profile != ProfileDevelopment {
		return errors.New("JWT_HMAC_SECRET is allowed only in development or test")
	}
	if strings.TrimSpace(cfg.JWTPublicKeyFile) == "" && strings.TrimSpace(cfg.JWTHMACSecret) == "" {
		return errors.New("AUTH_MODE=jwt requires JWT_PUBLIC_KEY_FILE or development-only JWT_HMAC_SECRET")
	}
	return nil
}

func validSecurityMode(mode string) bool {
	return mode == ModeOff || mode == ModeShadow || mode == ModeEnforce
}

func parseDependencyURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, false
	}
	return u, true
}

func validDependencyURL(raw string) bool {
	_, ok := parseDependencyURL(raw)
	return ok
}

func isMockUpstream(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "mock-upstream" || host == "mock" || host == "mock-upstream.local"
}

func validatePolicyFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("POLICY_FILE is required")
	}
	if _, err := policy.LoadFile(path); err != nil {
		return errors.New("POLICY_FILE is missing or invalid")
	}
	return nil
}

func validateQuestionsFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("QUESTIONS_FILE is required")
	}
	if _, err := decision.LoadQuestionsFile(path); err != nil {
		return errors.New("QUESTIONS_FILE is missing or invalid")
	}
	return nil
}

func validateThresholdsFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("THRESHOLDS_FILE is required")
	}
	if _, err := policy.LoadSemanticThresholdsFile(path); err != nil {
		return errors.New("THRESHOLDS_FILE is missing or invalid")
	}
	return nil
}

func getenvDefault(get func(string) string, key, def string) string {
	if v := get(key); v != "" {
		return v
	}
	return def
}

func getenvInt64(get func(string) string, key string, def int64) int64 {
	if v := get(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func getenvInt(get func(string) string, key string, def int) int {
	if v := get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func getenvFloat(get func(string) string, key string, def float64) float64 {
	if v := get(key); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func getenvDuration(get func(string) string, key string, def time.Duration) time.Duration {
	if v := get(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
