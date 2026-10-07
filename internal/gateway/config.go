package gateway

import (
	"crypto/sha256"
	"crypto/tls"
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
	"github.com/aegisllm/gateway/internal/routing"
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
	InboundTLSCertFile            string
	InboundTLSKeyFile             string
	InboundTLSClientCAFile        string
	InboundMTLSMode               string // off | require
	TLSMinVersion                 uint16
	TLSMaxVersion                 uint16
	TLSReloadInterval             time.Duration
	TLSTerminatedByTrustedEdge    bool
	PlaintextDependencyDevWaiver  bool
	UpstreamBaseURL               string
	UpstreamRegistryFile          string
	UpstreamAuthMode              string // none | bearer | header
	UpstreamAPIKey                string
	UpstreamAPIKeyFile            string
	UpstreamAuthHeaderName        string
	UpstreamAuthHeaderValue       string
	UpstreamAuthHeaderValueFile   string
	UpstreamTLSCAFile             string
	UpstreamTLSCertFile           string
	UpstreamTLSKeyFile            string
	UpstreamTLSServerName         string
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
	MaxSSEEventBytes              int64
	StreamInspectionWindow        int
	MaxBufferedStreamBytes        int64
	StreamFlushInterval           time.Duration
	StreamingFailClosed           bool
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
	SemanticEnforce               bool
	LayaURL                       string
	LayaEvaluatePath              string
	LayaTimeout                   time.Duration
	LayaTLSCAFile                 string
	LayaTLSCertFile               string
	LayaTLSKeyFile                string
	LayaTLSServerName             string
	HeaderApplication             string
	HeaderTenant                  string
	HeaderUser                    string
	HeaderTargetProvider          string
	DefaultTargetProvider         string
	PolicyFile                    string
	QuestionsFile                 string
	ThresholdsFile                string
	TokenVaultKey                 string
	TokenVaultKeyFile             string
	TokenVaultKeyringFile         string
	TokenVaultAllowKeyRemoval     bool
	TokenVaultRedisURL            string
	TokenVaultRedisCAFile         string
	TokenVaultRedisCertFile       string
	TokenVaultRedisKeyFile        string
	TokenVaultRedisServerName     string
	TelemetryHMACKey              string
	TelemetryHMACKeyFile          string
	AuthMode                      string // off | jwt | mtls
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
		InboundTLSCertFile:            get("INBOUND_TLS_CERT_FILE"),
		InboundTLSKeyFile:             get("INBOUND_TLS_KEY_FILE"),
		InboundTLSClientCAFile:        get("INBOUND_TLS_CLIENT_CA_FILE"),
		InboundMTLSMode:               getenvDefault(get, "INBOUND_MTLS_MODE", "off"),
		TLSMinVersion:                 parseTLSVersion(getenvDefault(get, "TLS_MIN_VERSION", "1.2")),
		TLSMaxVersion:                 parseTLSVersion(getenvDefault(get, "TLS_MAX_VERSION", "")),
		TLSReloadInterval:             getenvDuration(get, "TLS_RELOAD_INTERVAL", 2*time.Second),
		TLSTerminatedByTrustedEdge:    getenvBool(get, "TLS_TERMINATED_BY_TRUSTED_EDGE", false),
		PlaintextDependencyDevWaiver:  getenvBool(get, "PLAINTEXT_DEPENDENCY_DEVELOPMENT_WAIVER", false),
		UpstreamBaseURL:               get("UPSTREAM_BASE_URL"),
		UpstreamRegistryFile:          get("UPSTREAM_REGISTRY_FILE"),
		UpstreamAuthMode:              getenvDefault(get, "UPSTREAM_AUTH_MODE", "none"),
		UpstreamAPIKey:                get("UPSTREAM_API_KEY"),
		UpstreamAPIKeyFile:            get("UPSTREAM_API_KEY_FILE"),
		UpstreamAuthHeaderName:        getenvDefault(get, "UPSTREAM_AUTH_HEADER_NAME", "X-Upstream-Api-Key"),
		UpstreamAuthHeaderValue:       get("UPSTREAM_AUTH_HEADER_VALUE"),
		UpstreamAuthHeaderValueFile:   get("UPSTREAM_AUTH_HEADER_VALUE_FILE"),
		UpstreamTLSCAFile:             get("UPSTREAM_TLS_CA_FILE"),
		UpstreamTLSCertFile:           get("UPSTREAM_TLS_CERT_FILE"),
		UpstreamTLSKeyFile:            get("UPSTREAM_TLS_KEY_FILE"),
		UpstreamTLSServerName:         get("UPSTREAM_TLS_SERVER_NAME"),
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
		MaxSSEEventBytes:              getenvInt64(get, "MAX_SSE_EVENT_BYTES", 64*1024),
		StreamInspectionWindow:        getenvInt(get, "STREAM_INSPECTION_WINDOW", 4096),
		MaxBufferedStreamBytes:        getenvInt64(get, "MAX_BUFFERED_STREAM_BYTES", 1<<20),
		StreamFlushInterval:           getenvDuration(get, "STREAM_FLUSH_INTERVAL", 25*time.Millisecond),
		StreamingFailClosed:           getenvBool(get, "STREAM_FAIL_CLOSED", true),
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
		SemanticEnforce:               getenvBool(get, "SECURITY_SEMANTIC_ENFORCE", false),
		LayaURL:                       get("LAYA_URL"),
		LayaEvaluatePath:              getenvDefault(get, "LAYA_EVALUATE_PATH", "/v1/evaluate"),
		LayaTimeout:                   getenvDuration(get, "LAYA_TIMEOUT", 5*time.Second),
		LayaTLSCAFile:                 get("LAYA_TLS_CA_FILE"),
		LayaTLSCertFile:               get("LAYA_TLS_CERT_FILE"),
		LayaTLSKeyFile:                get("LAYA_TLS_KEY_FILE"),
		LayaTLSServerName:             get("LAYA_TLS_SERVER_NAME"),
		HeaderApplication:             getenvDefault(get, "HEADER_APPLICATION", "X-Application-Id"),
		HeaderTenant:                  getenvDefault(get, "HEADER_TENANT", "X-Tenant-Id"),
		HeaderUser:                    getenvDefault(get, "HEADER_USER", "X-User-Id"),
		HeaderTargetProvider:          getenvDefault(get, "HEADER_TARGET_PROVIDER", "X-Target-Provider"),
		DefaultTargetProvider:         getenvDefault(get, "DEFAULT_TARGET_PROVIDER", "cloud"),
		PolicyFile:                    getenvDefault(get, "POLICY_FILE", "policies/enterprise-default.yaml"),
		QuestionsFile:                 getenvDefault(get, "QUESTIONS_FILE", "questions/security-v1.yaml"),
		ThresholdsFile:                getenvDefault(get, "THRESHOLDS_FILE", "policies/thresholds-security-v1.yaml"),
		TokenVaultKey:                 get("TOKEN_VAULT_KEY"),
		TokenVaultKeyFile:             get("TOKEN_VAULT_KEY_FILE"),
		TokenVaultKeyringFile:         get("TOKEN_VAULT_KEYRING_FILE"),
		TokenVaultAllowKeyRemoval:     getenvBool(get, "TOKEN_VAULT_ALLOW_KEY_REMOVAL", false),
		TokenVaultRedisURL:            get("TOKEN_VAULT_REDIS_URL"),
		TokenVaultRedisCAFile:         get("TOKEN_VAULT_REDIS_CA_FILE"),
		TokenVaultRedisCertFile:       get("TOKEN_VAULT_REDIS_CERT_FILE"),
		TokenVaultRedisKeyFile:        get("TOKEN_VAULT_REDIS_KEY_FILE"),
		TokenVaultRedisServerName:     get("TOKEN_VAULT_REDIS_SERVER_NAME"),
		TelemetryHMACKey:              get("TELEMETRY_HMAC_KEY"),
		TelemetryHMACKeyFile:          get("TELEMETRY_HMAC_KEY_FILE"),
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
	// Older programmatic callers may omit the streaming fields; use the safe
	// defaults for those fields without masking existing zero-value validation
	// failures such as MAX_RESPONSE_BYTES=0.
	streamDefaults := configFrom(func(string) string { return "" })
	if cfg.MaxSSEEventBytes == 0 {
		cfg.MaxSSEEventBytes = streamDefaults.MaxSSEEventBytes
	}
	if cfg.StreamInspectionWindow == 0 {
		cfg.StreamInspectionWindow = streamDefaults.StreamInspectionWindow
	}
	if cfg.MaxBufferedStreamBytes == 0 {
		cfg.MaxBufferedStreamBytes = streamDefaults.MaxBufferedStreamBytes
	}
	if cfg.StreamFlushInterval == 0 {
		cfg.StreamFlushInterval = streamDefaults.StreamFlushInterval
	}
	if cfg.TLSMinVersion == 0 {
		cfg.TLSMinVersion = tls.VersionTLS12
	}
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
	if err := validateSemanticConfig(cfg); err != nil {
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
	if cfg.AuthMode != auth.ModeJWT && cfg.AuthMode != auth.ModeMTLS {
		return errors.New("production requires AUTH_MODE=jwt or mtls")
	}
	if cfg.AuthMode == auth.ModeJWT {
		if strings.TrimSpace(cfg.JWTIssuer) == "" {
			return errors.New("production requires JWT_ISSUER")
		}
		if strings.TrimSpace(cfg.JWTAudience) == "" {
			return errors.New("production requires JWT_AUDIENCE")
		}
		if strings.TrimSpace(cfg.JWTPublicKeyFile) == "" || strings.TrimSpace(cfg.JWTHMACSecret) != "" {
			return errors.New("production requires an asymmetric JWT_PUBLIC_KEY_FILE")
		}
	}
	if strings.TrimSpace(cfg.TokenVaultKey) != "" {
		return errors.New("production requires TOKEN_VAULT_KEY_FILE or TOKEN_VAULT_KEYRING_FILE; inline TOKEN_VAULT_KEY is rejected")
	}
	if strings.TrimSpace(cfg.TokenVaultKeyFile) == "" && strings.TrimSpace(cfg.TokenVaultKeyringFile) == "" {
		return errors.New("production requires TOKEN_VAULT_KEY_FILE or TOKEN_VAULT_KEYRING_FILE")
	}
	if strings.TrimSpace(cfg.TokenVaultRedisURL) == "" {
		return errors.New("TOKEN_VAULT_REDIS_URL is required")
	}
	if !validDependencyURL(cfg.TokenVaultRedisURL) {
		return errors.New("TOKEN_VAULT_REDIS_URL is invalid")
	}
	if strings.TrimSpace(cfg.TelemetryHMACKey) == "" {
		if strings.TrimSpace(cfg.TelemetryHMACKeyFile) == "" {
			return errors.New("production requires TELEMETRY_HMAC_KEY_FILE")
		}
	}
	if strings.TrimSpace(cfg.TelemetryHMACKeyFile) != "" && strings.TrimSpace(cfg.TelemetryHMACKey) != "" {
		return errors.New("production rejects inline TELEMETRY_HMAC_KEY when TELEMETRY_HMAC_KEY_FILE is configured")
	}
	if strings.TrimSpace(cfg.UpstreamRegistryFile) != "" {
		reg, err := routing.LoadFile(cfg.UpstreamRegistryFile)
		if err != nil {
			return errors.New("UPSTREAM_REGISTRY_FILE is invalid")
		}
		for _, upstream := range reg.Upstreams {
			u, parseErr := url.Parse(upstream.BaseURL)
			if parseErr != nil || !strings.EqualFold(u.Scheme, "https") || isMockUpstream(u.Hostname()) {
				return errors.New("production registry routes must use verified TLS and non-mock hosts")
			}
			if upstream.Auth.Mode != "none" && strings.TrimSpace(upstream.Auth.SecretFile) == "" {
				return errors.New("production registry routes require file-backed auth")
			}
			if (upstream.TLS.CertificateFile == "") != (upstream.TLS.KeyFile == "") {
				return errors.New("production registry route TLS certificate and key must be paired")
			}
		}
	} else {
		// ValidateConfig retains the P0 validation contract for programmatic
		// callers and migration tooling. The production command boundary rejects
		// this compatibility path before serving traffic (see NewServer).
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
		if cfg.UpstreamAuthMode == "bearer" && strings.TrimSpace(cfg.UpstreamAPIKeyFile) == "" {
			return errors.New("production requires UPSTREAM_API_KEY_FILE for bearer credentials")
		}
		if cfg.UpstreamAuthMode == "header" && strings.TrimSpace(cfg.UpstreamAuthHeaderValueFile) == "" {
			return errors.New("production requires UPSTREAM_AUTH_HEADER_VALUE_FILE for header credentials")
		}
		if strings.TrimSpace(cfg.UpstreamAPIKey) != "" || strings.TrimSpace(cfg.UpstreamAuthHeaderValue) != "" {
			return errors.New("production rejects inline upstream credentials; use *_FILE")
		}
	}
	if err := validateProductionTransport(cfg); err != nil {
		return err
	}
	if err := validatePolicyFile(cfg.PolicyFile); err != nil {
		return err
	}
	if err := validateQuestionsFile(cfg.QuestionsFile); err != nil {
		return err
	}
	// Threshold artifacts are mandatory and strictly validated only when
	// semantic enforcement is requested. Deterministic-only production may
	// omit or ignore semantic artifacts and reports semantic=disabled.
	return nil
}

func validateSemanticConfig(cfg Config) error {
	if !cfg.SemanticEnforce {
		return nil
	}
	if cfg.SecurityMode != ModeEnforce {
		return errors.New("SECURITY_SEMANTIC_ENFORCE=true requires SECURITY_MODE=enforce")
	}
	if strings.TrimSpace(cfg.LayaURL) == "" {
		return errors.New("SECURITY_SEMANTIC_ENFORCE=true requires LAYA_URL")
	}
	u, ok := parseDependencyURL(cfg.LayaURL)
	if !ok || (u.Scheme != "http" && u.Scheme != "https") || strings.EqualFold(u.Hostname(), "noop") {
		return errors.New("LAYA_URL is invalid for semantic enforcement")
	}
	if strings.TrimSpace(cfg.ThresholdsFile) == "" {
		return errors.New("SECURITY_SEMANTIC_ENFORCE=true requires THRESHOLDS_FILE")
	}
	pol, err := policy.LoadFile(cfg.PolicyFile)
	if err != nil {
		return errors.New("POLICY_FILE is missing or invalid")
	}
	if err := pol.ValidateSemanticFallbackMatrix(); err != nil {
		return errors.New("POLICY_FILE lacks a strict semantic fallback matrix")
	}
	qs, err := decision.LoadQuestionsFile(cfg.QuestionsFile)
	if err != nil {
		return errors.New("QUESTIONS_FILE is missing or invalid")
	}
	thresholds, err := policy.LoadSemanticThresholdsFile(cfg.ThresholdsFile)
	if err != nil {
		return errors.New("THRESHOLDS_FILE is missing or invalid")
	}
	questionData, err := os.ReadFile(cfg.QuestionsFile)
	if err != nil {
		return errors.New("QUESTIONS_FILE is unreadable")
	}
	sum := sha256.Sum256(questionData)
	questionIDs := make([]string, 0, len(qs.Questions))
	for _, q := range qs.Questions {
		questionIDs = append(questionIDs, q.ID)
	}
	if thresholds.QuestionSchemaSHA256 != "" && !strings.EqualFold(thresholds.QuestionSchemaSHA256, hex.EncodeToString(sum[:])) {
		return errors.New("THRESHOLDS_FILE question schema hash mismatch")
	}
	if err := thresholds.ValidateForEnforcement(qs.Schema, qs.Version, questionIDs, "laya"); err != nil {
		return errors.New("THRESHOLDS_FILE is not promotion-ready")
	}
	return nil
}

func validateProductionTransport(cfg Config) error {
	if cfg.PlaintextDependencyDevWaiver {
		return errors.New("PLAINTEXT_DEPENDENCY_DEVELOPMENT_WAIVER is rejected in production")
	}
	mtlsMode := cfg.InboundMTLSMode
	if mtlsMode == "" {
		mtlsMode = "off"
	}
	if cfg.TLSTerminatedByTrustedEdge {
		if cfg.InboundTLSCertFile != "" || cfg.InboundTLSKeyFile != "" || mtlsMode == "require" {
			return errors.New("TLS_TERMINATED_BY_TRUSTED_EDGE cannot be combined with direct gateway TLS or inbound mTLS")
		}
	} else {
		if strings.TrimSpace(cfg.InboundTLSCertFile) == "" || strings.TrimSpace(cfg.InboundTLSKeyFile) == "" {
			return errors.New("production requires inbound TLS certificate/key or TLS_TERMINATED_BY_TRUSTED_EDGE=true")
		}
	}
	if mtlsMode != "off" && mtlsMode != "require" {
		return errors.New("INBOUND_MTLS_MODE must be off or require")
	}
	if mtlsMode == "require" && strings.TrimSpace(cfg.InboundTLSClientCAFile) == "" {
		return errors.New("INBOUND_MTLS_MODE=require requires INBOUND_TLS_CLIENT_CA_FILE")
	}
	if cfg.TLSMinVersion < tls.VersionTLS12 {
		return errors.New("TLS_MIN_VERSION must be 1.2 or newer")
	}
	dependencyURLs := map[string]string{"TOKEN_VAULT_REDIS_URL": cfg.TokenVaultRedisURL}
	if cfg.UpstreamRegistryFile == "" {
		dependencyURLs["UPSTREAM_BASE_URL"] = cfg.UpstreamBaseURL
	}
	for name, value := range dependencyURLs {
		u, ok := parseDependencyURL(value)
		wanted := "rediss"
		if name == "UPSTREAM_BASE_URL" {
			wanted = "https"
		}
		if !ok || !strings.EqualFold(u.Scheme, wanted) {
			return errors.New(name + " must use verified TLS in production")
		}
	}
	if cfg.LayaURL != "" {
		u, ok := parseDependencyURL(cfg.LayaURL)
		if !ok || !strings.EqualFold(u.Scheme, "https") {
			return errors.New("LAYA_URL must use verified TLS in production")
		}
	}
	if err := validateTLSFilePair("UPSTREAM_TLS", cfg.UpstreamTLSCertFile, cfg.UpstreamTLSKeyFile); err != nil {
		return err
	}
	if err := validateTLSFilePair("LAYA_TLS", cfg.LayaTLSCertFile, cfg.LayaTLSKeyFile); err != nil {
		return err
	}
	if err := validateTLSFilePair("TOKEN_VAULT_REDIS_TLS", cfg.TokenVaultRedisCertFile, cfg.TokenVaultRedisKeyFile); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.TelemetryHMACKey) != "" {
		return errors.New("production rejects inline TELEMETRY_HMAC_KEY; use TELEMETRY_HMAC_KEY_FILE")
	}
	return nil
}

func validateTLSFilePair(name, certFile, keyFile string) error {
	if (certFile == "") != (keyFile == "") {
		return errors.New(name + " certificate and key must be configured together")
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
	if c.MaxSSEEventBytes <= 0 {
		c.MaxSSEEventBytes = defaults.MaxSSEEventBytes
	}
	if c.StreamInspectionWindow <= 0 {
		c.StreamInspectionWindow = defaults.StreamInspectionWindow
	}
	if c.MaxBufferedStreamBytes <= 0 {
		c.MaxBufferedStreamBytes = defaults.MaxBufferedStreamBytes
	}
	if c.StreamFlushInterval <= 0 {
		c.StreamFlushInterval = defaults.StreamFlushInterval
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
	if c.LayaTimeout <= 0 {
		c.LayaTimeout = defaults.LayaTimeout
	}
	if c.LayaEvaluatePath == "" {
		c.LayaEvaluatePath = defaults.LayaEvaluatePath
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
	if cfg.MaxSSEEventBytes <= 0 || cfg.StreamInspectionWindow <= 0 || cfg.MaxBufferedStreamBytes <= 0 || cfg.StreamFlushInterval <= 0 {
		return errors.New("streaming byte, window, buffer, and flush limits must be positive")
	}
	if cfg.profile() == ProfileProduction && cfg.StreamInspectionWindow < 4096 {
		return errors.New("STREAM_INSPECTION_WINDOW must be at least 4096 bytes in production")
	}
	if cfg.profile() == ProfileProduction && !cfg.StreamingFailClosed {
		return errors.New("production requires STREAM_FAIL_CLOSED=true")
	}
	if int64(cfg.StreamInspectionWindow) > cfg.MaxBufferedStreamBytes || cfg.MaxSSEEventBytes > cfg.MaxBufferedStreamBytes {
		return errors.New("streaming window and event limits must fit within MAX_BUFFERED_STREAM_BYTES")
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
	if mode != auth.ModeOff && mode != auth.ModeJWT && mode != auth.ModeMTLS {
		return errors.New("AUTH_MODE must be one of: off, jwt, mtls")
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
	if mode == auth.ModeMTLS {
		if cfg.InboundMTLSMode != "require" {
			return errors.New("AUTH_MODE=mtls requires INBOUND_MTLS_MODE=require")
		}
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

func getenvBool(get func(string) string, key string, def bool) bool {
	if v := strings.TrimSpace(strings.ToLower(get(key))); v != "" {
		return v == "1" || v == "true" || v == "yes"
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

func parseTLSVersion(value string) uint16 {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "1.2", "tls1.2", "tls12":
		return tls.VersionTLS12
	case "1.3", "tls1.3", "tls13":
		return tls.VersionTLS13
	default:
		return 0
	}
}
