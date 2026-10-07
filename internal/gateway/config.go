package gateway

import (
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"

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
	DeploymentProfile          DeploymentProfile
	ListenAddr                 string
	UpstreamBaseURL            string
	UpstreamAuthMode           string // none | bearer | header
	UpstreamAPIKey             string
	UpstreamAuthHeaderName     string
	UpstreamAuthHeaderValue    string
	UpstreamChatPathPrefix     string
	MaxBodyBytes               int64
	SecurityMode               string // off | shadow | enforce
	HeaderApplication          string
	HeaderTenant               string
	HeaderUser                 string
	HeaderTargetProvider       string
	DefaultTargetProvider      string
	PolicyFile                 string
	QuestionsFile              string
	ThresholdsFile             string
	TokenVaultKey              string
	TokenVaultRedisURL         string
	TelemetryHMACKey           string
	AuthMode                   string // off | jwt
	JWTPublicKeyFile           string
	JWTHMACSecret              string
	JWTIssuer                  string
	JWTAudience                string
	JWTTenantClaim             string
	JWTApplicationClaim        string
	JWTSubjectClaim            string
	JWTRolesClaim              string
	JWTProviderClaim           string
	AllowUnauthenticatedShadow bool
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
		DeploymentProfile:          profile,
		ListenAddr:                 getenvDefault(get, "LISTEN_ADDR", ":8080"),
		UpstreamBaseURL:            get("UPSTREAM_BASE_URL"),
		UpstreamAuthMode:           getenvDefault(get, "UPSTREAM_AUTH_MODE", "none"),
		UpstreamAPIKey:             get("UPSTREAM_API_KEY"),
		UpstreamAuthHeaderName:     getenvDefault(get, "UPSTREAM_AUTH_HEADER_NAME", "X-Upstream-Api-Key"),
		UpstreamAuthHeaderValue:    get("UPSTREAM_AUTH_HEADER_VALUE"),
		UpstreamChatPathPrefix:     get("UPSTREAM_CHAT_PATH_PREFIX"),
		MaxBodyBytes:               getenvInt64(get, "MAX_BODY_BYTES", 1<<20),
		SecurityMode:               getenvDefault(get, "SECURITY_MODE", ModeOff),
		HeaderApplication:          getenvDefault(get, "HEADER_APPLICATION", "X-Application-Id"),
		HeaderTenant:               getenvDefault(get, "HEADER_TENANT", "X-Tenant-Id"),
		HeaderUser:                 getenvDefault(get, "HEADER_USER", "X-User-Id"),
		HeaderTargetProvider:       getenvDefault(get, "HEADER_TARGET_PROVIDER", "X-Target-Provider"),
		DefaultTargetProvider:      getenvDefault(get, "DEFAULT_TARGET_PROVIDER", "cloud"),
		PolicyFile:                 getenvDefault(get, "POLICY_FILE", "policies/enterprise-default.yaml"),
		QuestionsFile:              getenvDefault(get, "QUESTIONS_FILE", "questions/security-v1.yaml"),
		ThresholdsFile:             getenvDefault(get, "THRESHOLDS_FILE", "policies/thresholds-security-v1.yaml"),
		TokenVaultKey:              get("TOKEN_VAULT_KEY"),
		TokenVaultRedisURL:         get("TOKEN_VAULT_REDIS_URL"),
		TelemetryHMACKey:           get("TELEMETRY_HMAC_KEY"),
		AuthMode:                   getenvDefault(get, "AUTH_MODE", auth.ModeOff),
		JWTPublicKeyFile:           get("JWT_PUBLIC_KEY_FILE"),
		JWTHMACSecret:              get("JWT_HMAC_SECRET"),
		JWTIssuer:                  get("JWT_ISSUER"),
		JWTAudience:                get("JWT_AUDIENCE"),
		JWTTenantClaim:             getenvDefault(get, "JWT_TENANT_CLAIM", "tenant_id"),
		JWTApplicationClaim:        getenvDefault(get, "JWT_APPLICATION_CLAIM", "azp"),
		JWTSubjectClaim:            getenvDefault(get, "JWT_SUBJECT_CLAIM", "sub"),
		JWTRolesClaim:              getenvDefault(get, "JWT_ROLES_CLAIM", "roles"),
		JWTProviderClaim:           getenvDefault(get, "JWT_PROVIDER_CLAIM", "provider"),
		AllowUnauthenticatedShadow: strings.EqualFold(get("ALLOW_UNAUTHENTICATED_SHADOW"), "true"),
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
