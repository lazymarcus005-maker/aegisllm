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

	"github.com/aegisllm/gateway/internal/attachment"
	"github.com/aegisllm/gateway/internal/auth"
	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/ragauth"
	"github.com/aegisllm/gateway/internal/routing"
	"github.com/aegisllm/gateway/internal/securetransport"
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
	DeploymentProfile              DeploymentProfile
	ListenAddr                     string
	InboundTLSCertFile             string
	InboundTLSKeyFile              string
	InboundTLSClientCAFile         string
	InboundMTLSMode                string // off | require
	TLSMinVersion                  uint16
	TLSMaxVersion                  uint16
	TLSReloadInterval              time.Duration
	TLSTerminatedByTrustedEdge     bool
	PlaintextDependencyDevWaiver   bool
	UpstreamBaseURL                string
	UpstreamRegistryFile           string
	MCPRegistryFile                string
	MCPCredentialsFile             string
	MCPSessionTTL                  time.Duration
	MCPToolSchemaTTL               time.Duration
	MCPMaxBodyBytes                int64
	MCPMaxEventBytes               int64
	MCPMaxStreamDuration           time.Duration
	MCPMaxSessionCount             int
	UpstreamAuthMode               string // none | bearer | header
	UpstreamAPIKey                 string
	UpstreamAPIKeyFile             string
	UpstreamAuthHeaderName         string
	UpstreamAuthHeaderValue        string
	UpstreamAuthHeaderValueFile    string
	UpstreamTLSCAFile              string
	UpstreamTLSCertFile            string
	UpstreamTLSKeyFile             string
	UpstreamTLSServerName          string
	UpstreamChatPathPrefix         string
	UpstreamDialTimeout            time.Duration
	UpstreamTLSHandshakeTimeout    time.Duration
	UpstreamResponseHeaderTimeout  time.Duration
	UpstreamRequestTimeout         time.Duration
	UpstreamIdleConnTimeout        time.Duration
	UpstreamMaxIdleConns           int
	MaxBodyBytes                   int64
	MaxResponseBytes               int64
	MaxPromptChars                 int
	MaxStreamDuration              time.Duration
	MaxSSEEventBytes               int64
	StreamInspectionWindow         int
	MaxBufferedStreamBytes         int64
	StreamFlushInterval            time.Duration
	StreamingFailClosed            bool
	RequestsPerSecond              float64
	RateBurst                      int
	MaxConcurrentRequests          int
	MaxConcurrentLaya              int
	LimiterMaxKeys                 int
	LimiterKeyIdleTimeout          time.Duration
	UpstreamBreakerThreshold       int
	UpstreamBreakerOpenInterval    time.Duration
	ServerReadHeaderTimeout        time.Duration
	ServerReadTimeout              time.Duration
	ServerIdleTimeout              time.Duration
	ServerShutdownTimeout          time.Duration
	SecurityMode                   string // off | shadow | enforce
	SemanticEnforce                bool
	LayaURL                        string
	LayaEvaluatePath               string
	LayaTimeout                    time.Duration
	LayaTLSCAFile                  string
	LayaTLSCertFile                string
	LayaTLSKeyFile                 string
	LayaTLSServerName              string
	PIIRegistryFile                string
	PIIRequireNER                  bool
	AttachmentEnabled              bool
	AttachmentAdapter              string
	AttachmentExtractorURL         string
	AttachmentAllowedHosts         []string
	AttachmentAllowPrivateHosts    bool
	AttachmentMaxEncodedBytes      int64
	AttachmentMaxDecodedBytes      int64
	AttachmentMaxTextBytes         int
	AttachmentMaxCount             int
	AttachmentMaxPages             int
	AttachmentMaxExpansionRatio    int64
	AttachmentTimeout              time.Duration
	AttachmentMaxRedirects         int
	AttachmentAllowedMIMEs         []string
	AttachmentTLSCAFile            string
	AttachmentTLSCertFile          string
	AttachmentTLSKeyFile           string
	AttachmentTLSServerName        string
	RAGAuthMode                    string
	RAGAuthAdapter                 string
	RAGAuthURL                     string
	RAGAuthTimeout                 time.Duration
	RAGAuthCAFile                  string
	RAGAuthCertFile                string
	RAGAuthKeyFile                 string
	RAGAuthServerName              string
	RAGMaxResults                  int
	RAGMaxResultBytes              int64
	RAGMaxDepth                    int
	RAGMaxNodes                    int
	RAGMaxConcurrency              int
	RAGDecisionMaxAge              time.Duration
	HeaderApplication              string
	HeaderTenant                   string
	HeaderUser                     string
	HeaderTargetProvider           string
	DefaultTargetProvider          string
	PolicyFile                     string
	QuestionsFile                  string
	ThresholdsFile                 string
	SemanticRegistryStateFile      string
	SemanticRegistryTrustStoreFile string
	PolicyBundleDir                string
	PolicyBundlePath               string
	PolicyControlPlaneURL          string
	PolicyTrustStoreFile           string
	PolicyStateFile                string
	PolicyDistributionTimeout      time.Duration
	PolicyDistributionPollInterval time.Duration
	PolicyTLSCAFile                string
	PolicyTLSCertFile              string
	PolicyTLSKeyFile               string
	PolicyTLSServerName            string
	PolicyCanaryPercent            int
	PolicyCanarySoak               time.Duration
	FleetControlPlaneURL           string
	FleetTenant                    string
	FleetRegion                    string
	FleetStateFile                 string
	FleetTrustStoreFile            string
	FleetCertificateID             string
	FleetKeyID                     string
	FleetTrustDomain               string
	FleetPollInterval              time.Duration
	FleetTimeout                   time.Duration
	FleetOfflineGrace              time.Duration
	FleetRequiredState             bool
	FleetCapabilities              []string
	FleetTLSCAFile                 string
	FleetTLSCertFile               string
	FleetTLSKeyFile                string
	FleetTLSServerName             string
	GatewayVersion                 string
	GatewayInstanceID              string
	DeploymentEnvironment          string
	TokenVaultKey                  string
	TokenVaultKeyFile              string
	TokenVaultKeyringFile          string
	TokenVaultAllowKeyRemoval      bool
	TokenVaultTTL                  time.Duration
	TokenVaultRedisURL             string
	TokenVaultRedisCAFile          string
	TokenVaultRedisCertFile        string
	TokenVaultRedisKeyFile         string
	TokenVaultRedisServerName      string
	TokenVaultIdleTTL              time.Duration
	TokenVaultMaxValueBytes        int
	TokenVaultMaxRecordsPerScope   int
	TokenVaultMaxRecordsPerTenant  int
	TokenVaultMaxRecordsPerUser    int
	TokenVaultMaxRecordsPerSession int
	TokenVaultMaxRetrievals        int
	TokenVaultSingleUse            bool
	TokenVaultVisibleCategory      bool
	QuarantineRedisURL             string
	QuarantineRedisCAFile          string
	QuarantineRedisCertFile        string
	QuarantineRedisKeyFile         string
	QuarantineRedisServerName      string
	TelemetryHMACKey               string
	TelemetryHMACKeyFile           string
	AuditDir                       string
	AuditSegmentBytes              int64
	AuditMaxBytes                  int64
	AuditRetention                 time.Duration
	AuditFsync                     string
	AuditHMACKey                   string
	AuditHMACKeyFile               string
	AuditEncryptionKeyringFile     string
	AuditFailureMode               string
	AuditSIEMURL                   string
	AuditSIEMAuthFile              string
	AuditSIEMCAFile                string
	AuditSIEMCertFile              string
	AuditSIEMKeyFile               string
	AuditSIEMServerName            string
	AuditSIEMTimeout               time.Duration
	AuditSIEMBatchSize             int
	AuditSIEMMaxRetries            int
	AuditSIEMDLQDir                string
	AuthMode                       string // off | jwt | mtls
	JWTPublicKeyFile               string
	JWTHMACSecret                  string
	JWTIssuer                      string
	JWTAudience                    string
	JWTTenantClaim                 string
	JWTApplicationClaim            string
	JWTSubjectClaim                string
	JWTRolesClaim                  string
	JWTGroupsClaim                 string
	JWTProviderClaim               string
	JWTSessionClaim                string
	AllowUnauthenticatedShadow     bool
	ConformanceCapabilityGate      bool
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
		DeploymentProfile:              profile,
		ListenAddr:                     getenvDefault(get, "LISTEN_ADDR", ":8080"),
		InboundTLSCertFile:             get("INBOUND_TLS_CERT_FILE"),
		InboundTLSKeyFile:              get("INBOUND_TLS_KEY_FILE"),
		InboundTLSClientCAFile:         get("INBOUND_TLS_CLIENT_CA_FILE"),
		InboundMTLSMode:                getenvDefault(get, "INBOUND_MTLS_MODE", "off"),
		TLSMinVersion:                  parseTLSVersion(getenvDefault(get, "TLS_MIN_VERSION", "1.2")),
		TLSMaxVersion:                  parseTLSVersion(getenvDefault(get, "TLS_MAX_VERSION", "")),
		TLSReloadInterval:              getenvDuration(get, "TLS_RELOAD_INTERVAL", 2*time.Second),
		TLSTerminatedByTrustedEdge:     getenvBool(get, "TLS_TERMINATED_BY_TRUSTED_EDGE", false),
		PlaintextDependencyDevWaiver:   getenvBool(get, "PLAINTEXT_DEPENDENCY_DEVELOPMENT_WAIVER", false),
		UpstreamBaseURL:                get("UPSTREAM_BASE_URL"),
		UpstreamRegistryFile:           get("UPSTREAM_REGISTRY_FILE"),
		MCPRegistryFile:                get("MCP_REGISTRY_FILE"),
		MCPCredentialsFile:             get("MCP_CREDENTIALS_FILE"),
		MCPSessionTTL:                  getenvDuration(get, "MCP_SESSION_TTL", 15*time.Minute),
		MCPToolSchemaTTL:               getenvDuration(get, "MCP_TOOL_SCHEMA_TTL", 5*time.Minute),
		MCPMaxBodyBytes:                getenvInt64(get, "MCP_MAX_BODY_BYTES", 1<<20),
		MCPMaxEventBytes:               getenvInt64(get, "MCP_MAX_EVENT_BYTES", 64<<10),
		MCPMaxStreamDuration:           getenvDuration(get, "MCP_MAX_STREAM_DURATION", 5*time.Minute),
		MCPMaxSessionCount:             getenvInt(get, "MCP_MAX_SESSION_COUNT", 10000),
		UpstreamAuthMode:               getenvDefault(get, "UPSTREAM_AUTH_MODE", "none"),
		UpstreamAPIKey:                 get("UPSTREAM_API_KEY"),
		UpstreamAPIKeyFile:             get("UPSTREAM_API_KEY_FILE"),
		UpstreamAuthHeaderName:         getenvDefault(get, "UPSTREAM_AUTH_HEADER_NAME", "X-Upstream-Api-Key"),
		UpstreamAuthHeaderValue:        get("UPSTREAM_AUTH_HEADER_VALUE"),
		UpstreamAuthHeaderValueFile:    get("UPSTREAM_AUTH_HEADER_VALUE_FILE"),
		UpstreamTLSCAFile:              get("UPSTREAM_TLS_CA_FILE"),
		UpstreamTLSCertFile:            get("UPSTREAM_TLS_CERT_FILE"),
		UpstreamTLSKeyFile:             get("UPSTREAM_TLS_KEY_FILE"),
		UpstreamTLSServerName:          get("UPSTREAM_TLS_SERVER_NAME"),
		UpstreamChatPathPrefix:         get("UPSTREAM_CHAT_PATH_PREFIX"),
		UpstreamDialTimeout:            getenvDuration(get, "UPSTREAM_DIAL_TIMEOUT", 5*time.Second),
		UpstreamTLSHandshakeTimeout:    getenvDuration(get, "UPSTREAM_TLS_HANDSHAKE_TIMEOUT", 5*time.Second),
		UpstreamResponseHeaderTimeout:  getenvDuration(get, "UPSTREAM_RESPONSE_HEADER_TIMEOUT", 30*time.Second),
		UpstreamRequestTimeout:         getenvDuration(get, "UPSTREAM_REQUEST_TIMEOUT", 2*time.Minute),
		UpstreamIdleConnTimeout:        getenvDuration(get, "UPSTREAM_IDLE_CONN_TIMEOUT", 90*time.Second),
		UpstreamMaxIdleConns:           getenvInt(get, "UPSTREAM_MAX_IDLE_CONNS", 100),
		MaxBodyBytes:                   getenvInt64(get, "MAX_BODY_BYTES", 1<<20),
		MaxResponseBytes:               getenvInt64(get, "MAX_RESPONSE_BYTES", 4<<20),
		MaxPromptChars:                 getenvInt(get, "MAX_PROMPT_CHARS", 64*1024),
		MaxStreamDuration:              getenvDuration(get, "MAX_STREAM_DURATION", 5*time.Minute),
		MaxSSEEventBytes:               getenvInt64(get, "MAX_SSE_EVENT_BYTES", 64*1024),
		StreamInspectionWindow:         getenvInt(get, "STREAM_INSPECTION_WINDOW", 4096),
		MaxBufferedStreamBytes:         getenvInt64(get, "MAX_BUFFERED_STREAM_BYTES", 1<<20),
		StreamFlushInterval:            getenvDuration(get, "STREAM_FLUSH_INTERVAL", 25*time.Millisecond),
		StreamingFailClosed:            getenvBool(get, "STREAM_FAIL_CLOSED", true),
		RequestsPerSecond:              getenvFloat(get, "REQUESTS_PER_SECOND", 10),
		RateBurst:                      getenvInt(get, "RATE_BURST", 20),
		MaxConcurrentRequests:          getenvInt(get, "MAX_CONCURRENT_REQUESTS", 16),
		MaxConcurrentLaya:              getenvInt(get, "MAX_CONCURRENT_LAYA", 4),
		LimiterMaxKeys:                 getenvInt(get, "LIMITER_MAX_KEYS", 10000),
		LimiterKeyIdleTimeout:          getenvDuration(get, "LIMITER_KEY_IDLE_TIMEOUT", 10*time.Minute),
		UpstreamBreakerThreshold:       getenvInt(get, "UPSTREAM_BREAKER_FAILURE_THRESHOLD", 3),
		UpstreamBreakerOpenInterval:    getenvDuration(get, "UPSTREAM_BREAKER_OPEN_INTERVAL", 30*time.Second),
		ServerReadHeaderTimeout:        getenvDuration(get, "SERVER_READ_HEADER_TIMEOUT", 10*time.Second),
		ServerReadTimeout:              getenvDuration(get, "SERVER_READ_TIMEOUT", 30*time.Second),
		ServerIdleTimeout:              getenvDuration(get, "SERVER_IDLE_TIMEOUT", 2*time.Minute),
		ServerShutdownTimeout:          getenvDuration(get, "SERVER_SHUTDOWN_TIMEOUT", 10*time.Second),
		SecurityMode:                   getenvDefault(get, "SECURITY_MODE", ModeOff),
		SemanticEnforce:                getenvBool(get, "SECURITY_SEMANTIC_ENFORCE", false),
		LayaURL:                        get("LAYA_URL"),
		LayaEvaluatePath:               getenvDefault(get, "LAYA_EVALUATE_PATH", "/v1/evaluate"),
		LayaTimeout:                    getenvDuration(get, "LAYA_TIMEOUT", 5*time.Second),
		LayaTLSCAFile:                  get("LAYA_TLS_CA_FILE"),
		LayaTLSCertFile:                get("LAYA_TLS_CERT_FILE"),
		LayaTLSKeyFile:                 get("LAYA_TLS_KEY_FILE"),
		LayaTLSServerName:              get("LAYA_TLS_SERVER_NAME"),
		PIIRegistryFile:                get("PII_NER_REGISTRY_FILE"),
		PIIRequireNER:                  getenvBool(get, "PII_NER_REQUIRED", profile == ProfileProduction),
		AttachmentEnabled:              getenvBool(get, "DLP_ATTACHMENT_ENABLED", profile == ProfileProduction || profile == ProfileShadow),
		AttachmentAdapter:              getenvDefault(get, "DLP_ATTACHMENT_ADAPTER", "builtin"),
		AttachmentExtractorURL:         get("DLP_ATTACHMENT_EXTRACTOR_URL"),
		AttachmentAllowedHosts:         splitCSV(get("DLP_ATTACHMENT_ALLOWED_HOSTS")),
		AttachmentAllowPrivateHosts:    getenvBool(get, "DLP_ATTACHMENT_ALLOW_PRIVATE_HOSTS", false),
		AttachmentMaxEncodedBytes:      getenvInt64(get, "DLP_ATTACHMENT_MAX_ENCODED_BYTES", attachment.DefaultMaxEncodedBytes),
		AttachmentMaxDecodedBytes:      getenvInt64(get, "DLP_ATTACHMENT_MAX_DECODED_BYTES", attachment.DefaultMaxDecodedBytes),
		AttachmentMaxTextBytes:         getenvInt(get, "DLP_ATTACHMENT_MAX_TEXT_BYTES", attachment.DefaultMaxTextBytes),
		AttachmentMaxCount:             getenvInt(get, "DLP_ATTACHMENT_MAX_COUNT", attachment.DefaultMaxAttachments),
		AttachmentMaxPages:             getenvInt(get, "DLP_ATTACHMENT_MAX_PAGES", attachment.DefaultMaxPages),
		AttachmentMaxExpansionRatio:    getenvInt64(get, "DLP_ATTACHMENT_MAX_EXPANSION_RATIO", 20),
		AttachmentTimeout:              getenvDuration(get, "DLP_ATTACHMENT_TIMEOUT", attachment.DefaultTimeout),
		AttachmentMaxRedirects:         getenvInt(get, "DLP_ATTACHMENT_MAX_REDIRECTS", 2),
		AttachmentAllowedMIMEs:         splitCSV(getenvDefault(get, "DLP_ATTACHMENT_ALLOWED_MIME_TYPES", strings.Join(attachment.DefaultAllowedMIMEs, ","))),
		AttachmentTLSCAFile:            get("DLP_ATTACHMENT_TLS_CA_FILE"),
		AttachmentTLSCertFile:          get("DLP_ATTACHMENT_TLS_CERT_FILE"),
		AttachmentTLSKeyFile:           get("DLP_ATTACHMENT_TLS_KEY_FILE"),
		AttachmentTLSServerName:        get("DLP_ATTACHMENT_TLS_SERVER_NAME"),
		RAGAuthMode:                    getenvDefault(get, "RAG_AUTH_MODE", ragauth.ModeOff),
		RAGAuthAdapter:                 getenvDefault(get, "RAG_AUTH_ADAPTER", ragauth.AdapterDeny),
		RAGAuthURL:                     get("RAG_AUTH_URL"),
		RAGAuthTimeout:                 getenvDuration(get, "RAG_AUTH_TIMEOUT", 5*time.Second),
		RAGAuthCAFile:                  get("RAG_AUTH_CA_FILE"),
		RAGAuthCertFile:                get("RAG_AUTH_CERT_FILE"),
		RAGAuthKeyFile:                 get("RAG_AUTH_KEY_FILE"),
		RAGAuthServerName:              get("RAG_AUTH_SERVER_NAME"),
		RAGMaxResults:                  getenvInt(get, "RAG_MAX_RESULTS", 64),
		RAGMaxResultBytes:              getenvInt64(get, "RAG_MAX_RESULT_BYTES", 1<<20),
		RAGMaxDepth:                    getenvInt(get, "RAG_MAX_DEPTH", 8),
		RAGMaxNodes:                    getenvInt(get, "RAG_MAX_NODES", 512),
		RAGMaxConcurrency:              getenvInt(get, "RAG_MAX_CONCURRENCY", 4),
		RAGDecisionMaxAge:              getenvDuration(get, "RAG_DECISION_MAX_AGE", 30*time.Second),
		HeaderApplication:              getenvDefault(get, "HEADER_APPLICATION", "X-Application-Id"),
		HeaderTenant:                   getenvDefault(get, "HEADER_TENANT", "X-Tenant-Id"),
		HeaderUser:                     getenvDefault(get, "HEADER_USER", "X-User-Id"),
		HeaderTargetProvider:           getenvDefault(get, "HEADER_TARGET_PROVIDER", "X-Target-Provider"),
		DefaultTargetProvider:          getenvDefault(get, "DEFAULT_TARGET_PROVIDER", "cloud"),
		PolicyFile:                     getenvDefault(get, "POLICY_FILE", "policies/enterprise-default.yaml"),
		QuestionsFile:                  getenvDefault(get, "QUESTIONS_FILE", "questions/security-v1.yaml"),
		ThresholdsFile:                 getenvDefault(get, "THRESHOLDS_FILE", "policies/thresholds-security-v1.yaml"),
		SemanticRegistryStateFile:      get("SEMANTIC_REGISTRY_STATE_FILE"),
		SemanticRegistryTrustStoreFile: get("SEMANTIC_REGISTRY_TRUST_STORE_FILE"),
		PolicyBundleDir:                get("POLICY_BUNDLE_DIR"),
		PolicyBundlePath:               get("POLICY_BUNDLE_PATH"),
		PolicyControlPlaneURL:          get("POLICY_CONTROL_PLANE_URL"),
		PolicyTrustStoreFile:           get("POLICY_TRUST_STORE_FILE"),
		PolicyStateFile:                get("POLICY_STATE_FILE"),
		PolicyDistributionTimeout:      getenvDuration(get, "POLICY_DISTRIBUTION_TIMEOUT", 10*time.Second),
		PolicyDistributionPollInterval: getenvDuration(get, "POLICY_DISTRIBUTION_POLL_INTERVAL", 30*time.Second),
		PolicyTLSCAFile:                get("POLICY_TLS_CA_FILE"),
		PolicyTLSCertFile:              get("POLICY_TLS_CERT_FILE"),
		PolicyTLSKeyFile:               get("POLICY_TLS_KEY_FILE"),
		PolicyTLSServerName:            get("POLICY_TLS_SERVER_NAME"),
		PolicyCanaryPercent:            getenvInt(get, "POLICY_CANARY_PERCENT", 0),
		PolicyCanarySoak:               getenvDuration(get, "POLICY_CANARY_SOAK", 0),
		FleetControlPlaneURL:           get("FLEET_CONTROL_PLANE_URL"),
		FleetTenant:                    get("FLEET_TENANT"),
		FleetRegion:                    getenvDefault(get, "FLEET_REGION", "unknown"),
		FleetStateFile:                 get("FLEET_STATE_FILE"),
		FleetTrustStoreFile:            get("FLEET_TRUST_STORE_FILE"),
		FleetCertificateID:             get("FLEET_CERTIFICATE_ID"),
		FleetKeyID:                     get("FLEET_KEY_ID"),
		FleetTrustDomain:               get("FLEET_TRUST_DOMAIN"),
		FleetPollInterval:              getenvDuration(get, "FLEET_POLL_INTERVAL", 30*time.Second),
		FleetTimeout:                   getenvDuration(get, "FLEET_TIMEOUT", 10*time.Second),
		FleetOfflineGrace:              getenvDuration(get, "FLEET_OFFLINE_GRACE", 24*time.Hour),
		FleetRequiredState:             getenvBool(get, "FLEET_REQUIRED_STATE", false),
		FleetCapabilities:              splitCSV(get("FLEET_CAPABILITIES")),
		FleetTLSCAFile:                 get("FLEET_TLS_CA_FILE"),
		FleetTLSCertFile:               get("FLEET_TLS_CERT_FILE"),
		FleetTLSKeyFile:                get("FLEET_TLS_KEY_FILE"),
		FleetTLSServerName:             get("FLEET_TLS_SERVER_NAME"),
		GatewayVersion:                 getenvDefault(get, "GATEWAY_VERSION", "1.5.0"),
		GatewayInstanceID:              getenvDefault(get, "GATEWAY_INSTANCE_ID", "gateway"),
		DeploymentEnvironment:          getenvDefault(get, "DEPLOYMENT_ENVIRONMENT", string(profile)),
		TokenVaultKey:                  get("TOKEN_VAULT_KEY"),
		TokenVaultKeyFile:              get("TOKEN_VAULT_KEY_FILE"),
		TokenVaultKeyringFile:          get("TOKEN_VAULT_KEYRING_FILE"),
		TokenVaultAllowKeyRemoval:      getenvBool(get, "TOKEN_VAULT_ALLOW_KEY_REMOVAL", false),
		TokenVaultTTL:                  getenvDuration(get, "TOKEN_VAULT_TTL", 24*time.Hour),
		TokenVaultRedisURL:             get("TOKEN_VAULT_REDIS_URL"),
		TokenVaultRedisCAFile:          get("TOKEN_VAULT_REDIS_CA_FILE"),
		TokenVaultRedisCertFile:        get("TOKEN_VAULT_REDIS_CERT_FILE"),
		TokenVaultRedisKeyFile:         get("TOKEN_VAULT_REDIS_KEY_FILE"),
		TokenVaultRedisServerName:      get("TOKEN_VAULT_REDIS_SERVER_NAME"),
		TokenVaultIdleTTL:              getenvDuration(get, "TOKEN_VAULT_IDLE_TTL", 0),
		TokenVaultMaxValueBytes:        getenvInt(get, "TOKEN_VAULT_MAX_VALUE_BYTES", 64*1024),
		TokenVaultMaxRecordsPerScope:   getenvInt(get, "TOKEN_VAULT_MAX_RECORDS_PER_SCOPE", 1000),
		TokenVaultMaxRecordsPerTenant:  getenvInt(get, "TOKEN_VAULT_MAX_RECORDS_PER_TENANT", 10000),
		TokenVaultMaxRecordsPerUser:    getenvInt(get, "TOKEN_VAULT_MAX_RECORDS_PER_USER", 1000),
		TokenVaultMaxRecordsPerSession: getenvInt(get, "TOKEN_VAULT_MAX_RECORDS_PER_SESSION", 1000),
		TokenVaultMaxRetrievals:        getenvInt(get, "TOKEN_VAULT_MAX_RETRIEVALS", 10),
		TokenVaultSingleUse:            getenvBool(get, "TOKEN_VAULT_SINGLE_USE", false),
		TokenVaultVisibleCategory:      getenvBool(get, "TOKEN_VAULT_VISIBLE_CATEGORY", false),
		QuarantineRedisURL:             get("QUARANTINE_REDIS_URL"),
		QuarantineRedisCAFile:          get("QUARANTINE_REDIS_CA_FILE"),
		QuarantineRedisCertFile:        get("QUARANTINE_REDIS_CERT_FILE"),
		QuarantineRedisKeyFile:         get("QUARANTINE_REDIS_KEY_FILE"),
		QuarantineRedisServerName:      get("QUARANTINE_REDIS_SERVER_NAME"),
		TelemetryHMACKey:               get("TELEMETRY_HMAC_KEY"),
		TelemetryHMACKeyFile:           get("TELEMETRY_HMAC_KEY_FILE"),
		AuditDir:                       getenvDefault(get, "AUDIT_WAL_DIR", "/tmp/aegisllm-audit"),
		AuditSegmentBytes:              getenvInt64(get, "AUDIT_SEGMENT_BYTES", 64<<20),
		AuditMaxBytes:                  getenvInt64(get, "AUDIT_MAX_BYTES", 4<<30),
		AuditRetention:                 getenvDuration(get, "AUDIT_RETENTION", 30*24*time.Hour),
		AuditFsync:                     getenvDefault(get, "AUDIT_FSYNC", "sync"),
		AuditHMACKey:                   get("AUDIT_HMAC_KEY"),
		AuditHMACKeyFile:               getenvDefault(get, "AUDIT_HMAC_KEY_FILE", "/run/secrets/aegis-audit-hmac-key"),
		AuditEncryptionKeyringFile:     get("AUDIT_ENCRYPTION_KEYRING_FILE"),
		AuditFailureMode:               getenvDefault(get, "AUDIT_FAILURE_MODE", "fail_closed"),
		AuditSIEMURL:                   get("AUDIT_SIEM_URL"),
		AuditSIEMAuthFile:              get("AUDIT_SIEM_AUTH_FILE"),
		AuditSIEMCAFile:                get("AUDIT_SIEM_CA_FILE"),
		AuditSIEMCertFile:              get("AUDIT_SIEM_CERT_FILE"),
		AuditSIEMKeyFile:               get("AUDIT_SIEM_KEY_FILE"),
		AuditSIEMServerName:            get("AUDIT_SIEM_SERVER_NAME"),
		AuditSIEMTimeout:               getenvDuration(get, "AUDIT_SIEM_TIMEOUT", 10*time.Second),
		AuditSIEMBatchSize:             getenvInt(get, "AUDIT_SIEM_BATCH_SIZE", 100),
		AuditSIEMMaxRetries:            getenvInt(get, "AUDIT_SIEM_MAX_RETRIES", 8),
		AuditSIEMDLQDir:                get("AUDIT_SIEM_DLQ_DIR"),
		AuthMode:                       getenvDefault(get, "AUTH_MODE", auth.ModeOff),
		JWTPublicKeyFile:               get("JWT_PUBLIC_KEY_FILE"),
		JWTHMACSecret:                  get("JWT_HMAC_SECRET"),
		JWTIssuer:                      get("JWT_ISSUER"),
		JWTAudience:                    get("JWT_AUDIENCE"),
		JWTTenantClaim:                 getenvDefault(get, "JWT_TENANT_CLAIM", "tenant_id"),
		JWTApplicationClaim:            getenvDefault(get, "JWT_APPLICATION_CLAIM", "azp"),
		JWTSubjectClaim:                getenvDefault(get, "JWT_SUBJECT_CLAIM", "sub"),
		JWTRolesClaim:                  getenvDefault(get, "JWT_ROLES_CLAIM", "roles"),
		JWTGroupsClaim:                 getenvDefault(get, "JWT_GROUPS_CLAIM", "groups"),
		JWTProviderClaim:               getenvDefault(get, "JWT_PROVIDER_CLAIM", "provider"),
		JWTSessionClaim:                getenvDefault(get, "JWT_SESSION_CLAIM", "sid"),
		AllowUnauthenticatedShadow:     strings.EqualFold(get("ALLOW_UNAUTHENTICATED_SHADOW"), "true"),
		ConformanceCapabilityGate:      getenvBool(get, "CONFORMANCE_CAPABILITY_GATE", false),
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
	auditDefaults := configFrom(func(string) string { return "" })
	if cfg.AuditDir == "" {
		cfg.AuditDir = auditDefaults.AuditDir
	}
	if cfg.AuditSegmentBytes == 0 {
		cfg.AuditSegmentBytes = auditDefaults.AuditSegmentBytes
	}
	if cfg.AuditMaxBytes == 0 {
		cfg.AuditMaxBytes = auditDefaults.AuditMaxBytes
	}
	if cfg.AuditRetention == 0 {
		cfg.AuditRetention = auditDefaults.AuditRetention
	}
	if cfg.AuditFsync == "" {
		cfg.AuditFsync = auditDefaults.AuditFsync
	}
	if cfg.AuditFailureMode == "" {
		cfg.AuditFailureMode = auditDefaults.AuditFailureMode
	}
	if cfg.AuditHMACKeyFile == "" {
		cfg.AuditHMACKeyFile = auditDefaults.AuditHMACKeyFile
	}
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
	if cfg.AttachmentMaxEncodedBytes == 0 {
		cfg.AttachmentMaxEncodedBytes = streamDefaults.AttachmentMaxEncodedBytes
	}
	if cfg.AttachmentMaxDecodedBytes == 0 {
		cfg.AttachmentMaxDecodedBytes = streamDefaults.AttachmentMaxDecodedBytes
	}
	if cfg.AttachmentMaxTextBytes == 0 {
		cfg.AttachmentMaxTextBytes = streamDefaults.AttachmentMaxTextBytes
	}
	if cfg.AttachmentMaxCount == 0 {
		cfg.AttachmentMaxCount = streamDefaults.AttachmentMaxCount
	}
	if cfg.AttachmentMaxPages == 0 {
		cfg.AttachmentMaxPages = streamDefaults.AttachmentMaxPages
	}
	if cfg.AttachmentMaxExpansionRatio == 0 {
		cfg.AttachmentMaxExpansionRatio = streamDefaults.AttachmentMaxExpansionRatio
	}
	if cfg.AttachmentTimeout == 0 {
		cfg.AttachmentTimeout = streamDefaults.AttachmentTimeout
	}
	if cfg.AttachmentMaxRedirects == 0 {
		cfg.AttachmentMaxRedirects = streamDefaults.AttachmentMaxRedirects
	}
	if cfg.TLSMinVersion == 0 {
		cfg.TLSMinVersion = tls.VersionTLS12
	}
	profile, err := ParseDeploymentProfile(string(cfg.profile()))
	if err != nil {
		return err
	}
	if cfg.JWTSessionClaim == "" {
		cfg.JWTSessionClaim = "sid"
	}
	if cfg.TokenVaultTTL == 0 {
		cfg.TokenVaultTTL = 24 * time.Hour
	}
	if cfg.TokenVaultMaxValueBytes == 0 {
		cfg.TokenVaultMaxValueBytes = 64 * 1024
	}
	if cfg.AuditDir == "" || cfg.AuditSegmentBytes <= 0 || cfg.AuditMaxBytes < cfg.AuditSegmentBytes {
		return errors.New("audit WAL capacity configuration is invalid")
	}
	if cfg.AuditFsync != string("write") && cfg.AuditFsync != string("sync") {
		return errors.New("AUDIT_FSYNC must be write or sync")
	}
	if cfg.AuditFailureMode != "fail_closed" && cfg.AuditFailureMode != "degrade" {
		return errors.New("AUDIT_FAILURE_MODE must be fail_closed or degrade")
	}
	if profile == ProfileProduction && strings.TrimSpace(cfg.AuditHMACKey) != "" {
		return errors.New("production rejects inline AUDIT_HMAC_KEY; use AUDIT_HMAC_KEY_FILE")
	}
	if cfg.AuditSIEMURL != "" {
		u, ok := parseDependencyURL(cfg.AuditSIEMURL)
		if !ok || !strings.EqualFold(u.Scheme, "https") {
			return errors.New("AUDIT_SIEM_URL must use verified TLS")
		}
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
	if err := validateRAGConfig(cfg, profile); err != nil {
		return err
	}
	if err := validateAttachmentConfig(cfg, profile); err != nil {
		return err
	}
	if err := validateFleetConfig(cfg, profile); err != nil {
		return err
	}
	if profile != ProfileProduction {
		if cfg.PIIRegistryFile != "" {
			if _, err := pii.LoadRegistryFile(cfg.PIIRegistryFile, string(profile)); err != nil {
				return errors.New("PII_NER_REGISTRY_FILE is invalid")
			}
		}
		return nil
	}
	if cfg.PIIRequireNER && strings.TrimSpace(cfg.PIIRegistryFile) == "" {
		return errors.New("production protected routes require PII_NER_REGISTRY_FILE")
	}
	if cfg.PIIRegistryFile != "" {
		if _, err := pii.LoadRegistryFile(cfg.PIIRegistryFile, string(profile)); err != nil {
			return errors.New("PII_NER_REGISTRY_FILE is invalid")
		}
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
		if strings.TrimSpace(cfg.JWTSessionClaim) == "" {
			return errors.New("production requires JWT_SESSION_CLAIM for session binding")
		}
	}
	if cfg.TokenVaultTTL <= 0 || cfg.TokenVaultMaxValueBytes <= 0 || cfg.TokenVaultMaxRetrievals < 0 || cfg.TokenVaultMaxRecordsPerScope < 0 || cfg.TokenVaultMaxRecordsPerTenant < 0 || cfg.TokenVaultMaxRecordsPerUser < 0 || cfg.TokenVaultMaxRecordsPerSession < 0 {
		return errors.New("token vault TTL, value, and retrieval limits are invalid")
	}
	if cfg.TokenVaultIdleTTL < 0 || (cfg.TokenVaultIdleTTL > 0 && cfg.TokenVaultIdleTTL >= cfg.TokenVaultTTL) {
		return errors.New("token vault idle TTL must be bounded by absolute TTL")
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
	if cfg.policyDistributionEnabled() {
		if strings.TrimSpace(cfg.PolicyTrustStoreFile) == "" {
			return errors.New("policy distribution requires POLICY_TRUST_STORE_FILE")
		}
	} else {
		if err := validatePolicyFile(cfg.PolicyFile); err != nil {
			return err
		}
		if err := validateQuestionsFile(cfg.QuestionsFile); err != nil {
			return err
		}
	}
	// Threshold artifacts are mandatory and strictly validated only when
	// semantic enforcement is requested. Deterministic-only production may
	// omit or ignore semantic artifacts and reports semantic=disabled.
	return nil
}

func validateRAGConfig(cfg Config, profile DeploymentProfile) error {
	defaults := configFrom(func(string) string { return "" })
	mode, adapter := strings.ToLower(strings.TrimSpace(cfg.RAGAuthMode)), strings.ToLower(strings.TrimSpace(cfg.RAGAuthAdapter))
	if mode == "" {
		mode = defaults.RAGAuthMode
	}
	if adapter == "" {
		adapter = defaults.RAGAuthAdapter
	}
	if mode != ragauth.ModeOff && mode != ragauth.ModeShadow && mode != ragauth.ModeEnforce {
		return errors.New("RAG_AUTH_MODE must be off, shadow, or enforce")
	}
	if adapter != ragauth.AdapterDeny && adapter != ragauth.AdapterFake && adapter != ragauth.AdapterHTTP {
		return errors.New("RAG_AUTH_ADAPTER must be deny, fake, or http")
	}
	if cfg.RAGAuthTimeout < 0 || cfg.RAGMaxResults < 0 || cfg.RAGMaxResultBytes < 0 || cfg.RAGMaxDepth < 0 || cfg.RAGMaxNodes < 0 || cfg.RAGMaxConcurrency < 0 || cfg.RAGDecisionMaxAge < 0 {
		return errors.New("RAG authorization limits must not be negative")
	}
	if (cfg.RAGAuthCertFile == "") != (cfg.RAGAuthKeyFile == "") {
		return errors.New("RAG_AUTH_CERT_FILE and RAG_AUTH_KEY_FILE must be paired")
	}
	if profile == ProfileProduction && mode == ragauth.ModeShadow {
		return errors.New("production does not permit RAG_AUTH_MODE=shadow")
	}
	if profile == ProfileProduction && mode == ragauth.ModeEnforce {
		if cfg.RAGAuthTimeout <= 0 || cfg.RAGMaxResults <= 0 || cfg.RAGMaxResultBytes <= 0 || cfg.RAGMaxDepth <= 0 || cfg.RAGMaxNodes <= 0 || cfg.RAGMaxConcurrency <= 0 || cfg.RAGDecisionMaxAge <= 0 {
			return errors.New("production RAG authorization limits must be positive")
		}
		if adapter != ragauth.AdapterHTTP {
			return errors.New("production RAG authorization requires RAG_AUTH_ADAPTER=http")
		}
		if strings.TrimSpace(cfg.RAGAuthURL) == "" || strings.TrimSpace(cfg.RAGAuthCAFile) == "" || strings.TrimSpace(cfg.RAGAuthCertFile) == "" || strings.TrimSpace(cfg.RAGAuthKeyFile) == "" {
			return errors.New("production RAG authorization requires private HTTPS/mTLS configuration")
		}
	}
	if mode == ragauth.ModeEnforce && adapter == ragauth.AdapterHTTP {
		u, err := url.Parse(strings.TrimSpace(cfg.RAGAuthURL))
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (profile == ProfileProduction && !strings.EqualFold(u.Scheme, "https")) || (profile != ProfileProduction && u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("RAG_AUTH_URL must be a bounded HTTP endpoint with verified TLS in production")
		}
	}
	return nil
}

func validateAttachmentConfig(cfg Config, profile DeploymentProfile) error {
	if cfg.AttachmentMaxEncodedBytes <= 0 || cfg.AttachmentMaxDecodedBytes <= 0 || cfg.AttachmentMaxTextBytes <= 0 || cfg.AttachmentMaxCount <= 0 || cfg.AttachmentMaxPages <= 0 || cfg.AttachmentMaxExpansionRatio <= 0 || cfg.AttachmentTimeout <= 0 || cfg.AttachmentMaxRedirects < 0 {
		return errors.New("attachment limits and timeout must be positive")
	}
	if cfg.AttachmentEnabled && len(cfg.AttachmentAllowedMIMEs) == 0 {
		return errors.New("DLP_ATTACHMENT_ALLOWED_MIME_TYPES must not be empty")
	}
	if !cfg.AttachmentEnabled {
		if profile == ProfileProduction && strings.TrimSpace(cfg.AttachmentAdapter) != "" {
			return errors.New("production cannot disable configured attachment DLP")
		}
		return nil
	}
	if cfg.AttachmentAdapter != "builtin" && cfg.AttachmentAdapter != "http" {
		return errors.New("DLP_ATTACHMENT_ADAPTER must be builtin or http")
	}
	if profile == ProfileProduction {
		if cfg.AttachmentAdapter != "http" || strings.TrimSpace(cfg.AttachmentExtractorURL) == "" {
			return errors.New("production attachment extraction requires authenticated private HTTP adapter")
		}
		u, ok := parseDependencyURL(cfg.AttachmentExtractorURL)
		if !ok || !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.RawQuery != "" {
			return errors.New("production attachment extractor must use verified HTTPS without credentials or query data")
		}
		if len(cfg.AttachmentAllowedHosts) == 0 {
			return errors.New("production attachment URL sources require DLP_ATTACHMENT_ALLOWED_HOSTS")
		}
		if cfg.AttachmentTLSCAFile == "" || cfg.AttachmentTLSCertFile == "" || cfg.AttachmentTLSKeyFile == "" {
			return errors.New("production attachment extractor requires CA and client certificate/key")
		}
		if !cfg.AttachmentAllowPrivateHosts {
			return errors.New("production attachment private service policy must explicitly allow private hosts")
		}
	}
	if (cfg.AttachmentTLSCertFile == "") != (cfg.AttachmentTLSKeyFile == "") {
		return errors.New("attachment TLS certificate and key must be paired")
	}
	return nil
}

func validateFleetConfig(cfg Config, profile DeploymentProfile) error {
	configured := strings.TrimSpace(cfg.FleetControlPlaneURL) != ""
	if !configured {
		if cfg.FleetRequiredState {
			return errors.New("FLEET_REQUIRED_STATE requires FLEET_CONTROL_PLANE_URL")
		}
		return nil
	}
	u, ok := parseDependencyURL(cfg.FleetControlPlaneURL)
	if !ok || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (profile == ProfileProduction && !strings.EqualFold(u.Scheme, "https")) || (profile != ProfileProduction && u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("FLEET_CONTROL_PLANE_URL must be a bounded HTTP endpoint; production requires HTTPS")
	}
	if cfg.FleetStateFile == "" || cfg.FleetTrustStoreFile == "" || cfg.FleetCertificateID == "" || cfg.FleetKeyID == "" || cfg.FleetTrustDomain == "" || cfg.FleetTenant == "" || cfg.FleetRegion == "" {
		return errors.New("fleet agent requires state, trust-store, certificate, key, and trust-domain references")
	}
	if cfg.FleetPollInterval <= 0 || cfg.FleetTimeout <= 0 || cfg.FleetOfflineGrace < 0 {
		return errors.New("fleet polling, timeout, and offline grace values are invalid")
	}
	if (cfg.FleetTLSCertFile == "") != (cfg.FleetTLSKeyFile == "") {
		return errors.New("FLEET_TLS_CERT_FILE and FLEET_TLS_KEY_FILE must be paired")
	}
	if profile == ProfileProduction && (cfg.FleetTLSCAFile == "" || cfg.FleetTLSCertFile == "" || cfg.FleetTLSKeyFile == "") {
		return errors.New("production fleet control plane requires CA and client certificate/key")
	}
	return nil
}

func (c Config) policyDistributionEnabled() bool {
	return strings.TrimSpace(c.PolicyBundleDir) != "" || strings.TrimSpace(c.PolicyBundlePath) != "" || strings.TrimSpace(c.PolicyControlPlaneURL) != ""
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
	questionData, err := securetransport.ReadTrustedFile(cfg.QuestionsFile)
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
	if cfg.profile() == ProfileProduction && (strings.TrimSpace(cfg.SemanticRegistryStateFile) == "" || strings.TrimSpace(cfg.SemanticRegistryTrustStoreFile) == "") {
		return errors.New("production semantic enforcement requires SEMANTIC_REGISTRY_STATE_FILE and SEMANTIC_REGISTRY_TRUST_STORE_FILE")
	}
	if (cfg.SemanticRegistryStateFile == "") != (cfg.SemanticRegistryTrustStoreFile == "") {
		return errors.New("semantic registry state and trust store must be configured together")
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
	if c.SecurityMode == "" {
		c.SecurityMode = defaults.SecurityMode
	}
	if c.AuthMode == "" {
		c.AuthMode = defaults.AuthMode
	}
	if c.HeaderApplication == "" {
		c.HeaderApplication = defaults.HeaderApplication
	}
	if c.HeaderTenant == "" {
		c.HeaderTenant = defaults.HeaderTenant
	}
	if c.HeaderUser == "" {
		c.HeaderUser = defaults.HeaderUser
	}
	if c.HeaderTargetProvider == "" {
		c.HeaderTargetProvider = defaults.HeaderTargetProvider
	}
	if c.DefaultTargetProvider == "" {
		c.DefaultTargetProvider = defaults.DefaultTargetProvider
	}
	if c.RAGAuthMode == "" {
		c.RAGAuthMode = defaults.RAGAuthMode
	}
	if c.RAGAuthAdapter == "" {
		c.RAGAuthAdapter = defaults.RAGAuthAdapter
	}
	if c.RAGAuthTimeout <= 0 {
		c.RAGAuthTimeout = defaults.RAGAuthTimeout
	}
	if c.RAGMaxResults <= 0 {
		c.RAGMaxResults = defaults.RAGMaxResults
	}
	if c.RAGMaxResultBytes <= 0 {
		c.RAGMaxResultBytes = defaults.RAGMaxResultBytes
	}
	if c.RAGMaxDepth <= 0 {
		c.RAGMaxDepth = defaults.RAGMaxDepth
	}
	if c.RAGMaxNodes <= 0 {
		c.RAGMaxNodes = defaults.RAGMaxNodes
	}
	if c.RAGMaxConcurrency <= 0 {
		c.RAGMaxConcurrency = defaults.RAGMaxConcurrency
	}
	if c.RAGDecisionMaxAge <= 0 {
		c.RAGDecisionMaxAge = defaults.RAGDecisionMaxAge
	}
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
	if c.MCPSessionTTL <= 0 {
		c.MCPSessionTTL = defaults.MCPSessionTTL
	}
	if c.MCPToolSchemaTTL <= 0 {
		c.MCPToolSchemaTTL = defaults.MCPToolSchemaTTL
	}
	if c.MCPMaxBodyBytes <= 0 {
		c.MCPMaxBodyBytes = defaults.MCPMaxBodyBytes
	}
	if c.MCPMaxEventBytes <= 0 {
		c.MCPMaxEventBytes = defaults.MCPMaxEventBytes
	}
	if c.MCPMaxStreamDuration <= 0 {
		c.MCPMaxStreamDuration = defaults.MCPMaxStreamDuration
	}
	if c.MCPMaxSessionCount <= 0 {
		c.MCPMaxSessionCount = defaults.MCPMaxSessionCount
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

func getenvDefault(get func(string) string, key, def string) string {
	if v := get(key); v != "" {
		return v
	}
	return def
}

func splitCSV(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
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
