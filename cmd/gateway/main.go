// Command gateway runs the LLM security gateway HTTP service.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aegisllm/gateway/internal/attachment"
	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/fleet"
	"github.com/aegisllm/gateway/internal/gateway"
	"github.com/aegisllm/gateway/internal/observability"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/policydistribution"
	"github.com/aegisllm/gateway/internal/quarantine"
	"github.com/aegisllm/gateway/internal/ragauth"
	"github.com/aegisllm/gateway/internal/securetransport"
	semanticcontrol "github.com/aegisllm/gateway/internal/semantic"
	"github.com/aegisllm/gateway/internal/tokenization"
)

// Injected by the reproducible release build. Developer builds remain
// explicit about their provenance rather than inheriting local VCS state.
var (
	buildVersion = "dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

type distributionObserver struct {
	metrics *observability.Metrics
	sink    audit.Sink
}

func (o distributionObserver) RecordDistribution(event, reason, keyID string) {
	if o.metrics != nil {
		o.metrics.RecordDistribution(event, reason, keyID)
	}
	if o.sink != nil {
		o.sink.Record(audit.Event{RequestID: "policy-distribution", Timestamp: time.Now().UTC(), Component: "policy-distribution", Mode: "distribution", Action: core.ActionAllow, Code: boundedDistributionValue(event), Reason: boundedDistributionValue(reason), DistributionEvent: boundedDistributionValue(event), DistributionKeyID: boundedDistributionValue(keyID)})
	}
}
func boundedDistributionValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		value = value[:64]
	}
	out := []byte(value)
	for i, c := range out {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':' {
			continue
		}
		out[i] = '_'
	}
	return string(out)
}

// loadVaultKey returns the 32-byte token-vault master key: hex-encoded via
// TOKEN_VAULT_KEY, or an ephemeral random key in development and shadow.
func loadVaultKey(hexKey string, logger *slog.Logger) ([]byte, error) {
	if hexKey != "" {
		key, err := hex.DecodeString(hexKey)
		if err != nil || len(key) != 32 {
			return nil, errors.New("TOKEN_VAULT_KEY must be 64 hex chars (32 bytes)")
		}
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	logger.Warn("TOKEN_VAULT_KEY not set; using ephemeral key (token mappings cannot survive restart)")
	return key, nil
}

func loadConfiguredSecret(inline, path string, metrics securetransport.Metrics) (string, *securetransport.File[string], error) {
	if path != "" {
		if inline != "" {
			return "", nil, errors.New("inline and file secret both configured")
		}
		file, err := securetransport.SecretFile(path, 2*time.Second, metrics)
		if err != nil {
			return "", nil, err
		}
		value, err := file.Get()
		if err != nil {
			file.Close()
			return "", nil, err
		}
		return value, file, nil
	}
	return inline, nil, nil
}

func loadVaultCipher(cfg gateway.Config, metrics securetransport.Metrics, logger *slog.Logger) (tokenization.Cipher, func(), error) {
	if cfg.TokenVaultKeyringFile != "" {
		if cfg.TokenVaultKeyFile != "" || cfg.TokenVaultKey != "" {
			return nil, nil, errors.New("multiple vault key sources configured")
		}
		keyring, err := tokenization.NewKeyringFile(cfg.TokenVaultKeyringFile, cfg.TLSReloadInterval, cfg.TokenVaultAllowKeyRemoval, metrics)
		if err != nil {
			return nil, nil, err
		}
		if _, err := keyring.Get(); err != nil {
			keyring.Close()
			return nil, nil, err
		}
		return keyring, keyring.Close, nil
	}
	if cfg.TokenVaultKeyFile != "" {
		if cfg.TokenVaultKey != "" {
			return nil, nil, errors.New("inline and file vault keys both configured")
		}
		file, err := securetransport.SecretFile(cfg.TokenVaultKeyFile, cfg.TLSReloadInterval, metrics)
		if err != nil {
			return nil, nil, err
		}
		encoded, err := file.Get()
		if err != nil {
			file.Close()
			return nil, nil, err
		}
		key, err := hex.DecodeString(encoded)
		if err != nil || len(key) != 32 {
			file.Close()
			return nil, nil, errors.New("vault key file is invalid")
		}
		return tokenization.NewReloadingCipher(file), file.Close, nil
	}
	key, err := loadVaultKey(cfg.TokenVaultKey, logger)
	if err != nil {
		return nil, nil, err
	}
	cipher, err := tokenization.NewCrypto(key)
	return cipher, func() {}, err
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		healthcheck()
		return
	}
	logger := newLogger()
	cfg := gateway.LoadConfig()
	if err := gateway.ValidateConfig(cfg); err != nil {
		logger.Error("configuration validation failed", "error", err)
		os.Exit(1)
	}

	// Invalid policy fails startup (T-010). When signed distribution is
	// configured, the verified bundle is the only source of runtime policy.
	var distribution *policydistribution.Manager
	var initialSnapshot *policydistribution.Snapshot
	var pol *policy.Policy
	var err error
	if cfg.PolicyBundleDir != "" || cfg.PolicyBundlePath != "" || cfg.PolicyControlPlaneURL != "" {
		distribution, err = policydistribution.NewManager(policydistribution.Config{
			BundleDir: cfg.PolicyBundleDir, BundlePath: cfg.PolicyBundlePath, ControlPlaneURL: cfg.PolicyControlPlaneURL,
			TrustStorePath: cfg.PolicyTrustStoreFile, StatePath: cfg.PolicyStateFile, Timeout: cfg.PolicyDistributionTimeout, PollInterval: cfg.PolicyDistributionPollInterval,
			GatewayVersion: cfg.GatewayVersion, Environment: cfg.DeploymentEnvironment, Retain: 3,
			CanaryPercent: cfg.PolicyCanaryPercent, CanarySoak: cfg.PolicyCanarySoak,
			TLS: securetransport.ClientTLSOptions{CAFile: cfg.PolicyTLSCAFile, CertificateFile: cfg.PolicyTLSCertFile, KeyFile: cfg.PolicyTLSKeyFile, ServerName: cfg.PolicyTLSServerName, MinVersion: cfg.TLSMinVersion, MaxVersion: cfg.TLSMaxVersion, PollInterval: cfg.TLSReloadInterval},
		}, nil)
		if err != nil {
			logger.Error("policy distribution configuration failed", "error", err)
			os.Exit(1)
		}
		if err = distribution.LoadInitial(context.Background()); err != nil {
			logger.Error("signed policy bundle unavailable")
			os.Exit(1)
		}
		initialSnapshot = distribution.Current()
		pol = initialSnapshot.Policy
	} else {
		pol, err = policy.LoadFile(cfg.PolicyFile)
		if err != nil {
			logger.Error("policy load failed", "path", cfg.PolicyFile)
			os.Exit(1)
		}
	}

	srv, err := gateway.NewServer(cfg, logger)
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}
	defer srv.Close()
	srv.SetBuildInfo(gateway.BuildInfo{Version: buildVersion, Commit: buildCommit, Date: buildDate})

	// Versioned question schema (FR-009); invalid schema fails startup.
	var questionSchema *decision.QuestionSchema
	if initialSnapshot != nil && initialSnapshot.Questions != nil {
		questionSchema = initialSnapshot.Questions
	} else {
		questionSchema, err = decision.LoadQuestionsFile(cfg.QuestionsFile)
		if err != nil {
			logger.Error("question schema load failed", "path", cfg.QuestionsFile)
			os.Exit(1)
		}
	}

	metrics := observability.New()
	srv.SetSecureMaterialMetrics(metrics)
	var quarantineStore quarantine.Store
	var quarantineRedis *redis.Client
	if cfg.DeploymentProfile == gateway.ProfileProduction {
		if strings.TrimSpace(cfg.QuarantineRedisURL) == "" || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.QuarantineRedisURL)), "rediss://") {
			logger.Error("production requires QUARANTINE_REDIS_URL=rediss://")
			os.Exit(1)
		}
	}
	if cfg.QuarantineRedisURL != "" {
		opts, parseErr := redis.ParseURL(cfg.QuarantineRedisURL)
		if parseErr != nil {
			logger.Error("quarantine Redis URL is invalid")
			os.Exit(1)
		}
		if strings.HasPrefix(strings.ToLower(cfg.QuarantineRedisURL), "rediss://") && (cfg.QuarantineRedisCAFile != "" || cfg.QuarantineRedisCertFile != "" || cfg.QuarantineRedisKeyFile != "") {
			tlsConfig, certFiles, tlsErr := (securetransport.ClientTLSOptions{CAFile: cfg.QuarantineRedisCAFile, CertificateFile: cfg.QuarantineRedisCertFile, KeyFile: cfg.QuarantineRedisKeyFile, ServerName: cfg.QuarantineRedisServerName, MinVersion: cfg.TLSMinVersion, MaxVersion: cfg.TLSMaxVersion, PollInterval: cfg.TLSReloadInterval, Metrics: metrics}).TLSConfig()
			if tlsErr != nil {
				logger.Error("quarantine Redis TLS configuration invalid")
				os.Exit(1)
			}
			opts.TLSConfig = tlsConfig
			for i, file := range certFiles {
				srv.AddMaterialReadiness(fmt.Sprintf("quarantine_redis_client_certificate_%d", i+1), file.Status)
				defer file.Close()
			}
		}
		quarantineRedis = redis.NewClient(opts)
		quarantineStore, err = quarantine.NewRedisStore(quarantineRedis, "aegis-quarantine")
		if err != nil {
			logger.Error("quarantine Redis store unavailable")
			os.Exit(1)
		}
		defer quarantineRedis.Close()
	} else {
		quarantineStore = quarantine.NewMemoryStore()
		logger.Warn("QUARANTINE_REDIS_URL not set; using process-local quarantine state (development/shadow only)")
	}
	quarantineManager, qErr := quarantine.NewManager(quarantineStore, gateway.QuarantinePolicyForPolicy(pol), cfg.DeploymentProfile == gateway.ProfileProduction)
	if qErr != nil {
		logger.Error("quarantine policy invalid")
		os.Exit(1)
	}
	srv.SetQuarantine(quarantineManager)
	var ragAuthorizer ragauth.Authorizer = ragauth.DenyByDefault{}
	var ragClose func()
	if cfg.RAGAuthAdapter == ragauth.AdapterHTTP && cfg.RAGAuthURL != "" {
		authorizer, authErr := ragauth.NewHTTPAuthorizer(ragauth.Config{URL: cfg.RAGAuthURL, Timeout: cfg.RAGAuthTimeout, Production: cfg.DeploymentProfile == gateway.ProfileProduction,
			TLS: securetransport.ClientTLSOptions{CAFile: cfg.RAGAuthCAFile, CertificateFile: cfg.RAGAuthCertFile, KeyFile: cfg.RAGAuthKeyFile, ServerName: cfg.RAGAuthServerName,
				MinVersion: cfg.TLSMinVersion, MaxVersion: cfg.TLSMaxVersion, PollInterval: cfg.TLSReloadInterval, Metrics: metrics}, Limits: ragauth.Limits{MaxResultBytes: cfg.RAGMaxResultBytes}})
		if authErr != nil {
			logger.Error("RAG authorization TLS configuration invalid")
			os.Exit(1)
		}
		ragAuthorizer = authorizer
		ragClose = authorizer.Close
	} else if cfg.RAGAuthAdapter == ragauth.AdapterFake && cfg.DeploymentProfile != gateway.ProfileProduction {
		ragAuthorizer = &ragauth.FakeAuthorizer{Allow: true}
	}
	ragGateway, ragErr := ragauth.NewGateway(ragauth.Config{Mode: cfg.RAGAuthMode, Adapter: cfg.RAGAuthAdapter, Production: cfg.DeploymentProfile == gateway.ProfileProduction,
		Timeout: cfg.RAGAuthTimeout, Limits: ragauth.Limits{MaxBytes: cfg.MaxBodyBytes, MaxResults: cfg.RAGMaxResults, MaxResultBytes: cfg.RAGMaxResultBytes, MaxDepth: cfg.RAGMaxDepth,
			MaxNodes: cfg.RAGMaxNodes, MaxConcurrency: cfg.RAGMaxConcurrency, DecisionMaxAge: cfg.RAGDecisionMaxAge}}, ragAuthorizer)
	if ragErr != nil {
		logger.Error("RAG authorization configuration invalid")
		os.Exit(1)
	}
	if ragClose != nil {
		defer ragClose()
	}
	srv.SetRAGAuthorization(ragGateway)
	srv.AddReadinessCheck("rag_authorization", func() string {
		status := ragGateway.Status()
		if cfg.DeploymentProfile == gateway.ProfileProduction && cfg.RAGAuthMode == ragauth.ModeEnforce && !status.Available {
			return "RAG authorization unavailable"
		}
		return ""
	})
	telemetryKey, telemetryFile, err := loadConfiguredSecret(cfg.TelemetryHMACKey, cfg.TelemetryHMACKeyFile, metrics)
	if err != nil {
		logger.Error("telemetry key unavailable")
		os.Exit(1)
	}
	if telemetryFile != nil {
		defer telemetryFile.Close()
		srv.AddMaterialReadiness("telemetry_hmac_key", telemetryFile.Status)
	}
	registry := detectors.ProductionRegistry(telemetryKey, nil)
	var auditHMAC []byte
	var auditKeyFile *securetransport.File[string]
	_, auditKeyPathExists := os.Stat(cfg.AuditHMACKeyFile)
	if cfg.AuditHMACKey != "" || cfg.DeploymentProfile == gateway.ProfileProduction || auditKeyPathExists == nil {
		var auditKey string
		auditKey, auditKeyFile, err = loadConfiguredSecret(cfg.AuditHMACKey, cfg.AuditHMACKeyFile, metrics)
		if err != nil {
			logger.Error("audit HMAC key unavailable")
			os.Exit(1)
		}
		auditHMAC = []byte(auditKey)
		if auditKeyFile != nil {
			defer auditKeyFile.Close()
			srv.AddMaterialReadiness("audit_hmac_key", auditKeyFile.Status)
		}
	}
	wal, err := audit.OpenWAL(audit.WALConfig{Dir: cfg.AuditDir, SegmentBytes: cfg.AuditSegmentBytes, MaxBytes: cfg.AuditMaxBytes, Retention: cfg.AuditRetention, Fsync: audit.Durability(cfg.AuditFsync), HMACKey: auditHMAC, EncryptionKeyring: cfg.AuditEncryptionKeyringFile, Sanitize: audit.SanitizeOptions{PrincipalHMACKey: auditHMAC, HashPrincipals: cfg.DeploymentProfile == gateway.ProfileProduction}})
	if err != nil {
		logger.Error("audit WAL unavailable")
		os.Exit(1)
	}
	var mirror audit.Sink
	if cfg.DeploymentProfile != gateway.ProfileProduction {
		mirror = audit.NewWriterSink(os.Stdout)
	}
	durableSink := audit.NewDurableSink(wal, mirror)
	durableSink.SetFailClosed(cfg.AuditFailureMode == "fail_closed")
	var exporter *audit.Exporter
	if cfg.AuditSIEMURL != "" {
		exporter, err = audit.NewExporter(wal, audit.ExporterConfig{URL: cfg.AuditSIEMURL, AuthFile: cfg.AuditSIEMAuthFile, CAFile: cfg.AuditSIEMCAFile, ClientCertFile: cfg.AuditSIEMCertFile, ClientKeyFile: cfg.AuditSIEMKeyFile, ServerName: cfg.AuditSIEMServerName, DLQDir: cfg.AuditSIEMDLQDir, Timeout: cfg.AuditSIEMTimeout, BatchSize: cfg.AuditSIEMBatchSize, MaxRetries: cfg.AuditSIEMMaxRetries})
		if err != nil {
			logger.Error("audit exporter unavailable")
			os.Exit(1)
		}
		exporter.Start(context.Background())
	}
	var sink audit.Sink = durableSink
	srv.SetAudit(wal, exporter, durableSink)
	var fleetAgent *fleet.Agent
	if cfg.FleetControlPlaneURL != "" {
		buildDigest := releaseDigest(buildVersion + "\x00" + buildCommit + "\x00" + buildDate)
		identity := fleet.Identity{GatewayID: cfg.GatewayInstanceID, Tenant: cfg.FleetTenant, Environment: cfg.DeploymentEnvironment, Region: cfg.FleetRegion, SoftwareVersion: cfg.GatewayVersion, BuildDigest: buildDigest, SBOMDigest: releaseDigest("sbom:" + buildDigest), Provenance: releaseDigest("provenance:" + buildDigest), Capabilities: cfg.FleetCapabilities, TrustDomain: cfg.FleetTrustDomain, EnrollmentState: "enrolled", CertificateID: cfg.FleetCertificateID, KeyID: cfg.FleetKeyID, Revision: 1}
		fleetAgent, err = fleet.NewAgent(fleet.AgentConfig{Identity: identity, ControlPlaneURL: cfg.FleetControlPlaneURL, TrustStorePath: cfg.FleetTrustStoreFile, StatePath: cfg.FleetStateFile, PollInterval: cfg.FleetPollInterval, Timeout: cfg.FleetTimeout, OfflineGrace: cfg.FleetOfflineGrace, RequireState: cfg.FleetRequiredState, TLS: securetransport.ClientTLSOptions{CAFile: cfg.FleetTLSCAFile, CertificateFile: cfg.FleetTLSCertFile, KeyFile: cfg.FleetTLSKeyFile, ServerName: cfg.FleetTLSServerName, MinVersion: cfg.TLSMinVersion, MaxVersion: cfg.TLSMaxVersion, PollInterval: cfg.TLSReloadInterval, Metrics: metrics}, Apply: func(desired fleet.DesiredState) error {
			if distribution == nil || distribution.Current() == nil || !strings.EqualFold(distribution.Current().Bundle.Manifest.PolicySHA256, desired.Policy.Digest) {
				return errors.New("fleet policy reference is not an already verified local policy artifact")
			}
			return nil
		}, Audit: fleetAuditAdapter{sink: sink, metrics: metrics}})
		if err != nil {
			logger.Error("fleet agent configuration failed", "error", err)
			os.Exit(1)
		}
		srv.SetFleetAgent(fleetAgent)
	}
	if distribution != nil {
		distribution.SetObserver(distributionObserver{metrics: metrics, sink: sink})
	}
	// Security mode is not stated here: Server.SetPipeline propagates
	// cfg.SecurityMode into the pipeline — the server owns the mode.
	pipe := gateway.NewSecurityPipeline(registry, policy.NewEngine(pol), sink)
	attachmentInspector, attachmentErr := attachment.New(attachment.Config{
		Enabled: cfg.AttachmentEnabled, Production: cfg.DeploymentProfile == gateway.ProfileProduction,
		Adapter: cfg.AttachmentAdapter, EndpointURL: cfg.AttachmentExtractorURL,
		AllowedHosts: cfg.AttachmentAllowedHosts, AllowPrivateHosts: cfg.AttachmentAllowPrivateHosts,
		MaxEncodedBytes: cfg.AttachmentMaxEncodedBytes, MaxDecodedBytes: cfg.AttachmentMaxDecodedBytes,
		MaxTextBytes: cfg.AttachmentMaxTextBytes, MaxAttachments: cfg.AttachmentMaxCount, MaxPages: cfg.AttachmentMaxPages,
		MaxExpansionRatio: cfg.AttachmentMaxExpansionRatio, Timeout: cfg.AttachmentTimeout, MaxRedirects: cfg.AttachmentMaxRedirects,
		AllowedMIMEs: cfg.AttachmentAllowedMIMEs,
		TLS:          securetransport.ClientTLSOptions{CAFile: cfg.AttachmentTLSCAFile, CertificateFile: cfg.AttachmentTLSCertFile, KeyFile: cfg.AttachmentTLSKeyFile, ServerName: cfg.AttachmentTLSServerName, MinVersion: cfg.TLSMinVersion, MaxVersion: cfg.TLSMaxVersion, PollInterval: cfg.TLSReloadInterval, Metrics: metrics},
	}, nil)
	if attachmentErr != nil {
		logger.Error("attachment extractor unavailable")
		os.Exit(1)
	}
	for n, status := range attachmentInspector.MaterialStatuses() {
		srv.AddMaterialReadiness(fmt.Sprintf("attachment_tls_material_%d", n+1), status)
	}
	defer attachmentInspector.Close()
	pipe.SetAttachmentInspector(attachmentInspector)
	srv.AddReadinessCheck("attachment_dlp", func() string {
		status := attachmentInspector.Status()
		if cfg.DeploymentProfile == gateway.ProfileProduction && !status.Enabled {
			return "attachment DLP disabled"
		}
		if status.Enabled && !status.Ready {
			return "attachment extractor unavailable"
		}
		return ""
	})
	spanProviders := []pii.SpanProvider{pii.NewRegexSpanProvider()}
	if cfg.PIIRegistryFile != "" {
		nerRegistry, loadErr := pii.LoadRegistryFile(cfg.PIIRegistryFile, string(cfg.DeploymentProfile))
		if loadErr != nil {
			logger.Error("PII NER registry unavailable")
			os.Exit(1)
		}
		nerProvider, buildErr := pii.NewProviderRegistry(nerRegistry)
		if buildErr != nil {
			logger.Error("PII NER provider configuration invalid")
			os.Exit(1)
		}
		nerProvider.SetMetrics(metrics)
		spanProviders = append(spanProviders, nerProvider)
		srv.SetPIIProviderStatus(nerProvider.Status)
		srv.AddReadinessCheck("pii_ner", func() string {
			for _, status := range nerProvider.Status() {
				if !status.Available || status.Breaker == "open" {
					return "PII NER provider unavailable"
				}
			}
			return ""
		})
	}
	pipe.SetSpanProvider(pii.NewCompositeSpanProvider(spanProviders...))
	pipe.SetSpanPolicy(cfg.PIIRequireNER)
	// Token vault (ticket 06): envelope-encrypted mappings with TTL.
	vaultCipher, closeVaultMaterial, err := loadVaultCipher(cfg, metrics, logger)
	if err != nil {
		logger.Error("token vault keyring unavailable")
		os.Exit(1)
	}
	if closeVaultMaterial != nil {
		defer closeVaultMaterial()
	}
	if provider, ok := vaultCipher.(interface{ Status() securetransport.Status }); ok {
		srv.AddMaterialReadiness("token_vault_key", provider.Status)
	}
	vaultTTL := cfg.TokenVaultTTL
	var vault tokenization.Vault
	if redisURL := cfg.TokenVaultRedisURL; redisURL != "" {
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			logger.Error("invalid TOKEN_VAULT_REDIS_URL")
			os.Exit(1)
		}
		if opts.TLSConfig != nil || cfg.TokenVaultRedisCAFile != "" || cfg.TokenVaultRedisCertFile != "" || cfg.TokenVaultRedisKeyFile != "" {
			serverName := cfg.TokenVaultRedisServerName
			if serverName == "" {
				if parsed, parseErr := url.Parse(redisURL); parseErr == nil {
					serverName = parsed.Hostname()
				}
			}
			tlsConfig, redisCertFiles, tlsErr := (securetransport.ClientTLSOptions{
				CAFile: cfg.TokenVaultRedisCAFile, CertificateFile: cfg.TokenVaultRedisCertFile, KeyFile: cfg.TokenVaultRedisKeyFile,
				ServerName: serverName, MinVersion: cfg.TLSMinVersion, MaxVersion: cfg.TLSMaxVersion,
				PollInterval: cfg.TLSReloadInterval, Metrics: metrics,
			}).TLSConfig()
			if tlsErr != nil {
				logger.Error("redis TLS configuration invalid")
				os.Exit(1)
			}
			if opts.TLSConfig != nil {
				opts.TLSConfig = tlsConfig
			} else {
				logger.Error("Redis TLS material requires rediss://")
				os.Exit(1)
			}
			for i, file := range redisCertFiles {
				srv.AddMaterialReadiness(fmt.Sprintf("redis_client_certificate_%d", i+1), file.Status)
			}
			defer func() {
				for _, file := range redisCertFiles {
					file.Close()
				}
			}()
		}
		client := redis.NewClient(opts)
		vault = tokenization.NewRedisVault(client, "tokvault", vaultTTL)
		srv.AddReadinessCheck("token_store", func() string {
			if err := client.Ping(context.Background()).Err(); err != nil {
				return "redis unreachable"
			}
			return ""
		})
	} else {
		vault = tokenization.NewInMemoryVault()
		logger.Warn("TOKEN_VAULT_REDIS_URL not set; using in-memory token vault (mappings are lost on restart)")
	}
	pipe.SetTokenStore(vault, vaultCipher, vaultTTL)
	if cfg.DeploymentProfile == gateway.ProfileProduction {
		scoped, scopedErr := tokenization.NewScopedVault(vault, vaultCipher, tokenization.SecureVaultOptions{
			RequireSession: true, TTL: vaultTTL, IdleTTL: cfg.TokenVaultIdleTTL,
			MaxValueBytes: cfg.TokenVaultMaxValueBytes, MaxRetrievals: cfg.TokenVaultMaxRetrievals,
			MaxRecordsPerScope: cfg.TokenVaultMaxRecordsPerScope, MaxRecordsPerTenant: cfg.TokenVaultMaxRecordsPerTenant,
			MaxRecordsPerUser: cfg.TokenVaultMaxRecordsPerUser, MaxRecordsPerSession: cfg.TokenVaultMaxRecordsPerSession,
			SingleUse: cfg.TokenVaultSingleUse, VisibleCategory: cfg.TokenVaultVisibleCategory,
		})
		if scopedErr != nil {
			logger.Error("scoped token vault unavailable")
			os.Exit(1)
		}
		pipe.SetScopedTokenStore(scoped)
	}

	// Semantic decision provider (ticket 08): local laya-serve when
	// configured, otherwise a noop provider and no semantic calls.
	var laya *decision.LayaProvider
	providerName := "noop"
	if cfg.LayaURL != "" {
		laya, err = decision.NewSecureLayaProvider(cfg.LayaURL, cfg.LayaEvaluatePath, cfg.LayaTimeout, securetransport.ClientTLSOptions{
			CAFile: cfg.LayaTLSCAFile, CertificateFile: cfg.LayaTLSCertFile, KeyFile: cfg.LayaTLSKeyFile,
			ServerName: cfg.LayaTLSServerName, MinVersion: cfg.TLSMinVersion, MaxVersion: cfg.TLSMaxVersion,
			PollInterval: cfg.TLSReloadInterval, Metrics: metrics,
		})
		if err != nil {
			logger.Error("Laya TLS configuration invalid")
			os.Exit(1)
		}
		defer laya.Close()
		for name, status := range laya.MaterialStatuses() {
			srv.AddMaterialReadiness(name, status)
		}
		laya.SetQuestionSchema(questionSchema.Schema)
		breaker := decision.NewCircuitBreaker(3, 30*time.Second)
		provider := decision.NewResilientProvider(laya, breaker)
		limited := decision.NewLimitedProvider(provider, cfg.MaxConcurrentLaya, metrics.SetActiveLayaEvaluations)
		pipe.SetDecisionProvider(limited, questionSchema)
		providerName = "laya"
		srv.AddReadinessCheck("laya", func() string {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := laya.Health(ctx); err != nil {
				return "laya-serve unreachable"
			}
			return ""
		})
		logger.Info("semantic provider enabled", "schema", "security-v1")
	} else {
		pipe.SetDecisionProvider(&decision.NoopProvider{}, questionSchema)
	}
	var thresholds *policy.SemanticThresholds
	var semanticRegistry *semanticcontrol.Manager
	if initialSnapshot != nil {
		thresholds = initialSnapshot.Thresholds
		if thresholds != nil {
			pipe.SetSemanticThresholds(thresholds)
			metrics.ObserveCalibrationArtifact(thresholds.ID, thresholds.Version, thresholds.Provider, thresholds.Checkpoint, thresholds.QuestionSchemaID, thresholds.State, thresholds.CalibrationTimestamp)
		}
	} else if cfg.ThresholdsFile != "" {
		if _, statErr := os.Stat(cfg.ThresholdsFile); statErr == nil {
			var loadErr error
			thresholds, loadErr = policy.LoadSemanticThresholdsFile(cfg.ThresholdsFile)
			if loadErr != nil {
				logger.Error("threshold policy load failed", "path", cfg.ThresholdsFile)
				os.Exit(1)
			}
			pipe.SetSemanticThresholds(thresholds)
			metrics.ObserveCalibrationArtifact(thresholds.ID, thresholds.Version, thresholds.Provider, thresholds.Checkpoint, thresholds.QuestionSchemaID, thresholds.State, thresholds.CalibrationTimestamp)
		}
	}
	if cfg.SemanticEnforce {
		pipe.EnableSemanticEnforce()
	}
	if cfg.SemanticRegistryStateFile != "" {
		registry, registryErr := semanticcontrol.NewManager(semanticcontrol.Config{StatePath: cfg.SemanticRegistryStateFile, TrustStorePath: cfg.SemanticRegistryTrustStoreFile, Production: cfg.DeploymentProfile == gateway.ProfileProduction, RuntimeVersion: cfg.GatewayVersion, Observer: func(t semanticcontrol.Transition) {
			sink.Record(audit.Event{RequestID: "semantic-registry", Timestamp: time.Now().UTC(), Component: "semantic-registry", Mode: cfg.SecurityMode, Action: core.ActionReview, Code: "SEMANTIC_LIFECYCLE_TRANSITION", ReasonID: t.Provenance, SemanticModelID: t.Model.ID, SemanticModelVersion: t.Model.Version, SemanticModelDigest: t.Model.Digest, SemanticLifecycleFrom: string(t.From), SemanticLifecycleState: string(t.To), SemanticLifecycleRevision: t.Revision, SemanticLifecycleActor: t.Actor})
		}})
		if registryErr != nil {
			logger.Error("semantic registry configuration failed")
			os.Exit(1)
		}
		semanticRegistry = registry
		registry.SetActivator(func(binding semanticcontrol.Activation) error {
			if thresholds == nil {
				return errors.New("semantic threshold artifact unavailable")
			}
			return pipe.ActivateRuntimeSnapshotBound(policy.NewEngine(pol), questionSchema, thresholds, binding.Model.ID, binding.Model.Version, binding.Model.Digest, binding.ThresholdID, binding.ThresholdVersion, binding.ThresholdDigest)
		})
		srv.SetSemanticRegistry(registry)
		if _, active := registry.Active(); active {
			if err := registry.ActivateCurrent(); err != nil {
				logger.Error("active semantic model could not be activated")
				os.Exit(1)
			}
		}
	}
	checkpoint, thresholdID, thresholdVersion, calibrationTimestamp := "", "", 0, ""
	if thresholds != nil {
		checkpoint, thresholdID, thresholdVersion, calibrationTimestamp = thresholds.Checkpoint, thresholds.ID, thresholds.Version, thresholds.CalibrationTimestamp
	}
	srv.SetSemanticReadiness(func() gateway.SemanticReadiness {
		status := "disabled"
		if !cfg.SemanticEnforce {
			if cfg.SecurityMode == gateway.ModeShadow {
				status = "shadow"
			}
		} else {
			status = "ready"
			if laya == nil || thresholds == nil {
				status = "unready"
			}
			if laya != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				if err := laya.Health(ctx); err != nil {
					status = "unready"
				}
				cancel()
			}
		}
		return gateway.SemanticReadiness{Status: status, Provider: providerName, SchemaVersion: questionSchema.Schema,
			ThresholdPolicyID: thresholdID, ThresholdPolicyVersion: thresholdVersion,
			CheckpointID: checkpoint, CalibrationTimestamp: calibrationTimestamp,
			ModelID: func() string {
				if semanticRegistry == nil {
					return ""
				}
				if r, ok := semanticRegistry.Active(); ok {
					return r.Artifact.Metadata.ModelID
				}
				return ""
			}(),
			ModelVersion: func() string {
				if semanticRegistry == nil {
					return ""
				}
				if r, ok := semanticRegistry.Active(); ok {
					return r.Artifact.Metadata.Version
				}
				return ""
			}(),
			ModelDigest: func() string {
				if semanticRegistry == nil {
					return ""
				}
				if r, ok := semanticRegistry.Active(); ok {
					return r.Artifact.Metadata.Digest
				}
				return ""
			}(),
			ThresholdArtifactDigest: func() string {
				if semanticRegistry == nil {
					return ""
				}
				if r, ok := semanticRegistry.Active(); ok {
					return r.Artifact.Metadata.ThresholdDigest
				}
				return ""
			}()}
	})

	pipe.SetRecorder(metrics)
	srv.SetMetricsHandler(metrics.Handler())

	srv.SetPipeline(pipe)
	srv.SetPolicy(pol)
	if distribution != nil {
		pipe.SetCanaryAssignment(func(env *core.InspectionEnvelope) bool {
			return env.Metadata["verified_identity"] == "true" && distribution.IsCanary(cfg.GatewayInstanceID, env.Tenant, env.Application)
		})
		pipe.SetCanaryObserver(func(disagreement bool) {
			distribution.ObserveCanary(cfg.GatewayInstanceID, disagreement)
			if disagreement {
				metrics.ObserveCanaryDisagreement()
			}
		})
		distribution.SetApply(func(snapshot *policydistribution.Snapshot) error {
			if semanticRegistry != nil && snapshot.SemanticModel.ID != "" {
				if err := semanticRegistry.BindPolicy(semanticcontrol.PolicyBinding{PolicyID: snapshot.Policy.ID, PolicyVersion: snapshot.Policy.Version, PolicyDigest: snapshot.Bundle.Manifest.PolicySHA256}, semanticcontrol.ModelRef{ID: snapshot.SemanticModel.ID, Version: snapshot.SemanticModel.Version, Digest: snapshot.SemanticModel.Digest}); err != nil {
					return err
				}
			}
			var activationErr error
			if snapshot.SemanticModel.ID != "" {
				if snapshot.Thresholds == nil {
					return errors.New("semantic policy bundle has no threshold artifact")
				}
				activationErr = pipe.ActivateRuntimeSnapshotBound(policy.NewEngine(snapshot.Policy), snapshot.Questions, snapshot.Thresholds, snapshot.SemanticModel.ID, snapshot.SemanticModel.Version, snapshot.SemanticModel.Digest, snapshot.Thresholds.ID, snapshot.Thresholds.Version, snapshot.Bundle.Manifest.ThresholdSHA256)
			} else {
				activationErr = pipe.ActivateRuntimeSnapshot(policy.NewEngine(snapshot.Policy), snapshot.Questions, snapshot.Thresholds)
			}
			if activationErr != nil {
				return activationErr
			}
			srv.SetRuntimePolicy(snapshot.Policy)
			return nil
		})
		distribution.SetCandidateApply(func(snapshot *policydistribution.Snapshot) error {
			if snapshot == nil {
				pipe.ClearCandidateRuntimeSnapshot()
				return nil
			}
			if semanticRegistry != nil && snapshot.SemanticModel.ID != "" {
				if err := semanticRegistry.BindPolicy(semanticcontrol.PolicyBinding{PolicyID: snapshot.Policy.ID, PolicyVersion: snapshot.Policy.Version, PolicyDigest: snapshot.Bundle.Manifest.PolicySHA256}, semanticcontrol.ModelRef{ID: snapshot.SemanticModel.ID, Version: snapshot.SemanticModel.Version, Digest: snapshot.SemanticModel.Digest}); err != nil {
					return err
				}
			}
			if snapshot.SemanticModel.ID != "" {
				if snapshot.Thresholds == nil {
					return errors.New("semantic policy bundle has no threshold artifact")
				}
				return pipe.SetCandidateRuntimeSnapshotBound(policy.NewEngine(snapshot.Policy), snapshot.Questions, snapshot.Thresholds, snapshot.SemanticModel.ID, snapshot.SemanticModel.Version, snapshot.SemanticModel.Digest, snapshot.Thresholds.ID, snapshot.Thresholds.Version, snapshot.Bundle.Manifest.ThresholdSHA256)
			}
			return pipe.SetCandidateRuntimeSnapshot(policy.NewEngine(snapshot.Policy), snapshot.Questions, snapshot.Thresholds)
		})
		srv.SetPolicyDistribution(distribution)
	}
	srv.AddReadinessCheck("policy_loaded", func() string { return "" })
	srv.AddReadinessCheck("questions_loaded", func() string { return "" })
	if cfg.TokenVaultRedisURL == "" {
		srv.AddReadinessCheck("token_store", func() string { return "" })
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: cfg.ServerReadHeaderTimeout,
		ReadTimeout:       cfg.ServerReadTimeout,
		IdleTimeout:       cfg.ServerIdleTimeout,
	}
	if cfg.InboundTLSCertFile != "" || cfg.InboundTLSKeyFile != "" {
		tlsConfig, certFiles, tlsErr := (securetransport.ServerTLSOptions{
			CertificateFile: cfg.InboundTLSCertFile, KeyFile: cfg.InboundTLSKeyFile, ClientCAFile: cfg.InboundTLSClientCAFile,
			RequireClient: cfg.InboundMTLSMode == "require", MinVersion: cfg.TLSMinVersion, MaxVersion: cfg.TLSMaxVersion,
			PollInterval: cfg.TLSReloadInterval, Metrics: metrics,
		}).TLSConfig()
		if tlsErr != nil {
			logger.Error("inbound TLS configuration invalid")
			os.Exit(1)
		}
		httpServer.TLSConfig = tlsConfig
		for i, file := range certFiles {
			srv.AddMaterialReadiness(fmt.Sprintf("inbound_server_certificate_%d", i+1), file.Status)
		}
		defer func() {
			for _, file := range certFiles {
				file.Close()
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if distribution != nil && cfg.PolicyControlPlaneURL != "" {
		go func() {
			ticker := time.NewTicker(cfg.PolicyDistributionPollInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					_ = distribution.Poll(ctx)
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	if fleetAgent != nil {
		go func() {
			fleetAgent.Run(ctx)
		}()
	}

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ServerShutdownTimeout)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	logger.Info("security gateway listening",
		"addr", cfg.ListenAddr,
		"deployment_profile", cfg.DeploymentProfile,
		"security_mode", cfg.SecurityMode)
	var serveErr error
	if httpServer.TLSConfig != nil {
		serveErr = httpServer.ListenAndServeTLS("", "")
	} else {
		serveErr = httpServer.ListenAndServe()
	}
	if err := serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func healthcheck() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/health")
	if err != nil {
		os.Exit(1)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func releaseDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type fleetAuditAdapter struct {
	sink    audit.Sink
	metrics *observability.Metrics
}

func (a fleetAuditAdapter) RecordFleet(e fleet.AuditEvent) {
	if a.metrics != nil {
		a.metrics.ObserveFleetEvent(e.Action, e.Outcome)
	}
	if a.sink == nil {
		return
	}
	a.sink.Record(audit.Event{RequestID: "fleet-" + e.Action, Timestamp: time.Now().UTC(), Component: "fleet", Mode: "control-plane", Action: core.ActionReview, Code: boundedDistributionValue(e.Action), Tenant: boundedDistributionValue(e.Tenant), DistributionEvent: boundedDistributionValue(e.Outcome), DistributionKeyID: boundedDistributionValue(e.Digest)})
}
