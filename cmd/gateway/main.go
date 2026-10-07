// Command gateway runs the LLM security gateway HTTP service.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/gateway"
	"github.com/aegisllm/gateway/internal/observability"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/securetransport"
	"github.com/aegisllm/gateway/internal/tokenization"
)

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
	logger := newLogger()
	cfg := gateway.LoadConfig()
	if err := gateway.ValidateConfig(cfg); err != nil {
		logger.Error("configuration validation failed", "error", err)
		os.Exit(1)
	}

	// Invalid policy fails startup (T-010).
	pol, err := policy.LoadFile(cfg.PolicyFile)
	if err != nil {
		logger.Error("policy load failed", "path", cfg.PolicyFile)
		os.Exit(1)
	}

	srv, err := gateway.NewServer(cfg, logger)
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// Versioned question schema (FR-009); invalid schema fails startup.
	questionSchema, err := decision.LoadQuestionsFile(cfg.QuestionsFile)
	if err != nil {
		logger.Error("question schema load failed", "path", cfg.QuestionsFile)
		os.Exit(1)
	}

	metrics := observability.New()
	srv.SetSecureMaterialMetrics(metrics)
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
	sink := audit.NewWriterSink(os.Stdout)
	// Security mode is not stated here: Server.SetPipeline propagates
	// cfg.SecurityMode into the pipeline — the server owns the mode.
	pipe := gateway.NewSecurityPipeline(registry, policy.NewEngine(pol), sink)
	pipe.SetSpanProvider(pii.NewCompositeSpanProvider(pii.NewRegexSpanProvider()))
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
	vaultTTL := 24 * time.Hour
	if v := os.Getenv("TOKEN_VAULT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			vaultTTL = d
		}
	}
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
	if cfg.ThresholdsFile != "" {
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
			CheckpointID: checkpoint, CalibrationTimestamp: calibrationTimestamp}
	})

	pipe.SetRecorder(metrics)
	srv.SetMetricsHandler(metrics.Handler())

	srv.SetPipeline(pipe)
	srv.SetPolicy(pol)
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
