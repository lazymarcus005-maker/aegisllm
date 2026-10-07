// Command gateway runs the LLM security gateway HTTP service.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
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

	registry := detectors.NewRegistry(nil)
	for _, d := range detectors.SecretDetectors(cfg.TelemetryHMACKey) {
		registry.Register(d)
	}
	for _, d := range detectors.PiiDetectors(cfg.TelemetryHMACKey) {
		registry.Register(d)
	}
	sink := audit.NewWriterSink(os.Stdout)
	// Security mode is not stated here: Server.SetPipeline propagates
	// cfg.SecurityMode into the pipeline — the server owns the mode.
	pipe := gateway.NewSecurityPipeline(registry, policy.NewEngine(pol), sink)
	pipe.SetSpanProvider(pii.NewCompositeSpanProvider(pii.NewRegexSpanProvider()))

	// Token vault (ticket 06): envelope-encrypted mappings with TTL.
	masterKey, err := loadVaultKey(cfg.TokenVaultKey, logger)
	if err != nil {
		logger.Error("token vault key invalid")
		os.Exit(1)
	}
	crypto, err := tokenization.NewCrypto(masterKey)
	if err != nil {
		logger.Error("token vault crypto invalid", "error", err)
		os.Exit(1)
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
	pipe.SetTokenStore(vault, crypto, vaultTTL)

	// Semantic decision provider (ticket 08): local laya-serve when
	// configured, otherwise a noop provider and no semantic calls.
	if layaURL := os.Getenv("LAYA_URL"); layaURL != "" {
		timeout := 5 * time.Second
		if v := os.Getenv("LAYA_TIMEOUT"); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > 0 {
				timeout = d
			}
		}
		laya := decision.NewLayaProvider(layaURL, os.Getenv("LAYA_EVALUATE_PATH"), timeout)
		breaker := decision.NewCircuitBreaker(3, 30*time.Second)
		provider := decision.NewResilientProvider(laya, breaker)
		pipe.SetDecisionProvider(provider, questionSchema)
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
	if os.Getenv("SECURITY_SEMANTIC_ENFORCE") == "true" {
		// Rollout stage 3 (ticket 11): only enable together with calibration.
		pipe.EnableSemanticEnforce()
	}
	// Threshold policy (ticket 11): required for semantic enforcement;
	// invalid threshold policy fails startup.
	if _, err := os.Stat(cfg.ThresholdsFile); err == nil {
		thresholds, err := policy.LoadSemanticThresholdsFile(cfg.ThresholdsFile)
		if err != nil {
			logger.Error("threshold policy load failed", "path", cfg.ThresholdsFile)
			os.Exit(1)
		}
		pipe.SetSemanticThresholds(thresholds)
	}

	metrics := observability.New()
	pipe.SetRecorder(metrics)
	srv.SetMetricsHandler(metrics.Handler())

	srv.SetPipeline(pipe)
	srv.AddReadinessCheck("policy_loaded", func() string { return "" })
	srv.AddReadinessCheck("questions_loaded", func() string { return "" })
	if cfg.TokenVaultRedisURL == "" {
		srv.AddReadinessCheck("token_store", func() string { return "" })
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	logger.Info("security gateway listening",
		"addr", cfg.ListenAddr,
		"deployment_profile", cfg.DeploymentProfile,
		"security_mode", cfg.SecurityMode)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
