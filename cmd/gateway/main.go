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
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/gateway"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/tokenization"
)

// loadVaultKey returns the 32-byte token-vault master key: hex-encoded via
// TOKEN_VAULT_KEY, or an ephemeral random key in development.
func loadVaultKey(logger *slog.Logger) ([]byte, error) {
	if hexKey := os.Getenv("TOKEN_VAULT_KEY"); hexKey != "" {
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

	// Invalid policy fails startup (T-010).
	policyPath := os.Getenv("POLICY_FILE")
	if policyPath == "" {
		policyPath = "policies/enterprise-default.yaml"
	}
	pol, err := policy.LoadFile(policyPath)
	if err != nil {
		logger.Error("policy load failed", "path", policyPath, "error", err)
		os.Exit(1)
	}

	srv, err := gateway.NewServer(cfg, logger)
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	registry := detectors.NewRegistry(nil)
	for _, d := range detectors.SecretDetectors(os.Getenv("TELEMETRY_HMAC_KEY")) {
		registry.Register(d)
	}
	for _, d := range detectors.PiiDetectors(os.Getenv("TELEMETRY_HMAC_KEY")) {
		registry.Register(d)
	}
	sink := audit.NewWriterSink(os.Stdout)
	pipe := gateway.NewSecurityPipeline(registry, policy.NewEngine(pol), sink, cfg.SecurityMode)
	pipe.SetSpanProvider(pii.NewCompositeSpanProvider(pii.NewRegexSpanProvider()))

	// Token vault (ticket 06): envelope-encrypted mappings with TTL.
	masterKey, err := loadVaultKey(logger)
	if err != nil {
		logger.Error("token vault key invalid", "error", err)
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
	if redisURL := os.Getenv("TOKEN_VAULT_REDIS_URL"); redisURL != "" {
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			logger.Error("invalid TOKEN_VAULT_REDIS_URL", "error", err)
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

	srv.SetPipeline(pipe)
	srv.AddReadinessCheck("policy_loaded", func() string { return "" })

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
		"upstream", cfg.UpstreamBaseURL,
		"mode", cfg.SecurityMode)
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
