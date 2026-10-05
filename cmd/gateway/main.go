// Command gateway runs the LLM security gateway HTTP service.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/gateway"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
)

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
