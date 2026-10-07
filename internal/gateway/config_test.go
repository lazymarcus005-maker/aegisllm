package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	cfg := configFrom(func(string) string { return "" })
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("listen addr: %s", cfg.ListenAddr)
	}
	if cfg.DeploymentProfile != ProfileDevelopment {
		t.Fatalf("deployment profile: %s", cfg.DeploymentProfile)
	}
	if cfg.MaxBodyBytes != 1<<20 {
		t.Fatalf("max body: %d", cfg.MaxBodyBytes)
	}
	if cfg.SecurityMode != ModeOff {
		t.Fatalf("mode: %s", cfg.SecurityMode)
	}
	if cfg.UpstreamAuthMode != "none" {
		t.Fatalf("auth mode: %s", cfg.UpstreamAuthMode)
	}
	if cfg.DefaultTargetProvider != "cloud" {
		t.Fatalf("default provider: %s", cfg.DefaultTargetProvider)
	}
	if cfg.HeaderApplication != "X-Application-Id" {
		t.Fatalf("app header: %s", cfg.HeaderApplication)
	}
	if cfg.UpstreamChatPathPrefix != "" {
		t.Fatalf("path prefix default: %q", cfg.UpstreamChatPathPrefix)
	}
	if cfg.MaxResponseBytes != 4<<20 || cfg.MaxPromptChars != 64*1024 || cfg.MaxStreamDuration != 5*time.Minute {
		t.Fatalf("content limits defaults: response=%d prompt=%d stream=%s", cfg.MaxResponseBytes, cfg.MaxPromptChars, cfg.MaxStreamDuration)
	}
	if cfg.RequestsPerSecond != 10 || cfg.RateBurst != 20 || cfg.MaxConcurrentRequests != 16 || cfg.MaxConcurrentLaya != 4 {
		t.Fatalf("limiter defaults: rps=%v burst=%d requests=%d laya=%d", cfg.RequestsPerSecond, cfg.RateBurst, cfg.MaxConcurrentRequests, cfg.MaxConcurrentLaya)
	}
}

func TestConfigOverrides(t *testing.T) {
	env := map[string]string{
		"LISTEN_ADDR":               ":9090",
		"MAX_BODY_BYTES":            "2048",
		"SECURITY_MODE":             "enforce",
		"DEPLOYMENT_PROFILE":        "production",
		"DEFAULT_TARGET_PROVIDER":   "local",
		"UPSTREAM_CHAT_PATH_PREFIX": "/generic",
	}
	cfg := configFrom(func(k string) string { return env[k] })
	if cfg.ListenAddr != ":9090" || cfg.MaxBodyBytes != 2048 || cfg.SecurityMode != ModeEnforce {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.DeploymentProfile != ProfileProduction {
		t.Fatalf("profile override: %s", cfg.DeploymentProfile)
	}
	if cfg.DefaultTargetProvider != "local" {
		t.Fatalf("provider override: %s", cfg.DefaultTargetProvider)
	}
	if cfg.UpstreamChatPathPrefix != "/generic" {
		t.Fatalf("path prefix override: %s", cfg.UpstreamChatPathPrefix)
	}
}

func TestProductionValidationRejectsUnsafeRuntimeLimit(t *testing.T) {
	cfg := productionConfig(t)
	cfg.MaxResponseBytes = 0
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "MAX_BODY_BYTES") {
		t.Fatalf("unsafe runtime limit error = %v", err)
	}
}

func TestProductionValidationRejectsUnsafeStreamingWindow(t *testing.T) {
	cfg := productionConfig(t)
	cfg.StreamInspectionWindow = 1024
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "STREAM_INSPECTION_WINDOW") {
		t.Fatalf("unsafe streaming window error = %v", err)
	}
}

func TestProductionValidationRequiresFailClosedStreaming(t *testing.T) {
	cfg := productionConfig(t)
	cfg.StreamingFailClosed = false
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "STREAM_FAIL_CLOSED") {
		t.Fatalf("fail-open streaming config error = %v", err)
	}
}

func TestConfigInvalidIntFallsBackToDefault(t *testing.T) {
	cfg := configFrom(func(k string) string {
		if k == "MAX_BODY_BYTES" {
			return "not-a-number"
		}
		return ""
	})
	if cfg.MaxBodyBytes != 1<<20 {
		t.Fatalf("max body: %d", cfg.MaxBodyBytes)
	}
}

func TestDeploymentProfileParsing(t *testing.T) {
	tests := []struct {
		input string
		want  DeploymentProfile
	}{
		{"", ProfileDevelopment},
		{"development", ProfileDevelopment},
		{"SHADOW", ProfileShadow},
		{"production", ProfileProduction},
	}
	for _, tc := range tests {
		got, err := ParseDeploymentProfile(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("ParseDeploymentProfile(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	if _, err := ParseDeploymentProfile("unsafe"); err == nil {
		t.Fatal("invalid deployment profile accepted")
	}
}

func productionConfig(t *testing.T) Config {
	t.Helper()
	root := filepath.Join("..", "..")
	return Config{
		DeploymentProfile:             ProfileProduction,
		SecurityMode:                  ModeEnforce,
		AuthMode:                      "jwt",
		JWTPublicKeyFile:              "/run/secrets/aegis-jwt-public.pem",
		JWTIssuer:                     "https://issuer.example.invalid",
		JWTAudience:                   "aegisllm",
		UpstreamBaseURL:               "https://llm-gateway.example.invalid",
		UpstreamAuthMode:              "none",
		UpstreamDialTimeout:           5 * time.Second,
		UpstreamTLSHandshakeTimeout:   5 * time.Second,
		UpstreamResponseHeaderTimeout: 30 * time.Second,
		UpstreamRequestTimeout:        2 * time.Minute,
		UpstreamIdleConnTimeout:       90 * time.Second,
		UpstreamMaxIdleConns:          100,
		MaxBodyBytes:                  1 << 20,
		MaxResponseBytes:              4 << 20,
		MaxPromptChars:                64 * 1024,
		MaxStreamDuration:             5 * time.Minute,
		MaxSSEEventBytes:              64 * 1024,
		StreamInspectionWindow:        4096,
		MaxBufferedStreamBytes:        1 << 20,
		StreamFlushInterval:           25 * time.Millisecond,
		StreamingFailClosed:           true,
		RequestsPerSecond:             10,
		RateBurst:                     20,
		MaxConcurrentRequests:         16,
		MaxConcurrentLaya:             4,
		LimiterMaxKeys:                10000,
		LimiterKeyIdleTimeout:         10 * time.Minute,
		UpstreamBreakerThreshold:      3,
		UpstreamBreakerOpenInterval:   30 * time.Second,
		ServerReadHeaderTimeout:       10 * time.Second,
		ServerReadTimeout:             30 * time.Second,
		ServerIdleTimeout:             2 * time.Minute,
		ServerShutdownTimeout:         10 * time.Second,
		PolicyFile:                    filepath.Join(root, "policies", "enterprise-default.yaml"),
		QuestionsFile:                 filepath.Join(root, "questions", "security-v1.yaml"),
		ThresholdsFile:                filepath.Join(root, "policies", "thresholds-security-v1.yaml"),
		TokenVaultKey:                 strings.Repeat("a", 64),
		TokenVaultRedisURL:            "redis://redis.example.invalid:6379/0",
		TelemetryHMACKey:              "synthetic-telemetry-key",
	}
}

func TestProductionConfigValidationSuccess(t *testing.T) {
	if err := ValidateConfig(productionConfig(t)); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
}

func TestProductionConfigValidationFailures(t *testing.T) {
	base := productionConfig(t)
	badFile := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tests := []struct {
		name   string
		mutate func(*Config, *testing.T)
		want   string
	}{
		{"security mode", func(c *Config, _ *testing.T) { c.SecurityMode = ModeShadow }, "SECURITY_MODE"},
		{"missing vault key", func(c *Config, _ *testing.T) { c.TokenVaultKey = "" }, "TOKEN_VAULT_KEY"},
		{"invalid vault key", func(c *Config, _ *testing.T) { c.TokenVaultKey = "not-hex" }, "TOKEN_VAULT_KEY"},
		{"missing redis", func(c *Config, _ *testing.T) { c.TokenVaultRedisURL = "" }, "TOKEN_VAULT_REDIS_URL"},
		{"invalid redis", func(c *Config, _ *testing.T) { c.TokenVaultRedisURL = "redis" }, "TOKEN_VAULT_REDIS_URL"},
		{"missing telemetry key", func(c *Config, _ *testing.T) { c.TelemetryHMACKey = " " }, "TELEMETRY_HMAC_KEY"},
		{"missing upstream", func(c *Config, _ *testing.T) { c.UpstreamBaseURL = "" }, "UPSTREAM_BASE_URL"},
		{"mock upstream", func(c *Config, _ *testing.T) { c.UpstreamBaseURL = "http://mock-upstream:9090" }, "mock upstream"},
		{"missing policy", func(c *Config, _ *testing.T) { c.PolicyFile = filepath.Join("/tmp", "missing-policy.yaml") }, "POLICY_FILE"},
		{"invalid policy", func(c *Config, t *testing.T) { c.PolicyFile = badFile(t, "not: a policy") }, "POLICY_FILE"},
		{"missing questions", func(c *Config, _ *testing.T) { c.QuestionsFile = filepath.Join("/tmp", "missing-questions.yaml") }, "QUESTIONS_FILE"},
		{"invalid questions", func(c *Config, t *testing.T) { c.QuestionsFile = badFile(t, "schema: broken") }, "QUESTIONS_FILE"},
		{"missing thresholds", func(c *Config, _ *testing.T) { c.ThresholdsFile = filepath.Join("/tmp", "missing-thresholds.yaml") }, "THRESHOLDS_FILE"},
		{"invalid thresholds", func(c *Config, t *testing.T) { c.ThresholdsFile = badFile(t, "id: broken") }, "THRESHOLDS_FILE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg, t)
			err := ValidateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateConfig error = %v; want text %q", err, tc.want)
			}
		})
	}
}

func TestShadowProfileRequiresShadowMode(t *testing.T) {
	cfg := Config{DeploymentProfile: ProfileShadow, SecurityMode: ModeEnforce}
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "SECURITY_MODE=shadow") {
		t.Fatalf("shadow profile validation error = %v", err)
	}
}
