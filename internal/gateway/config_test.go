package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		DeploymentProfile:  ProfileProduction,
		SecurityMode:       ModeEnforce,
		UpstreamBaseURL:    "https://llm-gateway.example.invalid",
		UpstreamAuthMode:   "none",
		PolicyFile:         filepath.Join(root, "policies", "enterprise-default.yaml"),
		QuestionsFile:      filepath.Join(root, "questions", "security-v1.yaml"),
		ThresholdsFile:     filepath.Join(root, "policies", "thresholds-security-v1.yaml"),
		TokenVaultKey:      strings.Repeat("a", 64),
		TokenVaultRedisURL: "redis://redis.example.invalid:6379/0",
		TelemetryHMACKey:   "synthetic-telemetry-key",
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
