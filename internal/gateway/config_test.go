package gateway

import (
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	cfg := configFrom(func(string) string { return "" })
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("listen addr: %s", cfg.ListenAddr)
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
}

func TestConfigOverrides(t *testing.T) {
	env := map[string]string{
		"LISTEN_ADDR":             ":9090",
		"MAX_BODY_BYTES":          "2048",
		"SECURITY_MODE":           "enforce",
		"DEFAULT_TARGET_PROVIDER": "local",
	}
	cfg := configFrom(func(k string) string { return env[k] })
	if cfg.ListenAddr != ":9090" || cfg.MaxBodyBytes != 2048 || cfg.SecurityMode != ModeEnforce {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.DefaultTargetProvider != "local" {
		t.Fatalf("provider override: %s", cfg.DefaultTargetProvider)
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
