package routing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/core"
)

const testRegistry = `schema: aegisllm.upstreams/v1
version: 1
upstreams:
  - id: local-primary
    class: local
    provider: local
    family: openai
    base_url: http://127.0.0.1:18081
    priority: 1
    weight: 1
    enabled: true
    auth: {mode: none}
    health: {endpoint: /health, interval: 1s, timeout: 100ms}
    breaker: {threshold: 2, open_interval: 1s}
    model_allow: [local/*]
    aliases: {local-chat: local/7b}
    capabilities: {chat: true, responses: true, messages: false, embeddings: false, streaming: true, tools: true}
  - id: cloud-primary
    class: cloud
    provider: cloud
    family: openai
    base_url: http://127.0.0.1:18082
    priority: 2
    weight: 1
    enabled: true
    auth: {mode: none}
    health: {endpoint: /health, interval: 1s, timeout: 100ms}
    breaker: {threshold: 2, open_interval: 1s}
    capabilities: {chat: true, responses: true, messages: false, embeddings: true, streaming: true, tools: true}
fallback_chains:
  - id: local-then-cloud
    routes: [local-primary, cloud-primary]
`

func TestRegistrySelectsLocalAndRewritesAlias(t *testing.T) {
	reg, err := Load([]byte(testRegistry))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(reg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Candidates(Input{Action: core.ActionForceLocalModel, RequestedModel: "local-chat", Family: "openai", Capability: "chat"})
	if err != nil || len(got) != 1 {
		t.Fatalf("selection: %v %#v", err, got)
	}
	if got[0].Route.Class != ClassLocal || got[0].RoutedModel != "local/7b" {
		t.Fatalf("selection=%+v", got[0])
	}
}

func TestRegistryForceLocalNeverUsesCloud(t *testing.T) {
	reg, err := Load([]byte(testRegistry))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := NewManager(reg)
	m.SetHealth("local-primary", false)
	_, err = m.Candidates(Input{Action: core.ActionForceLocalModel, RequestedModel: "local/7b", Family: "openai", Capability: "chat"})
	if err == nil || err.Error() != "ROUTE_LOCAL_UNAVAILABLE" {
		t.Fatalf("err=%v", err)
	}
}

func TestMalformedReloadRetainsLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "registry.yaml")
	if err := os.WriteFile(file, []byte(testRegistry), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := NewManagerFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("schema: broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("malformed reload accepted")
	}
	if len(m.Status()) != 2 {
		t.Fatalf("last known good lost: %#v", m.Status())
	}
}

func TestRegistryRejectsSecretsInBaseURLAndUnknownFields(t *testing.T) {
	for _, input := range []string{
		strings.Replace(testRegistry, "http://127.0.0.1:18081", "http://user:pass@127.0.0.1:18081", 1),
		strings.Replace(testRegistry, "schema: aegisllm.upstreams/v1", "schema: aegisllm.upstreams/v1\nunknown: true", 1),
	} {
		if _, err := Load([]byte(input)); err == nil {
			t.Fatal("invalid registry accepted")
		}
	}
}

func TestCommittedExampleRegistryLoads(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "upstream-registry.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(data); err != nil {
		t.Fatal(err)
	}
}
