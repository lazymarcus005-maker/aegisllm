package pii

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validRegistryURL(url string) []byte {
	return []byte("schema: aegisllm.pii-ner/v1\nversion: 1\nproviders:\n- id: local\n  type: aegis_ner_http\n  url: " + url + "\n  languages: [th, en, mixed]\n  entity_mappings: {PERSON: PERSON}\n  min_confidence: {PERSON: 0.7}\n  priority: 1\n  timeout: 1s\n  max_chars: 100\n  chunk_overlap: 10\n  max_concurrent: 2\n  breaker_threshold: 2\n  breaker_open_interval: 1s\n  fail_behavior: strict\n")
}

func TestRegistryProductionTransportValidation(t *testing.T) {
	if _, err := LoadRegistryForProfile(validRegistryURL("http://ner.internal:8400"), "production"); err == nil {
		t.Fatal("production must reject plaintext NER URL")
	}
	if _, err := LoadRegistryForProfile(validRegistryURL("https://public.example.com"), "production"); err == nil {
		t.Fatal("production must reject public NER host")
	}
	if _, err := LoadRegistryForProfile(validRegistryURL("https://ner.internal:8443"), "production"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistry(validRegistryURL("http://ner.internal:8400\n  unknown: bad")); err == nil {
		t.Fatal("unknown registry fields must fail")
	}
}

func TestRegistryManagerRetainsLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.yaml")
	if err := os.WriteFile(path, validRegistryURL("http://ner.internal:8400"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := NewRegistryManager(path, "development")
	if err != nil {
		t.Fatal(err)
	}
	if m.Provider() == nil {
		t.Fatal("provider missing")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(validRegistryURL("http://ner.internal:8400")), "schema: aegisllm.pii-ner/v1", "schema: bad", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("invalid replacement must fail")
	}
	if m.Provider() == nil || m.LastFailure() == "" {
		t.Fatal("last-known-good snapshot was not retained")
	}
	m.Close()
}
