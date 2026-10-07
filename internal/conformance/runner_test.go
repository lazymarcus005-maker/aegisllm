package conformance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeSSEStableAcrossIDsAndChunkBoundaries(t *testing.T) {
	one := "data: {\"id\":\"random-a\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: {\"id\":\"random-a\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
	two := "data: {\"id\":\"random-b\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: {\"id\":\"random-b\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
	a, err := NormalizeSSE([]byte(one), "openai-chat")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NormalizeSSE([]byte(two), "openai-chat")
	if err != nil {
		t.Fatal(err)
	}
	if a != b || !a.Done || a.Finish != "stop" {
		t.Fatalf("normalized shapes differ: %#v %#v", a, b)
	}
}

func TestRunReportNeverContainsResponseBody(t *testing.T) {
	secret := "glpat-super-secret-corpus-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"volatile","object":"chat.completion","model":"m","choices":[{"message":{"role":"assistant","content":"` + secret + `"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	spec := DefaultSpecification()
	filter := map[string]bool{"openai-chat": true}
	r, err := Run(context.Background(), spec, RunnerOptions{Target: server.URL}, filter)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MarshalDeterministic(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatal("secret was included in report")
	}
}

func TestReasonIDsBounded(t *testing.T) {
	if got := reasonForError(context.DeadlineExceeded); got != "timeout" {
		t.Fatal(got)
	}
	if !allowedReasonIDs["malformed_sse"] {
		t.Fatal("missing reason id")
	}
}

func TestAuthDescriptorUsesOnlyFileAndEnvironmentReferences(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "credential")
	if err := os.WriteFile(secretPath, []byte("test-only-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	descriptor := filepath.Join(dir, "auth.json")
	data := []byte(`{"schema_version":"aegisllm.conformance.auth/v1","headers":[{"name":"X-Test","value_file":"` + secretPath + `"}]}`)
	if err := os.WriteFile(descriptor, data, 0600); err != nil {
		t.Fatal(err)
	}
	h, err := LoadAuth(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Test") != "test-only-secret" {
		t.Fatalf("descriptor did not load mounted value")
	}
	if _, err := LoadAuth(writeAuthDescriptor(t, `{"schema_version":"aegisllm.conformance.auth/v1","headers":[{"name":"X-Test","value":"inline-secret"}]}`)); err == nil {
		t.Fatal("inline credential was accepted")
	}
}

func writeAuthDescriptor(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
