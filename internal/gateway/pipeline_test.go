package gateway

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/policy"
)

// newRealPipeline builds the production pipeline over a buffer audit sink.
func newRealPipeline(t *testing.T, mode string) (*SecurityPipeline, *bytesBufferSink) {
	t.Helper()
	pol, err := policy.LoadFile("../../policies/enterprise-default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	registry := detectors.NewRegistry(nil)
	for _, d := range detectors.SecretDetectors("test-telemetry-key") {
		registry.Register(d)
	}
	sink := &bytesBufferSink{}
	return NewSecurityPipeline(registry, policy.NewEngine(pol), sink, mode), sink
}

type bytesBufferSink struct {
	buf strings.Builder
}

func (s *bytesBufferSink) Record(e audit.Event) {
	b, _ := json.Marshal(e)
	s.buf.Write(b)
	s.buf.WriteString("\n")
}

func (s *bytesBufferSink) String() string { return s.buf.String() }

const secretRequest = `{"model":"m","messages":[{"role":"user","content":"Use this GitLab token: glpat-Abc123Xyz_-456DefGhi"}]}`

// AS-001: a known secret is blocked before the upstream, deterministically,
// with zero upstream calls, and the raw secret never reaches the audit log.
func TestAS001SecretBlockedInEnforceMode(t *testing.T) {
	srv, gw, up := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream must not be called when a known secret is blocked")
	})
	up.Close() // ensure any upstream call would fail loudly
	pipe, sink := newRealPipeline(t, ModeEnforce)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(secretRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var out struct {
		Error struct {
			Type      string `json:"type"`
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error.Type != "security_policy_violation" || out.Error.Code != "SECRET_DETECTED" {
		t.Fatalf("error contract: %+v", out.Error)
	}
	if out.Error.RequestID == "" {
		t.Fatal("request_id required in policy rejection")
	}

	auditOut := sink.String()
	if strings.Contains(auditOut, "glpat-Abc123Xyz") {
		t.Fatal("raw secret leaked into audit output")
	}
	if !strings.Contains(auditOut, `"finding_types":["GITLAB_PAT"]`) {
		t.Fatalf("audit missing finding types: %s", auditOut)
	}
	if !strings.Contains(auditOut, `"mode":"enforce"`) || !strings.Contains(auditOut, `"action":"BLOCK"`) {
		t.Fatalf("audit missing mode/action: %s", auditOut)
	}
	if !strings.Contains(auditOut, `"policy_version":2`) {
		t.Fatalf("audit missing policy version: %s", auditOut)
	}
}

// AS-006: in shadow mode the request still follows the incumbent path while
// the predicted BLOCK is audited with mode=shadow.
func TestAS006ShadowPredictsBlockWithoutBlocking(t *testing.T) {
	upCalled := false
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeShadow }, func(w http.ResponseWriter, _ *http.Request) {
		upCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	pipe, sink := newRealPipeline(t, ModeShadow)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(secretRequest))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if !upCalled || resp.StatusCode != http.StatusOK {
		t.Fatalf("shadow must not modify production behavior: called=%v status=%d", upCalled, resp.StatusCode)
	}
	auditOut := sink.String()
	if !strings.Contains(auditOut, `"mode":"shadow"`) || !strings.Contains(auditOut, `"action":"BLOCK"`) {
		t.Fatalf("shadow audit must record predicted action: %s", auditOut)
	}
	if strings.Contains(auditOut, "glpat-Abc123Xyz") {
		t.Fatal("raw secret leaked into shadow audit output")
	}
}

// Off mode: no inspection, no audit, pure pass-through.
func TestOffModeSkipsInspection(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeOff }, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	pipe, sink := newRealPipeline(t, ModeOff)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(secretRequest))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if sink.String() != "" {
		t.Fatalf("off mode must not audit: %s", sink.String())
	}
}

// Clean requests pass through with an ALLOW audit event.
func TestCleanRequestAllowedAndAudited(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	pipe, sink := newRealPipeline(t, ModeEnforce)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"what is the weather today?"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(sink.String(), `"action":"ALLOW"`) {
		t.Fatalf("expected ALLOW audit: %s", sink.String())
	}
}

// No raw secret may appear anywhere in the process log output either.
func TestGatewayLogsCarryNoSecret(t *testing.T) {
	var logBuf strings.Builder
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer up.Close()
	cfg := Config{
		ListenAddr: ":0", UpstreamBaseURL: up.URL, UpstreamAuthMode: "none",
		MaxBodyBytes: 1 << 20, SecurityMode: ModeEnforce, DefaultTargetProvider: "cloud",
	}
	srv, err := NewServer(cfg, slog.New(slog.NewTextHandler(&logBuf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	pipe, _ := newRealPipeline(t, ModeEnforce)
	srv.SetPipeline(pipe)
	gw := httptest.NewServer(srv.Handler())
	defer gw.Close()

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(secretRequest))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if strings.Contains(logBuf.String(), "glpat-Abc123Xyz") {
		t.Fatal("raw secret leaked into server logs")
	}
}
