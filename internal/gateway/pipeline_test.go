package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/tokenization"
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
	for _, d := range detectors.PiiDetectors("test-telemetry-key") {
		registry.Register(d)
	}
	sink := &bytesBufferSink{}
	pipe := NewSecurityPipeline(registry, policy.NewEngine(pol), sink, mode)
	pipe.SetSpanProvider(pii.NewCompositeSpanProvider(pii.NewRegexSpanProvider()))
	return pipe, sink
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
	if !regexp.MustCompile(`"policy_version":[0-9]+`).MatchString(auditOut) {
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

// Thai request containing a checksum-valid synthetic citizen ID, a phone, and
// an honorific name, headed for a cloud target.
const thaiPIIRequest = `{"model":"m","messages":[{"role":"user","content":"ลูกค้าชื่อ นายสมชาย ใจดี โทร 0812345678 เลขบัตร 1234567890121 ค่ะ"}]}`

// AS-002 (ticket 06): cloud-bound Thai PII arrives upstream as placeholders;
// audit records finding types without raw values.
func TestAS002ThaiPIIRedactedForCloud(t *testing.T) {
	var upstreamBody string
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	pipe, sink := newRealPipeline(t, ModeEnforce)
	attachVault(t, pipe)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(thaiPIIRequest))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	for _, raw := range []string{"0812345678", "1234567890121", "สมชาย"} {
		if strings.Contains(upstreamBody, raw) {
			t.Fatalf("raw PII %q reached the upstream: %s", raw, upstreamBody)
		}
	}
	var sent struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal([]byte(upstreamBody), &sent)
	for _, want := range []string{"<PERSON_001>", "<PHONE_NUMBER_001>", "<TH_CITIZEN_ID_001>"} {
		if !strings.Contains(sent.Messages[0].Content, want) {
			t.Fatalf("expected %s in upstream content: %s", want, sent.Messages[0].Content)
		}
	}

	auditOut := sink.String()
	if !strings.Contains(auditOut, `"action":"TOKENIZE"`) {
		t.Fatalf("expected TOKENIZE audit: %s", auditOut)
	}
	for _, leak := range []string{"0812345678", "1234567890121", "สมชาย"} {
		if strings.Contains(auditOut, leak) {
			t.Fatalf("raw PII %q leaked into audit", leak)
		}
	}
}

// UC-003: governed PII to a local model is allowed without transformation.
func TestUC003LocalModelAllowsPII(t *testing.T) {
	var upstreamBody string
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamBody = string(b)
		w.WriteHeader(http.StatusOK)
	})
	pipe, sink := newRealPipeline(t, ModeEnforce)
	srv.SetPipeline(pipe)

	req, _ := http.NewRequest("POST", gw.URL+"/v1/chat/completions", strings.NewReader(thaiPIIRequest))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Target-Provider", "local")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(upstreamBody, "0812345678") {
		t.Fatalf("local model policy must allow PII through: %s", upstreamBody)
	}
	if !strings.Contains(sink.String(), `"action":"ALLOW"`) || !strings.Contains(sink.String(), "TH_CITIZEN_ID") {
		t.Fatalf("audit must record allowed finding types: %s", sink.String())
	}
}

// AS-002 (ticket 06): cloud-bound Thai PII arrives upstream as stable
// placeholders, with mappings sealed in the vault; same value → same token.
func TestAS002ThaiPIITokenizedForCloud(t *testing.T) {
	var upstreamBody string
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamBody = string(b)
		w.WriteHeader(http.StatusOK)
	})
	pipe, sink := newRealPipeline(t, ModeEnforce)
	attachVault(t, pipe)
	srv.SetPipeline(pipe)

	// Same phone number appears twice: value-stable tokens must reuse 001.
	body := `{"model":"m","messages":[{"role":"user","content":"โทร 0812345678 หรือ 0812345678 ค่ะ เลขบัตร 1234567890121"}]}`
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	if strings.Contains(upstreamBody, "0812345678") || strings.Contains(upstreamBody, "1234567890121") {
		t.Fatalf("raw PII reached upstream: %s", upstreamBody)
	}
	var sent struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal([]byte(upstreamBody), &sent)
	sentContent := sent.Messages[0].Content
	if strings.Count(sentContent, "<PHONE_NUMBER_001>") != 2 {
		t.Fatalf("same value must share one token: %s", sentContent)
	}
	if !strings.Contains(sentContent, "<TH_CITIZEN_ID_001>") {
		t.Fatalf("citizen ID token missing: %s", sentContent)
	}
	if strings.Contains(sink.String(), "0812345678") || strings.Contains(sink.String(), "1234567890121") {
		t.Fatal("raw PII leaked into audit")
	}
}

// attachVault wires an in-memory vault with a fixed dev key into the pipeline.
func attachVault(t *testing.T, pipe *SecurityPipeline) tokenization.Vault {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	crypto, err := tokenization.NewCrypto(key)
	if err != nil {
		t.Fatal(err)
	}
	vault := tokenization.NewInMemoryVault()
	pipe.SetTokenStore(vault, crypto, time.Hour)
	return vault
}

// Re-identification round trip through the full gateway path: the vault
// record created during tokenization resolves for the issuing application
// and is denied for others (T-023).
func TestTokenizeReidentifyRoundTrip(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	pipe, sink := newRealPipeline(t, ModeEnforce)
	vault := attachVault(t, pipe)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"โทร 0812345678"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Find the request ID from the audit sink (sink records request_id), then
	// resolve the placeholder through the controlled interface.
	auditOut := sink.String()
	requestID := requestIDFromAudit(t, auditOut)
	reid := tokenization.NewReidentifier(vault, pipe.crypto)

	got, err := reid.Reidentify(context.Background(), requestID, "PHONE_NUMBER_001",
		tokenization.Caller{Application: "unknown"})
	if err != nil || got != "0812345678" {
		t.Fatalf("re-identify: %q %v", got, err)
	}
	if _, err := reid.Reidentify(context.Background(), requestID, "PHONE_NUMBER_001",
		tokenization.Caller{Application: "other-app"}); !errors.Is(err, tokenization.ErrUnauthorized) {
		t.Fatalf("cross-application access must be denied: %v", err)
	}
}

// requestIDFromAudit pulls the most recent request_id from newline-joined
// audit JSON (test helper).
func requestIDFromAudit(t *testing.T, auditOut string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(auditOut), "\n")
	if len(lines) == 0 {
		t.Fatal("no audit events")
	}
	var ev struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.RequestID == "" {
		t.Fatal("audit missing request_id")
	}
	return ev.RequestID
}

// --- ticket 07: outbound protection + re-identification ---

// AS-005: a secret the model emits never reaches the client under block
// policy; the outbound audit event records the predicted BLOCK.
func TestAS005OutboundSecretBlocked(t *testing.T) {
	respBody := `{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"here is your key: glpat-Abc123Xyz_-456DefGhi"},"finish_reason":"stop"}]}`
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	})
	pipe, sink := newRealPipeline(t, ModeEnforce)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(b), "glpat-Abc123Xyz") {
		t.Fatal("raw secret reached the client")
	}
	if !strings.Contains(string(b), "security_policy_violation") {
		t.Fatalf("expected policy error contract: %s", b)
	}
	if !strings.Contains(sink.String(), `"direction":"RESPONSE"`) || !strings.Contains(sink.String(), `"action":"BLOCK"`) {
		t.Fatalf("outbound audit event missing: %s", sink.String())
	}
}

// UC-008: model-emitted PII is redacted before the client sees it.
func TestOutboundPIIRedacted(t *testing.T) {
	respBody := `{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"call the customer at 0812345678"},"finish_reason":"stop"}]}`
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	})
	pipe, _ := newRealPipeline(t, ModeEnforce)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	var got struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v (body: %s)", err, b)
	}
	if len(got.Choices) == 0 {
		t.Fatalf("no choices in body: %s", b)
	}
	content := got.Choices[0].Message.Content
	if strings.Contains(content, "0812345678") {
		t.Fatalf("raw PII reached the client: %s", content)
	}
	if !strings.Contains(content, "[REDACTED:PHONE_NUMBER]") {
		t.Fatalf("redaction missing: %s", content)
	}
}

// Re-identification round trip: request tokenizes the phone, the model echoes
// the placeholder, and the authorized caller receives the original value.
func TestOutboundReidentifiesEchoedToken(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"[mock-upstream echo] โทร <PHONE_NUMBER_001> ค่ะ"},"finish_reason":"stop"}]}`))
	})
	pipe, _ := newRealPipeline(t, ModeEnforce)
	attachVault(t, pipe)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"โทร 0812345678 ค่ะ"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	b, _ := io.ReadAll(resp.Body)
	var got struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	_ = json.Unmarshal(b, &got)
	content := got.Choices[0].Message.Content
	if strings.Contains(content, "PHONE_NUMBER_001") {
		t.Fatalf("placeholder was not re-identified: %s", content)
	}
	if !strings.Contains(content, "0812345678") {
		t.Fatalf("original value missing for authorized caller: %s", content)
	}
}

// Model-invented placeholders (never issued in this namespace) must pass
// through untouched — no blind replacement (T-023).
func TestOutboundLeavesInventedPlaceholdersAlone(t *testing.T) {
	respBody := `{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"the model claims <PERSON_999> and <TH_CITIZEN_ID_123> exist"},"finish_reason":"stop"}]}`
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	})
	pipe, _ := newRealPipeline(t, ModeEnforce)
	attachVault(t, pipe)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	var got struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	_ = json.Unmarshal(b, &got)
	content := got.Choices[0].Message.Content
	for _, want := range []string{"<PERSON_999>", "<TH_CITIZEN_ID_123>"} {
		if !strings.Contains(content, want) {
			t.Fatalf("invented placeholder %s was mutated: %s", want, content)
		}
	}
}

// Shadow mode: an outbound secret is predicted BLOCK in audit, but the client
// still receives the incumbent response unchanged.
func TestShadowOutboundPassesThroughWithPrediction(t *testing.T) {
	respBody := `{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"key: glpat-Abc123Xyz_-456DefGhi"},"finish_reason":"stop"}]}`
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeShadow }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	})
	pipe, sink := newRealPipeline(t, ModeShadow)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "glpat-Abc123Xyz") {
		t.Fatal("shadow mode must not modify the incumbent response")
	}
	if !strings.Contains(sink.String(), `"direction":"RESPONSE"`) || !strings.Contains(sink.String(), `"action":"BLOCK"`) {
		t.Fatalf("shadow must audit the predicted outbound block: %s", sink.String())
	}
}

// Streaming requests are forwarded without outbound scanning for now, per the
// staged plan (architecture §13).
func TestStreamingRequestsBypassOutboundScan(t *testing.T) {
	respBody := `{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"key: glpat-Abc123Xyz_-456DefGhi"},"finish_reason":"stop"}]}`
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(respBody))
	})
	pipe, sink := newRealPipeline(t, ModeEnforce)
	srv.SetPipeline(pipe)

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "glpat-Abc123Xyz") {
		t.Fatal("streaming must pass through verbatim in this stage")
	}
	if strings.Contains(sink.String(), `"direction":"RESPONSE"`) {
		t.Fatal("streaming must not be scanned in this stage")
	}
}
