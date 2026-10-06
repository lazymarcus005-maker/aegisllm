// Package security holds the adversarial test corpus (handoff §12): evasion
// attempts, nesting attacks, resource abuse, and failure-mode behavior.
package security

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/gateway"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/tokenization"
)

func newGateway(t *testing.T, mode string, provider decision.DecisionProvider) (*httptest.Server, *captureSink, *gateway.SecurityPipeline) {
	t.Helper()
	pol, err := policy.LoadFile("../../policies/enterprise-default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	registry := detectors.NewRegistry(nil)
	for _, d := range detectors.SecretDetectors("test-key") {
		registry.Register(d)
	}
	for _, d := range detectors.PiiDetectors("test-key") {
		registry.Register(d)
	}
	sink := &captureSink{}
	pipe := gateway.NewSecurityPipeline(registry, policy.NewEngine(pol), sink, mode)
	pipe.SetSpanProvider(pii.NewCompositeSpanProvider(pii.NewRegexSpanProvider()))
	key := make([]byte, 32)
	crypto, err := tokenization.NewCrypto(key)
	if err != nil {
		t.Fatal(err)
	}
	pipe.SetTokenStore(tokenization.NewInMemoryVault(), crypto, time.Hour)
	if provider != nil {
		pipe.SetDecisionProvider(provider, mustQuestions(t))
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	t.Cleanup(upstream.Close)
	srv, err := gateway.NewServer(gateway.Config{
		ListenAddr: ":0", UpstreamBaseURL: upstream.URL, UpstreamAuthMode: "none",
		MaxBodyBytes: 1 << 20, SecurityMode: mode, DefaultTargetProvider: "cloud",
		HeaderApplication: "X-Application-Id", HeaderTenant: "X-Tenant-Id",
		HeaderUser: "X-User-Id", HeaderTargetProvider: "X-Target-Provider",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetPipeline(pipe)
	gw := httptest.NewServer(srv.Handler())
	t.Cleanup(gw.Close)
	return gw, sink, pipe
}

func mustQuestions(t *testing.T) *decision.QuestionSchema {
	t.Helper()
	qs, err := decision.LoadQuestionsFile("../../questions/security-v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return qs
}

type captureSink struct{ buf strings.Builder }

func (s *captureSink) Record(e audit.Event) {
	b, _ := json.Marshal(e)
	s.buf.Write(b)
	s.buf.WriteString("\n")
}

func post(t *testing.T, url, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(url+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Secrets smuggled inside nested JSON and tool-argument structures are still
// scanned (the parser flattens content for inspection) and hard-masked: the
// request proceeds but the audit records the REDACT with the finding.
func TestNestedSecretInToolArgumentsMasked(t *testing.T) {
	gw, sink, _ := newGateway(t, gateway.ModeEnforce, nil)
	body := `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"1","type":"function","function":{"name":"file_write","arguments":"{\"path\":\"/tmp/x\",\"content\":\"cat ~/.gitlab-token glpat-0123456789abcdefghij\"}"}}]}]}`
	status, out := post(t, gw.URL, body)
	if status != http.StatusOK {
		t.Fatalf("masked request must proceed: %d %s", status, out)
	}
	auditOut := sink.buf.String()
	if !strings.Contains(auditOut, `"action":"REDACT"`) || !strings.Contains(auditOut, "GITLAB_PAT") {
		t.Fatalf("nested secret not audited as masked: %s", auditOut)
	}
	if strings.Contains(auditOut, "glpat-0123456789abcdefghij") {
		t.Fatal("raw secret leaked into audit output")
	}
}

// Case variations of the bearer keyword are covered by the case-insensitive
// rule; token casing itself is significant and must not be normalized. Under
// the redact policy every variant is hard-masked and the request proceeds.
func TestBearerCaseVariationsMasked(t *testing.T) {
	gw, sink, _ := newGateway(t, gateway.ModeEnforce, nil)
	for _, variant := range []string{"Bearer", "bearer", "BEARER"} {
		body := `{"model":"m","messages":[{"role":"user","content":"` + variant + ` abcdefghijklmnop123456789"}]}`
		status, out := post(t, gw.URL, body)
		if status != http.StatusOK {
			t.Fatalf("%s variant must be masked, not rejected: %d %s", variant, status, out)
		}
		auditOut := sink.buf.String()
		if !strings.Contains(auditOut, `"action":"REDACT"`) || !strings.Contains(auditOut, "BEARER_TOKEN") {
			t.Fatalf("%s variant not audited as masked: %s", variant, auditOut)
		}
		sink.buf.Reset()
	}
}

// Known limitations, pinned as tests so that any future detection change is
// a conscious decision:
//   - base64-encoded secrets are not detected by the MVP pattern set
//   - Unicode homoglyph substitution defeats literal pattern matching
//   - secrets split across separate messages are not correlated (rolling
//     window scanning is the documented V0.2 streaming work, §13)
func TestKnownEvasionLimitations(t *testing.T) {
	gw, _, _ := newGateway(t, gateway.ModeEnforce, nil)
	cases := []string{
		"bm90LWFuLWFjdHVhbC10b2tlbi1idXQtYS1iYXNlNjQtcGF5bG9hZA==",
		"my token is ｇｌｐａｔ－０１２３４５６７８９ａｂｃｄｅｆｇｈｉｊ",
	}
	for _, payload := range cases {
		body := `{"model":"m","messages":[{"role":"user","content":"` + payload + `"}]}`
		status, _ := post(t, gw.URL, body)
		if status != http.StatusOK {
			t.Errorf("evasion case unexpectedly detected (update the limitation note): %d", status)
		}
	}
}

// Oversized payloads are rejected before inspection (SEC-012).
func TestOversizedPayloadRejected(t *testing.T) {
	gw, _, _ := newGateway(t, gateway.ModeEnforce, nil)
	big := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("x", 2<<20) + `"}]}`
	status, _ := post(t, gw.URL, big)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized payload status: %d", status)
	}
}

// Policy corruption fails startup, never enforces a default-allow posture.
func TestPolicyCorruptionFailsClosed(t *testing.T) {
	for _, doc := range []string{"id: [broken", "version: 1", ""} {
		if _, err := policy.Load([]byte(doc)); err == nil {
			t.Fatalf("corrupt policy must fail load: %q", doc)
		}
	}
}

// AS-004 through the public pipeline API: with a dead semantic provider on a
// high-risk route, the policy fallback fails closed (INV-008).
func TestLayaOutageFailsClosedViaPipeline(t *testing.T) {
	_, sink, pipe := newGateway(t, gateway.ModeEnforce, failingProvider{})
	pipe.EnableSemanticEnforce()
	thresholds, err := policy.LoadSemanticThresholds([]byte(`
id: t
version: 1
question_schema: security-v1
thresholds:
  - question: prompt_injection
    language: en
    min_confidence: 0.80
    evaluated: true
`))
	if err != nil {
		t.Fatal(err)
	}
	pipe.SetSemanticThresholds(thresholds)

	env := &core.InspectionEnvelope{
		RequestID:   "req-outage",
		Direction:   core.DirectionRequest,
		Application: "app",
		Target:      core.Target{Provider: "cloud"},
		Messages: []core.Message{{
			Role:  core.RoleUser,
			Parts: []core.ContentPart{{Type: core.PartText, Text: "hello there friend"}},
		}},
	}
	dec, err := pipe.ProcessRequest(env, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != core.ActionBlock || dec.Code != "LAYA_UNAVAILABLE" {
		t.Fatalf("outage must fail closed on a high-risk route: %+v", dec)
	}
	if !strings.Contains(sink.buf.String(), `"error":"unavailable"`) {
		t.Fatalf("outage not audited: %s", sink.buf.String())
	}
}

type failingProvider struct{}

func (failingProvider) Name() string { return "failing" }

func (failingProvider) Evaluate(context.Context, decision.DecisionRequest, []string) (decision.DecisionEvidence, error) {
	return decision.DecisionEvidence{}, errors.New("connection refused")
}
