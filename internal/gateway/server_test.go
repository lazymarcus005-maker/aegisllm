package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/core"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestGateway starts a mock upstream and a gateway backed by it.
func newTestGateway(t *testing.T, mutate func(*Config), upstream http.HandlerFunc) (*Server, *httptest.Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	cfg := Config{
		ListenAddr:            ":0",
		UpstreamBaseURL:       up.URL,
		UpstreamAuthMode:      "none",
		MaxBodyBytes:          1 << 20,
		SecurityMode:          ModeOff,
		DefaultTargetProvider: "cloud",
		HeaderApplication:     "X-Application-Id",
		HeaderTenant:          "X-Tenant-Id",
		HeaderUser:            "X-User-Id",
		HeaderTargetProvider:  "X-Target-Provider",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := NewServer(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(srv.Handler())
	t.Cleanup(gw.Close)
	return srv, gw, up
}

const cleanRequest = `{"model":"mock-model","messages":[{"role":"user","content":"hello there"}]}`

func TestCleanRequestProxiedUnchanged(t *testing.T) {
	var upstreamBody string
	_, gw, _ := newTestGateway(t, nil, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	})

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if upstreamBody != cleanRequest {
		t.Fatalf("upstream body mutated:\n got %s\nwant %s", upstreamBody, cleanRequest)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "chatcmpl-1") {
		t.Fatalf("response not passed through: %s", b)
	}
}

func TestMalformedRequestReturns400(t *testing.T) {
	_, gw, _ := newTestGateway(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream must not be called for malformed requests")
	})
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model": `))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var out struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error.Type != "invalid_request_error" {
		t.Fatalf("error type: %s", out.Error.Type)
	}
}

func TestOversizedRequestReturns413(t *testing.T) {
	_, gw, _ := newTestGateway(t, func(c *Config) { c.MaxBodyBytes = 64 }, func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream must not be called for oversized requests")
	})
	big := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("x", 4096) + `"}]}`
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestHealthAndReady(t *testing.T) {
	_, gw, _ := newTestGateway(t, nil, func(w http.ResponseWriter, _ *http.Request) {})

	resp, _ := http.Get(gw.URL + "/health")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "ok") {
		t.Fatalf("health: %d %s", resp.StatusCode, body)
	}

	resp, _ = http.Get(gw.URL + "/ready")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "ready") {
		t.Fatalf("ready: %d %s", resp.StatusCode, body)
	}
}

func TestReadyFailsWhenUpstreamUnreachable(t *testing.T) {
	_, gw, _ := newTestGateway(t, func(c *Config) { c.UpstreamBaseURL = "http://127.0.0.1:1" }, func(w http.ResponseWriter, _ *http.Request) {})
	resp, err := http.Get(gw.URL + "/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

// stubPipeline returns fixed decisions; used to test server-side mode handling.
type stubPipeline struct {
	dec RequestDecision
}

func (s stubPipeline) ProcessRequest(*core.InspectionEnvelope, []byte) (RequestDecision, error) {
	return s.dec, nil
}

func TestEnforceModeBlocksOnPipelineBlock(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream must not be called when blocked")
	})
	srv.SetPipeline(stubPipeline{dec: RequestDecision{Action: core.ActionBlock, Code: "SECRET_DETECTED"}})

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "security_policy_violation") || !strings.Contains(string(b), "SECRET_DETECTED") {
		t.Fatalf("error contract wrong: %s", b)
	}
}

func TestShadowModeForwardsDespiteBlockPrediction(t *testing.T) {
	called := false
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeShadow }, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	srv.SetPipeline(stubPipeline{dec: RequestDecision{Action: core.ActionBlock, Code: "SECRET_DETECTED"}})

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !called {
		t.Fatalf("shadow mode must follow incumbent path: status=%d called=%v", resp.StatusCode, called)
	}
}

func TestEnforceModeForwardsTransformedBody(t *testing.T) {
	var upstreamBody string
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamBody = string(b)
		w.WriteHeader(http.StatusOK)
	})
	srv.SetPipeline(stubPipeline{dec: RequestDecision{Action: core.ActionRedact, TransformedBody: []byte(`{"transformed":true}`)}})

	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if upstreamBody != `{"transformed":true}` {
		t.Fatalf("transformed body not forwarded: %s", upstreamBody)
	}
}
