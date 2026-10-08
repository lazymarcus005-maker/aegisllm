package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/routing"
)

type routeDecisionPipeline struct{ action core.Action }

func (p routeDecisionPipeline) ProcessRequest(*core.InspectionEnvelope, []byte) (RequestDecision, error) {
	return RequestDecision{Action: p.action}, nil
}
func (routeDecisionPipeline) ProcessResponse(*core.InspectionEnvelope, []byte) (ResponseOutcome, error) {
	return ResponseOutcome{Action: core.ActionAllow}, nil
}
func (routeDecisionPipeline) SetSecurityMode(string) {}

func writeRouteRegistry(t *testing.T, local, cloud string, localAllow string) string {
	t.Helper()
	data := fmt.Sprintf(`schema: aegisllm.upstreams/v1
version: 1
upstreams:
  - id: local-primary
    class: local
    provider: local
    family: openai
    base_url: %s
    priority: 1
    weight: 1
    enabled: true
    auth: {mode: none}
    health: {endpoint: /health, interval: 1h, timeout: 100ms}
    breaker: {threshold: 2, open_interval: 1s}
    model_allow: [%s]
    aliases: {alias: local/model}
    capabilities: {chat: true, responses: true, messages: false, embeddings: false, streaming: true, tools: true}
  - id: cloud-primary
    class: cloud
    provider: cloud
    family: openai
    base_url: %s
    priority: 2
    weight: 1
    enabled: true
    auth: {mode: none}
    health: {endpoint: /health, interval: 1h, timeout: 100ms}
    breaker: {threshold: 2, open_interval: 1s}
    capabilities: {chat: true, responses: true, messages: false, embeddings: true, streaming: true, tools: true}
fallback_chains:
  - id: local-then-cloud
    routes: [local-primary, cloud-primary]
`, local, localAllow, cloud)
	file := filepath.Join(t.TempDir(), "registry.yaml")
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func routeConfig(registry string) Config {
	return Config{UpstreamRegistryFile: registry, SecurityMode: ModeEnforce, DefaultTargetProvider: "cloud", HeaderApplication: "X-Application-Id", HeaderTenant: "X-Tenant-Id", HeaderUser: "X-User-Id", HeaderTargetProvider: "X-Target-Provider", MaxBodyBytes: 1 << 20}
}

func TestForceLocalIsolationAndAliasRewrite(t *testing.T) {
	var local, cloud atomic.Int32
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		local.Add(1)
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"model":"local/model"`) {
			t.Errorf("alias not rewritten: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"local","choices":[]}`)
	}))
	defer localServer.Close()
	cloudServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cloud.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer cloudServer.Close()
	srv, err := NewServer(routeConfig(writeRouteRegistry(t, localServer.URL, cloudServer.URL, "local/*")), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	srv.SetPipeline(routeDecisionPipeline{action: core.ActionForceLocalModel})
	gw := httptest.NewServer(srv.Handler())
	defer gw.Close()
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"alias","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || local.Load() != 1 || cloud.Load() != 0 {
		t.Fatalf("status=%d local=%d cloud=%d", resp.StatusCode, local.Load(), cloud.Load())
	}
	routesResp, err := http.Get(gw.URL + "/api/routes")
	if err != nil {
		t.Fatal(err)
	}
	routesBody, _ := io.ReadAll(routesResp.Body)
	routesResp.Body.Close()
	if routesResp.StatusCode != http.StatusOK || strings.Contains(string(routesBody), localServer.URL) || strings.Contains(string(routesBody), "secret") {
		t.Fatalf("unsanitized route status: %s", routesBody)
	}
}

func TestForceLocalUnavailableFailsClosedBeforeCloud(t *testing.T) {
	var cloud atomic.Int32
	cloudServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { cloud.Add(1); w.WriteHeader(http.StatusOK) }))
	defer cloudServer.Close()
	reg := writeRouteRegistry(t, "http://127.0.0.1:1", cloudServer.URL, "local/*")
	srv, err := NewServer(routeConfig(reg), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	srv.SetPipeline(routeDecisionPipeline{action: core.ActionForceLocalModel})
	srv.routed.Manager().SetHealth("local-primary", false)
	gw := httptest.NewServer(srv.Handler())
	defer gw.Close()
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"local/model","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || cloud.Load() != 0 {
		t.Fatalf("status=%d cloud=%d", resp.StatusCode, cloud.Load())
	}
}

func TestModelDeniedBeforeUpstream(t *testing.T) {
	var calls atomic.Int32
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }))
	defer cloud.Close()
	reg := writeRouteRegistry(t, cloud.URL, cloud.URL, "allowed/*")
	srv, err := NewServer(routeConfig(reg), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	srv.SetPipeline(routeDecisionPipeline{action: core.ActionForceLocalModel})
	gw := httptest.NewServer(srv.Handler())
	defer gw.Close()
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"denied","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", resp.StatusCode, calls.Load())
	}
}

func TestExplicitFallbackAndUncertainPostDelivery(t *testing.T) {
	var cloudCalls atomic.Int32
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cloudCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer cloud.Close()
	regFile := writeRouteRegistry(t, "http://127.0.0.1:1", cloud.URL, "local/*")
	manager, err := routing.NewManagerFile(regFile)
	if err != nil {
		t.Fatal(err)
	}
	routed, err := NewRoutedProxy(routeConfig(regFile), manager)
	if err != nil {
		t.Fatal(err)
	}
	defer routed.Close()
	req := httptest.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions", strings.NewReader(`{"model":"local/model"}`))
	resp, selection, err := routed.Forward(req, []byte(`{"model":"local/model"}`), routing.Input{Action: core.ActionAllow, RequestedModel: "local/model", Family: "openai", Capability: "chat", Constraint: routing.Constraint{FallbackChain: "local-then-cloud"}, AllowFailover: true})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !selection.Failover || cloudCalls.Load() != 1 {
		t.Fatalf("selection=%+v calls=%d", selection, cloudCalls.Load())
	}

	var uncertainCloud atomic.Int32
	uncertain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		uncertainCloud.Add(1)
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer uncertain.Close()
	cloudBeforeUncertain := cloudCalls.Load()
	uncertainReg := writeRouteRegistry(t, uncertain.URL, cloud.URL, "local/*")
	uncertainManager, err := routing.NewManagerFile(uncertainReg)
	if err != nil {
		t.Fatal(err)
	}
	uncertainRouted, err := NewRoutedProxy(routeConfig(uncertainReg), uncertainManager)
	if err != nil {
		t.Fatal(err)
	}
	defer uncertainRouted.Close()
	uncertainReq := httptest.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions", strings.NewReader(`{"model":"local/model"}`))
	_, _, _ = uncertainRouted.Forward(uncertainReq, []byte(`{"model":"local/model"}`), routing.Input{Action: core.ActionAllow, RequestedModel: "local/model", Family: "openai", Capability: "chat", Constraint: routing.Constraint{FallbackChain: "local-then-cloud"}, AllowFailover: true})
	if cloudCalls.Load() != cloudBeforeUncertain {
		t.Fatal("POST with uncertain delivery was retried")
	}
}
