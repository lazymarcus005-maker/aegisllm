package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/dashboard"
	"github.com/aegisllm/gateway/internal/observability"
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
	t.Cleanup(srv.Close)
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

func TestUniversalEndpointRoutes(t *testing.T) {
	routes := []struct {
		path string
		body string
	}{
		{"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hello"}]}`},
		{"/v1/responses", `{"model":"m","input":"hello"}`},
		{"/v1/completions", `{"model":"m","prompt":"hello"}`},
		{"/v1/embeddings", `{"model":"m","input":"hello"}`},
		{"/v1/messages", `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hello"}]}`},
		{"/v1/complete", `{"model":"m","prompt":"hello"}`},
		{"/anthropic/v1/messages", `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hello"}]}`},
		{"/message", `{"model":"m","messages":[{"role":"user","content":"hello"}]}`},
		{"/messages", `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hello"}]}`},
		{"/chatcompletion", `{"prompt":"hello"}`},
		{"/chat/completions", `{"input":"hello"}`},
		{"/response", `{"text":"hello"}`},
		{"/responses", `{"content":"hello"}`},
		{"/v1/message", `{"prompt":"hello"}`},
		{"/v1/response", `{"input":"hello"}`},
	}
	_, gw, _ := newTestGateway(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	for _, tc := range routes {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Post(gw.URL+tc.path, "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status: %d", resp.StatusCode)
			}
		})
	}
}

func TestModelsPassthrough(t *testing.T) {
	_, gw, _ := newTestGateway(t, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" {
			t.Fatalf("upstream request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	resp, err := http.Get(gw.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestModelsPassthroughAuditsAllow(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	pipe, sink := newRealPipeline(t)
	srv.SetPipeline(pipe)
	resp, err := http.Get(gw.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(sink.String(), `"action":"ALLOW"`) {
		t.Fatalf("models audit: status=%d audit=%s", resp.StatusCode, sink.String())
	}
}

func TestUniversalBadBodyAndSecretBlock(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("blocked request reached upstream")
	})
	pipe, _ := newRealPipeline(t)
	srv.SetPipeline(pipe)
	bad, err := http.Post(gw.URL+"/v1/responses", "application/json", strings.NewReader(`{"model":`))
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad body status: %d", bad.StatusCode)
	}
	secret := `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"use sk-abcdefghijklmnopqrstuvwxyz123456"}]}`
	blocked, err := http.Post(gw.URL+"/v1/messages", "application/json", strings.NewReader(secret))
	if err != nil {
		t.Fatal(err)
	}
	blocked.Body.Close()
	if blocked.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked status: %d", blocked.StatusCode)
	}
}

func TestStreamingRequestIsInspectedBeforeUpstream(t *testing.T) {
	called := false
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, r *http.Request) {
		called = true
		body, _ := io.ReadAll(r.Body)
		_ = body
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	})
	srv.SetPipeline(stubPipeline{dec: RequestDecision{Action: core.ActionBlock, Code: "SECRET_DETECTED"}})
	body := `{"model":"m","stream":true,"messages":[{"role":"user","content":"sk-abcdefghijklmnopqrstuvwxyz123456"}]}`
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || called {
		t.Fatalf("stream request bypassed policy: status=%d called=%v", resp.StatusCode, called)
	}
}

func TestStreamingRequestPIIIsTransformedBeforeUpstream(t *testing.T) {
	var upstreamBody string
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	})
	pipe, _ := newRealPipeline(t)
	srv.SetPipeline(pipe)
	body := `{"model":"m","stream":true,"messages":[{"role":"user","content":"call 0812345678"}]}`
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if strings.Contains(upstreamBody, "0812345678") || !strings.Contains(upstreamBody, "PHONE_NUMBER_001") {
		t.Fatalf("stream request was not transformed: %s", upstreamBody)
	}
}

func TestUniversalPIITransformationUsesEndpointNormalizer(t *testing.T) {
	cases := []struct {
		path string
		body string
	}{
		{"/v1/responses", `{"model":"m","input":"call 0812345678"}`},
		{"/v1/completions", `{"model":"m","prompt":"call 0812345678"}`},
		{"/v1/messages", `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"call 0812345678"}]}`},
		{"/message", `{"prompt":"call 0812345678"}`},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			var upstreamBody string
			srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				upstreamBody = string(b)
				w.WriteHeader(http.StatusOK)
			})
			pipe, _ := newRealPipeline(t)
			srv.SetPipeline(pipe)
			resp, err := http.Post(gw.URL+tc.path, "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status: %d", resp.StatusCode)
			}
			if strings.Contains(upstreamBody, "0812345678") || !strings.Contains(upstreamBody, "PHONE_NUMBER_001") {
				t.Fatalf("PII not transformed: %s", upstreamBody)
			}
		})
	}
}

func TestUniversalSecretSmokeMatrix(t *testing.T) {
	requests := []struct {
		path string
		body string
	}{
		{"/v1/messages", `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"sk-abcdefghijklmnopqrstuvwxyz123456"}]}`},
		{"/v1/responses", `{"model":"m","input":"sk-abcdefghijklmnopqrstuvwxyz123456"}`},
		{"/v1/completions", `{"model":"m","prompt":"sk-abcdefghijklmnopqrstuvwxyz123456"}`},
		{"/message", `{"prompt":"sk-abcdefghijklmnopqrstuvwxyz123456"}`},
		{"/chatcompletion", `{"prompt":"sk-abcdefghijklmnopqrstuvwxyz123456"}`},
		{"/response", `{"prompt":"sk-abcdefghijklmnopqrstuvwxyz123456"}`},
	}
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("secret reached upstream")
	})
	pipe, _ := newRealPipeline(t)
	srv.SetPipeline(pipe)
	for _, tc := range requests {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Post(gw.URL+tc.path, "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("secret status: %d", resp.StatusCode)
			}
		})
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
	srv, gw, _ := newTestGateway(t, nil, func(w http.ResponseWriter, _ *http.Request) {})
	srv.AddReadinessCheck("policy_loaded", func() string { return "" })

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
	var ready struct {
		Status            string            `json:"status"`
		DeploymentProfile string            `json:"deployment_profile"`
		SecurityMode      string            `json:"security_mode"`
		Dependencies      map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(body, &ready); err != nil {
		t.Fatal(err)
	}
	if ready.Status != "ready" || ready.DeploymentProfile != string(ProfileDevelopment) || ready.Dependencies["upstream"] != "ready" || ready.Dependencies["policy_loaded"] != "ready" {
		t.Fatalf("readiness evidence missing: %+v", ready)
	}
}

func TestProtectionStatsAndDashboardEndpoints(t *testing.T) {
	srv, gw, _ := newTestGateway(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	metrics := observability.New()
	metrics.ObserveRequest(core.ActionBlock, "enforce")
	metrics.ObserveFindings(string(core.CategoryPII), "phone")
	srv.SetProtectionDashboard(dashboard.New(metrics))

	resp, err := http.Get(gw.URL + "/api/protection-stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("stats response: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var stats struct {
		TotalPrevented uint64 `json:"total_prevented"`
		ByCategory     []struct {
			Category string `json:"category"`
			Subtype  string `json:"subtype"`
			Count    uint64 `json:"count"`
		} `json:"by_category"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats.TotalPrevented != 1 || len(stats.ByCategory) != 1 || stats.ByCategory[0].Subtype != "phone" {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	resp, err = http.Get(gw.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Protection Leaderboard") {
		t.Fatalf("dashboard response: %d %s", resp.StatusCode, body)
	}

	resp, err = http.Get(gw.URL + "/dashboard/style.css")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard asset status: %d", resp.StatusCode)
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

func TestPromptBudgetRejectsBeforeUpstream(t *testing.T) {
	called := false
	_, gw, _ := newTestGateway(t, func(c *Config) { c.MaxPromptChars = 4 }, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || called {
		t.Fatalf("prompt budget status=%d upstream_called=%v", resp.StatusCode, called)
	}
}

func TestResponseBudgetRejectsWithoutPartialBody(t *testing.T) {
	_, gw, _ := newTestGateway(t, func(c *Config) { c.MaxResponseBytes = 8 }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"secret":"must-not-reach-client"}`))
	})
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || len(body) == 0 || strings.Contains(string(body), "must-not-reach-client") {
		t.Fatalf("oversized response status=%d body=%s", resp.StatusCode, body)
	}
}

func TestRateLimitReturnsRetryAfterAndIsolatesApplications(t *testing.T) {
	_, gw, _ := newTestGateway(t, func(c *Config) {
		c.RequestsPerSecond = 1
		c.RateBurst = 1
	}, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	post := func(app string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, gw.URL+"/v1/chat/completions", strings.NewReader(cleanRequest))
		req.Header.Set("X-Application-Id", app)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	first := post("app-a")
	first.Body.Close()
	second := post("app-a")
	defer second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests || second.Header.Get("Retry-After") == "" {
		t.Fatalf("rate limit status=%d retry-after=%q", second.StatusCode, second.Header.Get("Retry-After"))
	}
	other := post("app-b")
	defer other.Body.Close()
	if other.StatusCode != http.StatusOK {
		t.Fatalf("isolated application status=%d", other.StatusCode)
	}
}

func TestConcurrencyLimitReleasesOnCompletion(t *testing.T) {
	started := make(chan struct{})
	finish := make(chan struct{})
	var once sync.Once
	_, gw, _ := newTestGateway(t, func(c *Config) {
		c.RequestsPerSecond = 100
		c.RateBurst = 100
		c.MaxConcurrentRequests = 1
	}, func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(started) })
		<-finish
		w.WriteHeader(http.StatusOK)
	})
	firstDone := make(chan *http.Response, 1)
	go func() {
		resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
		if err != nil {
			t.Errorf("first request: %v", err)
			return
		}
		firstDone <- resp
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first request did not reach upstream")
	}
	second, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests || second.Header.Get("Retry-After") == "" {
		t.Fatalf("concurrency status=%d retry-after=%q", second.StatusCode, second.Header.Get("Retry-After"))
	}
	close(finish)
	first := <-firstDone
	first.Body.Close()
	third, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	third.Body.Close()
	if third.StatusCode != http.StatusOK {
		t.Fatalf("released concurrency status=%d", third.StatusCode)
	}
}

func TestUpstreamHeaderTimeoutIsSanitized(t *testing.T) {
	_, gw, _ := newTestGateway(t, func(c *Config) {
		c.UpstreamResponseHeaderTimeout = 20 * time.Millisecond
		c.UpstreamRequestTimeout = 100 * time.Millisecond
	}, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusGatewayTimeout || strings.Contains(string(body), "timeout") && strings.Contains(string(body), "Client.Timeout") {
		t.Fatalf("timeout response status=%d body=%s", resp.StatusCode, body)
	}
}

func TestUpstreamBodyTimeoutIsSanitized(t *testing.T) {
	_, gw, _ := newTestGateway(t, func(c *Config) {
		c.UpstreamResponseHeaderTimeout = time.Second
		c.UpstreamRequestTimeout = 30 * time.Millisecond
	}, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(`{"ok":`))
		flusher.Flush()
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`true}`))
	})
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusGatewayTimeout || strings.Contains(string(body), "true}") {
		t.Fatalf("body timeout response status=%d body=%s", resp.StatusCode, body)
	}
}

func TestUpstreamBreakerOpensAndReadinessIsNotReady(t *testing.T) {
	_, gw, _ := newTestGateway(t, func(c *Config) {
		c.UpstreamBaseURL = "http://127.0.0.1:1"
		c.UpstreamDialTimeout = 20 * time.Millisecond
		c.UpstreamRequestTimeout = 50 * time.Millisecond
		c.UpstreamBreakerThreshold = 1
		c.UpstreamBreakerOpenInterval = time.Minute
	}, func(w http.ResponseWriter, _ *http.Request) {})
	post := func() *http.Response {
		resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(cleanRequest))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	first := post()
	first.Body.Close()
	second := post()
	defer second.Body.Close()
	if second.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("breaker status=%d", second.StatusCode)
	}
	ready, err := http.Get(gw.URL + "/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Body.Close()
	if ready.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("breaker readiness status=%d", ready.StatusCode)
	}
}

func TestStreamDurationCancelsUpstreamWithoutInspection(t *testing.T) {
	upstreamCanceled := make(chan struct{})
	_, gw, _ := newTestGateway(t, func(c *Config) {
		c.MaxStreamDuration = 40 * time.Millisecond
		c.UpstreamRequestTimeout = time.Second
	}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: first\n\n"))
		flusher.Flush()
		<-r.Context().Done()
		close(upstreamCanceled)
	})
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/v1/chat/completions", strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"stream me"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "data: first") {
		t.Fatalf("stream status=%d body=%q", resp.StatusCode, body)
	}
	select {
	case <-upstreamCanceled:
	case <-time.After(time.Second):
		t.Fatal("stream context was not cancelled")
	}
}

// stubPipeline returns fixed decisions; used to test server-side mode handling.
type stubPipeline struct {
	dec RequestDecision
}

func (s stubPipeline) ProcessRequest(*core.InspectionEnvelope, []byte) (RequestDecision, error) {
	return s.dec, nil
}

func (s stubPipeline) ProcessResponse(*core.InspectionEnvelope, []byte) (ResponseOutcome, error) {
	return ResponseOutcome{Action: core.ActionAllow}, nil
}

func (s stubPipeline) SetSecurityMode(string) {}

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
