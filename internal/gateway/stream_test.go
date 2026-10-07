package gateway

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOpenAISecretSplitAcrossDeltasNeverReachesClient(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"glpat-\"}}]}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"Abc123Xyz_-456DefGhi\"}}]}\n\n")
	})
	pipe, _ := newRealPipeline(t)
	srv.SetPipeline(pipe)
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "glpat-") || strings.Contains(string(body), "Abc123") {
		t.Fatalf("raw split secret leaked: %s", body)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
}

func TestAnthropicSplitPIIIsTokenizedWithValidSSE(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"call 08123\"}}\n\n")
		_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"45678\"}}\n\n")
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	})
	pipe, _ := newRealPipeline(t)
	srv.SetPipeline(pipe)
	request := `{"model":"m","stream":true,"max_tokens":8,"messages":[{"role":"user","content":"hello"}]}`
	resp, err := http.Post(gw.URL+"/v1/messages", "application/json", strings.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "0812345678") || !strings.Contains(string(body), "PHONE_NUMBER_001") {
		t.Fatalf("PII was not tokenized safely: %s", body)
	}
	if !strings.Contains(string(body), "event: content_block_delta") {
		t.Fatalf("SSE framing was not preserved: %s", body)
	}
}

func TestOpenAIResponsesTextAndToolArgumentsAreInspected(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeEnforce }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"phone 0812345678\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.function_call_arguments.delta\",\"delta\":\"phone=0812345678\"}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})
	pipe, _ := newRealPipeline(t)
	srv.SetPipeline(pipe)
	resp, err := http.Post(gw.URL+"/v1/responses", "application/json", strings.NewReader(`{"model":"m","stream":true,"input":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if strings.Contains(text, "0812345678") {
		t.Fatalf("response delta leaked protected content: %s", text)
	}
	if strings.Count(text, "PHONE_NUMBER_001") < 2 {
		t.Fatalf("expected text/tool transformations: %s", text)
	}
}

func TestStreamingShadowForwardsPredictionWithoutApplying(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) { c.SecurityMode = ModeShadow }, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"glpat-Abc123Xyz_-456DefGhi\"}}]}\n\n")
	})
	pipe, sink := newRealPipeline(t)
	srv.SetPipeline(pipe)
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "glpat-Abc123") {
		t.Fatalf("shadow changed response: %s", body)
	}
	audit := sink.String()
	if !strings.Contains(audit, `"predicted_action":"BLOCK"`) || !strings.Contains(audit, `"applied_action":"ALLOW"`) {
		t.Fatalf("shadow prediction/applied audit missing: %s", audit)
	}
}

func TestStreamingMalformedAndTimeoutFailClosed(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		srv, gw, _ := newTestGateway(t, func(c *Config) {
			c.SecurityMode = ModeEnforce
			c.MaxSSEEventBytes = 32
		}, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"oversized\"}}]}\n\n")
		})
		pipe, _ := newRealPipeline(t)
		srv.SetPipeline(pipe)
		resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		srv, gw, _ := newTestGateway(t, func(c *Config) {
			c.SecurityMode = ModeEnforce
			c.MaxStreamDuration = 30 * time.Millisecond
		}, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(200 * time.Millisecond)
		})
		pipe, _ := newRealPipeline(t)
		srv.SetPipeline(pipe)
		resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusGatewayTimeout {
			t.Fatalf("timeout status = %d", resp.StatusCode)
		}
	})
}

func TestStreamingBlockAfterHeadersEmitsSanitizedSSEError(t *testing.T) {
	srv, gw, _ := newTestGateway(t, func(c *Config) {
		c.SecurityMode = ModeEnforce
		c.StreamInspectionWindow = 8
	}, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"1234567890\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"abcdefghij\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"glpat-Abc123Xyz_-456DefGhi\"}}]}\n\n")
	})
	pipe, _ := newRealPipeline(t)
	srv.SetPipeline(pipe)
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(text, `"security_policy_violation"`) {
		t.Fatalf("expected committed SSE error, status=%d body=%s", resp.StatusCode, text)
	}
	if strings.Contains(text, "glpat-Abc123") {
		t.Fatalf("raw secret leaked in terminal event: %s", text)
	}
}
