// Command fakeprovider is a deterministic, non-production upstream for the
// conformance lab. It accepts no real provider credentials and never logs
// request or response bodies.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
)

type Behavior struct {
	Status             int    `json:"status,omitempty"`
	DelayMS            int    `json:"delay_ms,omitempty"`
	FragmentBytes      int    `json:"fragment_bytes,omitempty"`
	InvalidFrame       bool   `json:"invalid_frame,omitempty"`
	DisconnectAfter    int    `json:"disconnect_after_events,omitempty"`
	ResponseText       string `json:"response_text,omitempty"`
	SensitiveOutput    string `json:"sensitive_output,omitempty"`
	ToolCall           bool   `json:"tool_call,omitempty"`
	Usage              bool   `json:"usage,omitempty"`
	RetryAfter         string `json:"retry_after,omitempty"`
	OversizeBytes      int    `json:"oversize_bytes,omitempty"`
	AuthHeaderExpected string `json:"auth_header_expected,omitempty"`
}
type Config struct {
	Default Behavior            `json:"default"`
	Cases   map[string]Behavior `json:"cases"`
}

func main() {
	port := flag.String("port", getenv("PORT", "9090"), "listen port")
	profile := flag.String("profile", getenv("FAKE_PROVIDER_PROFILE", "matrix"), "openai, anthropic, or generic")
	behaviorFile := flag.String("behavior-file", os.Getenv("FAKE_PROVIDER_BEHAVIOR_FILE"), "JSON behavior descriptor")
	flag.Parse()
	cfg := Config{Default: Behavior{Usage: true}, Cases: map[string]Behavior{}}
	if *behaviorFile != "" {
		data, err := securetransport.ReadTrustedFile(*behaviorFile)
		if err != nil {
			panic("fakeprovider behavior unavailable")
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			panic("fakeprovider behavior malformed")
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","non_production":true}`)
	})
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) { handle(w, r, *profile, cfg) })
	server := &http.Server{Addr: ":" + *port, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	fmt.Fprintf(os.Stderr, "fakeprovider profile=%s port=%s non_production=true\n", safe(*profile), safe(*port))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic("fakeprovider stopped")
	}
}

func handle(w http.ResponseWriter, r *http.Request, profile string, cfg Config) {
	if profile == "matrix" {
		switch {
		case strings.Contains(r.URL.Path, "messages"):
			profile = "anthropic"
		case strings.Contains(r.URL.Path, "responses") || strings.HasSuffix(r.URL.Path, "/response"):
			profile = "openai-responses"
		default:
			profile = "openai"
		}
	}
	caseID := r.Header.Get("X-Conformance-Case")
	behavior := cfg.Default
	if selected, ok := cfg.Cases[caseID]; ok {
		behavior = selected
	}
	if behavior.Status == 0 {
		behavior.Status = http.StatusOK
	}
	if behavior.DelayMS > 0 {
		time.Sleep(time.Duration(behavior.DelayMS) * time.Millisecond)
	}
	if behavior.AuthHeaderExpected != "" && r.Header.Get("Authorization") != behavior.AuthHeaderExpected {
		writeError(w, http.StatusUnauthorized, "fake_auth_mismatch")
		return
	}
	if behavior.RetryAfter != "" {
		w.Header().Set("Retry-After", safe(behavior.RetryAfter))
	}
	if behavior.Status != http.StatusOK {
		writeError(w, behavior.Status, "fake_provider_error")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	var req map[string]any
	_ = json.Unmarshal(body, &req)
	model, _ := req["model"].(string)
	if model == "" {
		model = "fake-model"
	}
	stream, _ := req["stream"].(bool)
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		stream = true
	}
	text := behavior.ResponseText
	if text == "" {
		text = "conformance ok"
	}
	if behavior.SensitiveOutput != "" {
		text += " " + behavior.SensitiveOutput
	}
	if behavior.OversizeBytes > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Repeat("x", behavior.OversizeBytes))
		return
	}
	if stream {
		writeStream(w, profile, text, behavior)
		return
	}
	writeJSON(w, profile, model, text, behavior)
}

func writeJSON(w http.ResponseWriter, profile, model, text string, b Behavior) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	var response map[string]any
	switch profile {
	case "anthropic":
		response = map[string]any{"id": "msg_fake", "type": "message", "role": "assistant", "model": model, "content": []any{map[string]any{"type": "text", "text": text}}, "stop_reason": "end_turn"}
	case "openai-responses":
		response = map[string]any{"id": "resp_fake", "object": "response", "model": model, "output": []any{map[string]any{"type": "message", "content": []any{map[string]any{"type": "output_text", "text": text}}}}, "status": "completed"}
	default:
		message := map[string]any{"role": "assistant", "content": text}
		if b.ToolCall {
			message["tool_calls"] = []any{map[string]any{"id": "call_fake", "type": "function", "function": map[string]any{"name": "lookup", "arguments": "{\"q\":\"safe\"}"}}}
		}
		response = map[string]any{"id": "chat_fake", "object": "chat.completion", "model": model, "choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": "stop"}}}
	}
	if b.Usage {
		response["usage"] = map[string]any{"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
	}
	_ = json.NewEncoder(w).Encode(response)
}

func writeStream(w http.ResponseWriter, profile, text string, b Behavior) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	var events []string
	switch profile {
	case "anthropic":
		events = []string{
			`{"type":"message_start","message":{"id":"msg_fake","type":"message","role":"assistant","model":"fake-model","usage":{"input_tokens":1}}}`,
			fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}`, text),
			`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`,
			`{"type":"message_stop"}`,
		}
	case "openai-responses":
		events = []string{fmt.Sprintf(`{"type":"response.output_text.delta","delta":%q}`, text), `{"type":"response.completed","response":{"status":"completed"}}`}
	default:
		events = []string{
			fmt.Sprintf(`{"id":"chat_fake","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":%q}}]}`, text),
			`{"id":"chat_fake","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		}
	}
	for i, event := range events {
		if b.DisconnectAfter > 0 && i >= b.DisconnectAfter {
			if h, ok := w.(http.Hijacker); ok {
				conn, _, err := h.Hijack()
				if err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		if b.InvalidFrame && i == len(events)-1 {
			event = "{malformed"
		}
		writeEvent(w, event, b.FragmentBytes)
		if flusher != nil {
			flusher.Flush()
		}
		if b.DelayMS > 0 {
			time.Sleep(time.Duration(b.DelayMS) * time.Millisecond)
		}
	}
	if b.DisconnectAfter == 0 {
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}
}
func writeEvent(w io.Writer, event string, fragment int) {
	if fragment <= 0 {
		_, _ = fmt.Fprintf(w, "data: %s\n\n", event)
		return
	}
	line := "data: " + event + "\n\n"
	for len(line) > 0 {
		n := fragment
		if n > len(line) {
			n = len(line)
		}
		_, _ = io.WriteString(w, line[:n])
		line = line[n:]
	}
}
func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"type": "fake_provider_error", "code": safe(code)}})
}
func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func safe(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		value = value[:64]
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r) {
			continue
		}
		value = value[:i] + "_" + value[i+len(string(r)):]
	}
	return value
}
