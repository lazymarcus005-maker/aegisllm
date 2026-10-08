// Command fakelaya is an in-repository HTTP provider for CI and smoke tests.
// It is intentionally not a calibration source for production promotion.
package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aegisllm/gateway/internal/securetransport"
)

type request struct {
	State struct {
		Content string `json:"content"`
	} `json:"state"`
	Questions []string `json:"questions"`
}

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	http.HandleFunc("/v1/evaluate", func(w http.ResponseWriter, r *http.Request) {
		var in request
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		content := strings.ToLower(in.State.Content)
		decisions := map[string]map[string]any{}
		for _, id := range in.Questions {
			triggered := false
			switch id {
			case "prompt_injection", "policy_bypass_intent":
				triggered = strings.Contains(content, "ignore") || strings.Contains(content, "override")
			case "system_prompt_extraction":
				triggered = strings.Contains(content, "system prompt")
			case "credential_exfiltration":
				triggered = strings.Contains(content, "token") || strings.Contains(content, "password")
			case "unsafe_tool_intent":
				triggered = strings.Contains(content, "delete") || strings.Contains(content, "shell")
			case "sensitive_data_intent":
				triggered = strings.Contains(content, "personal") || strings.Contains(content, "confidential")
			}
			confidence := 0.91
			if !triggered {
				confidence = 0.09
			}
			decisions[id] = map[string]any{"value": triggered, "answer_confidence": confidence}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"provider": "laya", "checkpoint": "fake-checkpoint", "schema_version": "security-v1", "route": "fake", "decisions": decisions})
	})
	if err := securetransport.ServeHTTPServer(securetransport.NewHTTPServer(":8300", http.DefaultServeMux), "", ""); err != nil {
		panic(err)
	}
}
