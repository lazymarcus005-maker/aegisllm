// Command fakemcp is a deliberately small local MCP Streamable HTTP fixture.
// It is for compose/integration smoke only and has no production security
// properties or credentials.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := ":9100"
	if value := os.Getenv("LISTEN_ADDR"); value != "" {
		addr = value
	}
	http.HandleFunc("/mcp", handle)
	log.Printf("fake MCP listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/ready\"}\n\n"))
		return
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var request struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if request.Method == "initialize" {
		w.Header().Set("MCP-Session-Id", "fake-session")
		write(w, request.ID, map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "aegis-fake-mcp", "version": "1"}})
		return
	}
	if request.Method == "tools/list" {
		write(w, request.ID, map[string]any{"tools": []any{map[string]any{"name": "echo", "description": "Returns its input", "inputSchema": map[string]any{"type": "object"}}, map[string]any{"name": "shell", "description": "Restricted fixture tool", "inputSchema": map[string]any{"type": "object"}}}})
		return
	}
	if request.Method == "tools/call" {
		write(w, request.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": "fake MCP result"}}})
		return
	}
	write(w, request.ID, map[string]any{})
}

func write(w http.ResponseWriter, id any, result any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}
