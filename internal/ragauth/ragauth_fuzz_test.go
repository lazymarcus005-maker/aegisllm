package ragauth

import "testing"

func FuzzParseBounded(f *testing.F) {
	f.Add([]byte(`{"retrieval":{"query":"q","collection":"c","purpose":"p","documents":[{"id":"d","tenant_id":"t","application_id":"a","content":"x"}]}}`))
	f.Add([]byte(`{"messages":[{"content":[{"type":"tool_result","context":{"chunks":[]}}]}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		limits := Limits{MaxBytes: 64 << 10, MaxResults: 8, MaxResultBytes: 4096, MaxDepth: 6, MaxNodes: 128}
		_, _ = Parse(body, Identity{Tenant: "t", Application: "a", Subject: "s"}, "request", "policy", 1, limits)
	})
}
