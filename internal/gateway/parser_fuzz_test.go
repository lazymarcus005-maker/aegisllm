package gateway

import "testing"

func FuzzChatCompletionsParser(f *testing.F) {
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	f.Add([]byte(`{"model":"m","messages":[{"role":"tool","tool_call_id":"x","content":"<TOKEN>"}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseChatCompletions(raw)
	})
}
