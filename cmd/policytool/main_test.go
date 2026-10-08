package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/policy"
)

func TestExplainOutputIsSanitized(t *testing.T) {
	const secret = "glpat-0123456789abcdefghij"
	const email = "operator@example.invalid"
	file := t.TempDir() + "/request.json"
	if err := os.WriteFile(file, []byte(`{"model":"m","messages":[{"role":"user","content":"`+secret+` `+email+`"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.LoadFile("../../policies/strict-cloud.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var out result
	explainInto(&out, pol, file, "/v1/chat/completions", "cloud", "", "")
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || strings.Contains(string(data), email) || strings.Contains(string(data), "sha256:") {
		t.Fatalf("policytool output leaked request material: %s", data)
	}
	if out.FinalAction == "" || len(out.Findings) == 0 {
		t.Fatalf("missing sanitized explanation: %+v", out)
	}
}
