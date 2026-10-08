package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/tokenization"
)

func TestScopedPipelineOnlyRestoresWithinVerifiedResponseScope(t *testing.T) {
	pipe, _ := newRealPipeline(t)
	pipe.SetSecurityMode(ModeEnforce)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := tokenization.NewCrypto(key)
	if err != nil {
		t.Fatal(err)
	}
	backend := tokenization.NewInMemoryVault()
	scoped, err := tokenization.NewScopedVault(backend, cipher, tokenization.SecureVaultOptions{RequireSession: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	pipe.SetScopedTokenStore(scoped)
	env, err := NormalizerFor("/v1/chat/completions").ParseRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"โทร 0812345678"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	env.Tenant, env.Application, env.User.Subject = "tenant-a", "app-a", "user-a"
	env.Target.Provider = "cloud"
	env.Metadata["session_binding"] = "sid-a"
	decision, err := pipe.ProcessRequestContext(context.Background(), env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionTokenize || len(decision.Transformations) != 1 {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	placeholder := decision.Transformations[0].Replacement
	response := []byte(`{"model":"m","choices":[{"message":{"role":"assistant","content":"call ` + placeholder + `"}}]}`)
	out, err := pipe.ProcessResponse(env, response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.TransformedBody), "0812345678") {
		t.Fatalf("verified response was not restored: %s", out.TransformedBody)
	}

	other := *env
	other.Metadata = map[string]string{}
	for k, v := range env.Metadata {
		other.Metadata[k] = v
	}
	other.Metadata["session_binding"] = "sid-b"
	denied, err := pipe.ProcessResponse(&other, response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(denied.TransformedBody), "0812345678") {
		t.Fatal("cross-session value restored")
	}
}
