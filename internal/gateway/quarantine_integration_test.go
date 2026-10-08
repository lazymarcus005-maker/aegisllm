package gateway

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/quarantine"
)

func TestQuarantineIngressBlocksAliasesWithoutCrossTenantImpact(t *testing.T) {
	var calls atomic.Int32
	srv, gw, _ := newTestGateway(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	p := quarantine.DefaultPolicy()
	p.Default = quarantine.Rule{Reason: "default", Level: quarantine.LevelObserve, Scope: quarantine.ScopeSession, Threshold: 1, Window: time.Minute, Cooldown: time.Second, TTL: time.Minute}
	p.Rules = []quarantine.Rule{{Reason: quarantine.ReasonOperatorAction, Level: quarantine.LevelIsolate, Scope: quarantine.ScopeUser, Threshold: 1, Window: time.Minute, Cooldown: time.Second, TTL: time.Minute}}
	manager, err := quarantine.NewManager(quarantine.NewMemoryStore(), p, true)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetQuarantine(manager)
	if _, err := manager.Emergency(context.Background(), quarantine.Identity{Tenant: "tenant-a", Application: "app", Subject: "user-a"}, quarantine.Resource{}, quarantine.ScopeUser, quarantine.LevelIsolate, "operator", "contain", true); err != nil {
		t.Fatal(err)
	}
	request := func(tenant, path string) int {
		body := cleanRequest
		if path == "/v1/responses" {
			body = `{"model":"m","input":"hello"}`
		}
		req, _ := http.NewRequest(http.MethodPost, gw.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-Id", tenant)
		req.Header.Set("X-Application-Id", "app")
		req.Header.Set("X-User-Id", "user-a")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := request("tenant-a", "/v1/responses"); got != http.StatusForbidden {
		t.Fatalf("quarantined alias status=%d", got)
	}
	if got := request("tenant-b", "/v1/responses"); got != http.StatusOK {
		t.Fatalf("cross-tenant status=%d", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected upstream calls=%d", calls.Load())
	}
}
