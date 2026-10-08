package quarantine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func testPolicy(scope, level string, threshold int) Policy {
	p := DefaultPolicy()
	p.Default = Rule{Reason: "default", Level: LevelObserve, Scope: ScopeSession, Threshold: 1, Window: time.Minute, Cooldown: time.Second, TTL: time.Minute}
	p.Rules = []Rule{{Reason: ReasonSecretExfiltration, Level: level, Scope: scope, Threshold: threshold, Window: time.Minute, Cooldown: time.Second, TTL: time.Minute}}
	if scope == ScopeTenant || scope == ScopeProvider {
		p.Rules[0].AllowBroad = true
	}
	return p
}

func trustedSignal(tenant, subject, key string) Signal {
	return Signal{Reason: ReasonSecretExfiltration, Identity: Identity{Tenant: tenant, Application: "app", Subject: subject, Session: "session"}, Evidence: []EvidenceRef{{Kind: "finding", Digest: strings.Repeat("a", 64)}}, IdempotencyKey: key, Trusted: true, Policy: Snapshot{ID: "policy", Version: 1}}
}

func newTestManager(t *testing.T, p Policy) (*Manager, *MemoryStore, *time.Time) {
	t.Helper()
	store := NewMemoryStore()
	m, err := NewManager(store, p, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	m.SetClock(func() time.Time { return now })
	return m, store, &now
}

func TestThresholdDuplicateAndTenantIsolation(t *testing.T) {
	m, _, _ := newTestManager(t, testPolicy(ScopeUser, LevelIsolate, 2))
	sig := trustedSignal("tenant-a", "user-a", "one")
	if _, created, err := m.Observe(context.Background(), sig); err != nil || created {
		t.Fatalf("first signal created=%v err=%v", created, err)
	}
	if _, created, err := m.Observe(context.Background(), sig); err != nil || created {
		t.Fatalf("duplicate created=%v err=%v", created, err)
	}
	sig.IdempotencyKey = "two"
	state, created, err := m.Observe(context.Background(), sig)
	if err != nil || !created {
		t.Fatalf("threshold state created=%v err=%v", created, err)
	}
	if state.TenantDigest == "tenant-a" || strings.Contains(state.ID, "tenant-a") {
		t.Fatal("raw tenant identifier persisted")
	}
	decision, err := m.Check(context.Background(), Identity{Tenant: "tenant-a", Application: "app", Subject: "user-a"}, Resource{})
	if err != nil || decision.Allowed {
		t.Fatalf("same tenant was not contained: %+v %v", decision, err)
	}
	other, err := m.Check(context.Background(), Identity{Tenant: "tenant-b", Application: "app", Subject: "user-a"}, Resource{})
	if err != nil || !other.Allowed {
		t.Fatalf("cross-tenant impact: %+v %v", other, err)
	}
}

func TestUnauthenticatedCheckDoesNotCreateBroadContainment(t *testing.T) {
	m, _, _ := newTestManager(t, testPolicy(ScopeTenant, LevelDisable, 1))
	decision, err := m.Check(context.Background(), Identity{}, Resource{Provider: "cloud"})
	if err != nil || !decision.Allowed {
		t.Fatalf("no-identity probe should remain uncontained: %+v %v", decision, err)
	}
}

func TestForgedSignalRejectedAndBroadConfirmation(t *testing.T) {
	m, _, _ := newTestManager(t, testPolicy(ScopeTenant, LevelDisable, 3))
	sig := trustedSignal("tenant-a", "user-a", "one")
	sig.Trusted = false
	if _, _, err := m.Observe(context.Background(), sig); !errors.Is(err, ErrInvalidSignal) {
		t.Fatalf("forged signal err=%v", err)
	}
	id := Identity{Tenant: "tenant-a", Application: "app"}
	if _, err := m.Emergency(context.Background(), id, Resource{Provider: "cloud"}, ScopeProvider, LevelDisable, "operator", "contain provider", false); !errors.Is(err, ErrConfirmation) {
		t.Fatalf("confirmation err=%v", err)
	}
	state, err := m.Emergency(context.Background(), id, Resource{Provider: "cloud"}, ScopeProvider, LevelDisable, "operator", "contain provider", true)
	if err != nil || state.Scope != ScopeProvider {
		t.Fatalf("emergency state=%+v err=%v", state, err)
	}
	if d, _ := m.Check(context.Background(), id, Resource{Provider: "cloud"}); d.Allowed {
		t.Fatal("provider emergency did not apply")
	}
}

func TestConcurrentTransitionsAndStaleRevision(t *testing.T) {
	m, _, _ := newTestManager(t, testPolicy(ScopeUser, LevelIsolate, 1))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sig := trustedSignal("tenant-a", "user-a", "signal-"+string(rune(i+65)))
			_, _, _ = m.Observe(context.Background(), sig)
		}(i)
	}
	wg.Wait()
	summary, err := m.ListSummary(context.Background())
	if err != nil || summary.Active != 1 {
		t.Fatalf("concurrent summary=%+v err=%v", summary, err)
	}
	states, _ := m.store.List(context.Background())
	state := states[0]
	if _, err := m.Acknowledge(context.Background(), state.ID, state.Revision-1, "operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision err=%v", err)
	}
	if _, err := m.Acknowledge(context.Background(), state.ID, state.Revision, "operator"); err != nil {
		t.Fatal(err)
	}
}

func TestExpiryProbationAndStoreOutage(t *testing.T) {
	m, store, now := newTestManager(t, testPolicy(ScopeProvider, LevelDisable, 1))
	sig := trustedSignal("tenant-a", "user-a", "one")
	sig.Resource.Provider = "cloud"
	state, _, err := m.Observe(context.Background(), sig)
	if err != nil {
		t.Fatal(err)
	}
	*now = state.ExpiresAt.Add(time.Second)
	if d, err := m.Check(context.Background(), sig.Identity, sig.Resource); err != nil || d.Allowed || d.Code != "QUARANTINE_PROBATION" {
		t.Fatalf("probation decision=%+v err=%v", d, err)
	}
	m.SetHealthGate(func(Resource) bool { return true })
	if d, err := m.Check(context.Background(), sig.Identity, sig.Resource); err != nil || d.Allowed {
		t.Fatalf("probation silently restored risky provider: %+v %v", d, err)
	}
	*now = state.ExpiresAt.Add(11 * time.Minute)
	if d, err := m.Check(context.Background(), sig.Identity, sig.Resource); err != nil || !d.Allowed {
		t.Fatalf("green probation did not release: %+v %v", d, err)
	}
	store.SetFailure(true)
	if _, err := m.Check(context.Background(), sig.Identity, sig.Resource); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("outage err=%v", err)
	}
}

func TestPrivacySafeStateJSON(t *testing.T) {
	m, _, _ := newTestManager(t, testPolicy(ScopeUser, LevelIsolate, 1))
	sig := trustedSignal("tenant-secret", "user-secret", "one")
	state, _, err := m.Observe(context.Background(), sig)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "tenant-secret") || strings.Contains(string(b), "user-secret") || strings.Contains(string(b), "one") {
		t.Fatalf("privacy leak: %s", b)
	}
}

func TestSharedStoreRestartRetainsContainment(t *testing.T) {
	store := NewMemoryStore()
	p := testPolicy(ScopeUser, LevelIsolate, 1)
	m1, err := NewManager(store, p, true)
	if err != nil {
		t.Fatal(err)
	}
	sig := trustedSignal("tenant-a", "user-a", "restart")
	if _, _, err := m1.Observe(context.Background(), sig); err != nil {
		t.Fatal(err)
	}
	m2, err := NewManager(store, p, true)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := m2.Check(context.Background(), sig.Identity, Resource{})
	if err != nil || decision.Allowed {
		t.Fatalf("restart lost quarantine: %+v %v", decision, err)
	}
}

func TestNarrowCreatesScopedReplacementWithoutBroadLeak(t *testing.T) {
	p := testPolicy(ScopeApplication, LevelIsolate, 1)
	m, _, _ := newTestManager(t, p)
	id := Identity{Tenant: "tenant-a", Application: "app", Subject: "user-a", Session: "session-a"}
	state, err := m.Emergency(context.Background(), id, Resource{}, ScopeApplication, LevelIsolate, "operator", "narrow", true)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := m.Narrow(context.Background(), state.ID, state.Revision, ScopeUser, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Scope != ScopeUser {
		t.Fatalf("scope=%s", replacement.Scope)
	}
	if d, _ := m.Check(context.Background(), id, Resource{}); d.Allowed {
		t.Fatal("replacement did not contain original subject")
	}
	if d, _ := m.Check(context.Background(), Identity{Tenant: "tenant-a", Application: "app", Subject: "other"}, Resource{}); !d.Allowed {
		t.Fatal("narrowed quarantine affected another user")
	}
}

func FuzzSignalValidation(f *testing.F) {
	f.Add("secret_exfiltration", "tenant", "subject", true, "one")
	f.Add("not-a-reason", "", "", false, "")
	f.Fuzz(func(t *testing.T, reason, tenant, subject string, trusted bool, key string) {
		store := NewMemoryStore()
		m, err := NewManager(store, testPolicy(ScopeUser, LevelIsolate, 2), true)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _ = m.Observe(context.Background(), Signal{Reason: reason, Identity: Identity{Tenant: tenant, Application: "app", Subject: subject}, Trusted: trusted, IdempotencyKey: key, Evidence: []EvidenceRef{{Kind: "f", Digest: strings.Repeat("a", 64)}}})
	})
}
