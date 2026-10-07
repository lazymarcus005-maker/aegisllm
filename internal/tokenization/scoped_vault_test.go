package tokenization

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func secureTestVault(t *testing.T, opts SecureVaultOptions) (*ScopedVault, *InMemoryVault) {
	t.Helper()
	c, err := NewCrypto(testKey())
	if err != nil {
		t.Fatal(err)
	}
	mem := NewInMemoryVault()
	if opts.TTL == 0 {
		opts.TTL = time.Hour
	}
	v, err := NewScopedVault(mem, c, opts)
	if err != nil {
		t.Fatal(err)
	}
	return v, mem
}

func secureTestScope(t *testing.T, v *ScopedVault, in ScopeInput) Scope {
	t.Helper()
	s, err := NewScope(in, v.MACKey())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScopedVaultBindsEveryScopeDimension(t *testing.T) {
	v, _ := secureTestVault(t, SecureVaultOptions{RequireSession: true})
	base := ScopeInput{Tenant: "tenant-a", Application: "app-a", Subject: "subject-a", SessionID: "sid-a", PolicyID: "policy-a", PolicyVersion: 7, Purpose: PurposeResponse, DataCategory: "PII:PHONE_NUMBER"}
	scope := secureTestScope(t, v, base)
	label, err := v.Issue(context.Background(), scope, "0812345678")
	if err != nil {
		t.Fatal(err)
	}
	if label == "<PII:PHONE_NUMBER_001>" || label == "<PHONE_NUMBER_001>" {
		t.Fatal("placeholder is enumerable")
	}
	if _, err := v.Retrieve(context.Background(), scope, label); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ScopeInput){
		"tenant":      func(in *ScopeInput) { in.Tenant = "tenant-b" },
		"application": func(in *ScopeInput) { in.Application = "app-b" },
		"subject":     func(in *ScopeInput) { in.Subject = "subject-b" },
		"session":     func(in *ScopeInput) { in.SessionID = "sid-b" },
		"policy":      func(in *ScopeInput) { in.PolicyID = "policy-b" },
		"version":     func(in *ScopeInput) { in.PolicyVersion++ },
		"purpose":     func(in *ScopeInput) { in.Purpose = "other" },
		"category":    func(in *ScopeInput) { in.DataCategory = "PII:EMAIL" },
	} {
		in := base
		change(&in)
		wrong := secureTestScope(t, v, in)
		if _, err := v.Retrieve(context.Background(), wrong, label); !errors.Is(err, ErrInvalidPlaceholder) {
			t.Fatalf("%s mismatch returned %v", name, err)
		}
	}
}

func TestPlaceholderTamperAndVersionErrorsAreUniform(t *testing.T) {
	v, _ := secureTestVault(t, SecureVaultOptions{})
	scope := secureTestScope(t, v, ScopeInput{Tenant: "t", Application: "a", Subject: "u", SessionID: "s", PolicyID: "p", PolicyVersion: 1, Purpose: PurposeResponse, DataCategory: "PII:X"})
	label, err := v.Issue(context.Background(), scope, "value")
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{label[:len(label)-2] + "xx>", "<v2.bad.bad.bad>", "<v1.bad>", "<v1.000000000000000000000000000000000000.00000000.00000000000000000000000000000000>"}
	for _, candidate := range bad {
		if _, err := v.Retrieve(context.Background(), scope, candidate); !errors.Is(err, ErrInvalidPlaceholder) {
			t.Fatalf("%q returned %v", candidate, err)
		}
	}
}

func TestScopedVaultSingleUseIsAtomic(t *testing.T) {
	v, _ := secureTestVault(t, SecureVaultOptions{SingleUse: true})
	scope := secureTestScope(t, v, ScopeInput{Tenant: "t", Application: "a", Subject: "u", SessionID: "s", PolicyID: "p", PolicyVersion: 1, Purpose: PurposeResponse, DataCategory: "PII:X"})
	label, err := v.Issue(context.Background(), scope, "value")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Retrieve(context.Background(), scope, label); err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("single-use retrievals=%d", success)
	}
}

func TestScopedVaultRevokeSessionAndAADIsolation(t *testing.T) {
	v, _ := secureTestVault(t, SecureVaultOptions{})
	base := ScopeInput{Tenant: "t", Application: "a", Subject: "u", SessionID: "s", PolicyID: "p", PolicyVersion: 1, Purpose: PurposeResponse, DataCategory: "PII:X"}
	scope := secureTestScope(t, v, base)
	label, err := v.Issue(context.Background(), scope, "value")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RevokeSession(context.Background(), "t", "a", "u", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Retrieve(context.Background(), scope, label); !errors.Is(err, ErrInvalidPlaceholder) {
		t.Fatalf("revoked record returned %v", err)
	}
	wrong := base
	wrong.SessionID = "other"
	if _, err := v.Retrieve(context.Background(), secureTestScope(t, v, wrong), label); !errors.Is(err, ErrInvalidPlaceholder) {
		t.Fatalf("wrong AAD returned %v", err)
	}
}

func TestRedisScopedVaultAtomicRetrievalAndRevocation(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	c, _ := NewCrypto(testKey())
	backend := NewRedisVault(rdb, "tokvault", time.Hour)
	v, err := NewScopedVault(backend, c, SecureVaultOptions{SingleUse: true})
	if err != nil {
		t.Fatal(err)
	}
	scope := secureTestScope(t, v, ScopeInput{Tenant: "t", Application: "a", Subject: "u", SessionID: "s", PolicyID: "p", PolicyVersion: 1, Purpose: PurposeResponse, DataCategory: "PII:X"})
	label, err := v.Issue(context.Background(), scope, "value")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Retrieve(context.Background(), scope, label); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Retrieve(context.Background(), scope, label); !errors.Is(err, ErrRetrievalLimit) {
		t.Fatalf("expected atomic limit, got %v", err)
	}
	label, err = v.Issue(context.Background(), scope, "value-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RevokeSession(context.Background(), "t", "a", "u", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Retrieve(context.Background(), scope, label); !errors.Is(err, ErrInvalidPlaceholder) {
		t.Fatalf("expected revoked record, got %v", err)
	}
	for _, key := range mr.Keys() {
		if strings.Contains(key, "tenant") || strings.Contains(key, "value") || strings.Contains(key, label) {
			t.Fatalf("raw vault material in Redis key: %q", key)
		}
	}
}

func TestKeyringAADAndRetainedKeyRead(t *testing.T) {
	oldKey := bytes.Repeat([]byte{3}, 32)
	newKey := bytes.Repeat([]byte{4}, 32)
	old, err := NewKeyring("old", map[string][]byte{"old": oldKey, "new": newKey})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := old.SealAAD([]byte("secret"), []byte("scope-aad"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewKeyring("new", map[string][]byte{"old": oldKey, "new": newKey})
	if err != nil {
		t.Fatal(err)
	}
	got, err := rotated.OpenAAD(blob, []byte("scope-aad"))
	if err != nil || string(got) != "secret" {
		t.Fatalf("retained AAD read: %q %v", got, err)
	}
	if _, err := rotated.OpenAAD(blob, []byte("wrong")); err == nil {
		t.Fatal("wrong AAD decrypted")
	}
	withoutOld, _ := NewKeyring("new", map[string][]byte{"new": newKey})
	if _, err := withoutOld.OpenAAD(blob, []byte("scope-aad")); err == nil {
		t.Fatal("removed key decrypted old record")
	}
}

func TestExternalRedisScopedVaultSmoke(t *testing.T) {
	addr := os.Getenv("AEGIS_REDIS_ADDR")
	if addr == "" {
		t.Skip("AEGIS_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	defer rdb.Close()
	if err := rdb.FlushDB(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	oldKey := bytes.Repeat([]byte{7}, 32)
	newKey := bytes.Repeat([]byte{8}, 32)
	old, _ := NewKeyring("old", map[string][]byte{"old": oldKey, "new": newKey})
	v1, err := NewScopedVault(NewRedisVault(rdb, "smoke-vault", time.Hour), old, SecureVaultOptions{SingleUse: false})
	if err != nil {
		t.Fatal(err)
	}
	base := ScopeInput{Tenant: "smoke-tenant", Application: "smoke-app", Subject: "smoke-user", SessionID: "smoke-session", PolicyID: "smoke-policy", PolicyVersion: 1, Purpose: PurposeResponse, DataCategory: "PII:PHONE"}
	scope := secureTestScope(t, v1, base)
	label, err := v1.Issue(context.Background(), scope, "0812345678")
	if err != nil {
		t.Fatal(err)
	}
	other := base
	other.SessionID = "other-session"
	if _, err := v1.Retrieve(context.Background(), secureTestScope(t, v1, other), label); !errors.Is(err, ErrInvalidPlaceholder) {
		t.Fatalf("cross-session restore: %v", err)
	}
	rotated, _ := NewKeyring("new", map[string][]byte{"old": oldKey, "new": newKey})
	v2, err := NewScopedVault(NewRedisVault(rdb, "smoke-vault", time.Hour), rotated, SecureVaultOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v2.Retrieve(context.Background(), secureTestScope(t, v2, base), label); err != nil || got != "0812345678" {
		t.Fatalf("retained-key restore: %q %v", got, err)
	}
	if err := v2.RevokeSession(context.Background(), base.Tenant, base.Application, base.Subject, base.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Retrieve(context.Background(), secureTestScope(t, v2, base), label); !errors.Is(err, ErrInvalidPlaceholder) {
		t.Fatalf("revoked restore: %v", err)
	}
}
