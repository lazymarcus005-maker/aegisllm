package tokenization

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestCryptoSealOpenRoundTrip(t *testing.T) {
	c, err := NewCrypto(testKey())
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0812345678")
	blob, err := c.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, secret) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := c.Open(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip mismatch: %q", got)
	}
	// Two seals of the same value must differ (fresh data keys).
	blob2, _ := c.Seal(secret)
	if bytes.Equal(blob, blob2) {
		t.Fatal("seals must be randomized")
	}
}

func TestCryptoRejectsWrongKeyAndShortKeys(t *testing.T) {
	c, _ := NewCrypto(testKey())
	blob, _ := c.Seal([]byte("value"))

	other := make([]byte, 32)
	other[31] = 1
	c2, _ := NewCrypto(other)
	if _, err := c2.Open(blob); err == nil {
		t.Fatal("wrong key must fail to open")
	}
	if _, err := NewCrypto([]byte("short")); err == nil {
		t.Fatal("short key must be rejected")
	}
}

func TestInMemoryVaultTTLAndIsolation(t *testing.T) {
	v := NewInMemoryVault()
	now := time.Now()
	v.SetClock(func() time.Time { return now })

	rec := VaultRecord{
		Namespace: "req-1", Token: "PHONE_001", Type: "PHONE_NUMBER",
		Ciphertext: []byte{1, 2, 3}, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := v.Put(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	// Namespace isolation: same token in another namespace is invisible.
	if _, ok, _ := v.Get(context.Background(), "req-2", "PHONE_001"); ok {
		t.Fatal("namespace isolation violated")
	}
	if _, ok, _ := v.Get(context.Background(), "req-1", "PHONE_001"); !ok {
		t.Fatal("record must be readable before expiry")
	}
	now = now.Add(2 * time.Hour)
	if _, ok, _ := v.Get(context.Background(), "req-1", "PHONE_001"); ok {
		t.Fatal("record must be expired after TTL")
	}
}

func TestRedisVaultRoundTripAndTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	v := NewRedisVault(client, "tokvault", time.Hour)

	now := time.Now()
	rec := VaultRecord{
		Namespace: "req-1", Token: "TH_CITIZEN_ID_001", Type: "TH_CITIZEN_ID",
		Ciphertext: []byte{9, 8, 7}, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := v.Put(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := v.Get(context.Background(), "req-1", "TH_CITIZEN_ID_001")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if string(got.Ciphertext) != string(rec.Ciphertext) {
		t.Fatal("ciphertext mismatch")
	}
	if _, ok, _ := v.Get(context.Background(), "req-2", "TH_CITIZEN_ID_001"); ok {
		t.Fatal("namespace isolation violated")
	}
	mr.FastForward(2 * time.Hour)
	if _, ok, _ := v.Get(context.Background(), "req-1", "TH_CITIZEN_ID_001"); ok {
		t.Fatal("record must expire via redis TTL")
	}
}

func TestReidentifierAuthorization(t *testing.T) {
	c, _ := NewCrypto(testKey())
	v := NewInMemoryVault()
	r := NewReidentifier(v, c)

	value := "0812345678"
	blob, _ := c.Seal([]byte(value))
	now := time.Now()
	err := v.Put(context.Background(), VaultRecord{
		Namespace: "req-1", Token: "PHONE_001", Type: "PHONE_NUMBER",
		Ciphertext: blob, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		Application: "agent-x", Subject: "user-123",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Authorized caller: same application as recorded at issuance.
	got, err := r.Reidentify(context.Background(), "req-1", "PHONE_001", Caller{Application: "agent-x", Subject: "user-123"})
	if err != nil || got != value {
		t.Fatalf("authorized re-identification failed: %q %v", got, err)
	}

	// Different application: denied.
	if _, err := r.Reidentify(context.Background(), "req-1", "PHONE_001", Caller{Application: "other-app"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}

	// Namespace mismatch and unknown tokens: not found.
	if _, err := r.Reidentify(context.Background(), "req-2", "PHONE_001", Caller{Application: "agent-x"}); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound, got %v", err)
	}
	// Model-invented placeholders must not resolve.
	if _, err := r.Reidentify(context.Background(), "req-1", "PERSON_999", Caller{Application: "agent-x"}); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("invented token must not resolve, got %v", err)
	}
}

func TestTokenLabel(t *testing.T) {
	if TokenLabel("<TH_CITIZEN_ID_001>") != "TH_CITIZEN_ID_001" {
		t.Fatal("label extraction wrong")
	}
	if strings.Contains(TokenLabel("<PHONE_002>"), "<") {
		t.Fatal("brackets must be stripped")
	}
}
