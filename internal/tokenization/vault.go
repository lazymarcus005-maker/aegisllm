package tokenization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// VaultRecord is one token → ciphertext mapping. The raw value never appears
// in the record: only in the encrypted payload.
type VaultRecord struct {
	Namespace   string    `json:"namespace"`
	Token       string    `json:"token"` // e.g. TH_CITIZEN_ID_001 (no raw value encoded)
	Type        string    `json:"type"`  // finding subtype
	Ciphertext  []byte    `json:"ciphertext"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Application string    `json:"application,omitempty"`
	Subject     string    `json:"subject,omitempty"`
}

// Vault stores token mappings with TTL (PRIV-003). Implementations must not
// put raw values in key names or logs.
type Vault interface {
	Put(ctx context.Context, rec VaultRecord) error
	Get(ctx context.Context, namespace, token string) (VaultRecord, bool, error)
}

// InMemoryVault is the zero-dependency MVP store. Suitable for development;
// production deployments should use RedisVault.
type InMemoryVault struct {
	mu    sync.RWMutex
	recs  map[string]VaultRecord
	clock func() time.Time
}

func NewInMemoryVault() *InMemoryVault {
	return &InMemoryVault{recs: map[string]VaultRecord{}, clock: time.Now}
}

// SetClock overrides time for TTL tests.
func (v *InMemoryVault) SetClock(clock func() time.Time) { v.mu.Lock(); v.clock = clock; v.mu.Unlock() }

func vaultKey(namespace, token string) string { return namespace + "\x00" + token }

func (v *InMemoryVault) Put(_ context.Context, rec VaultRecord) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.recs[vaultKey(rec.Namespace, rec.Token)] = rec
	return nil
}

func (v *InMemoryVault) Get(_ context.Context, namespace, token string) (VaultRecord, bool, error) {
	v.mu.RLock()
	rec, ok := v.recs[vaultKey(namespace, token)]
	v.mu.RUnlock()
	if !ok {
		return VaultRecord{}, false, nil
	}
	if v.clock().After(rec.ExpiresAt) {
		return VaultRecord{}, false, nil
	}
	return rec, true, nil
}

// RedisVault persists records in Redis with native TTL. Key names contain
// namespace and token label only — never raw values (T-020).
type RedisVault struct {
	rdb        redis.UniversalClient
	prefix     string
	defaultTTL time.Duration
}

func NewRedisVault(rdb redis.UniversalClient, prefix string, defaultTTL time.Duration) *RedisVault {
	if prefix == "" {
		prefix = "tokvault"
	}
	return &RedisVault{rdb: rdb, prefix: prefix, defaultTTL: defaultTTL}
}

func (v *RedisVault) key(namespace, token string) string {
	return fmt.Sprintf("%s:%s:%s", v.prefix, namespace, token)
}

func (v *RedisVault) Put(ctx context.Context, rec VaultRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	ttl := time.Until(rec.ExpiresAt)
	if ttl <= 0 {
		ttl = v.defaultTTL
	}
	return v.rdb.Set(ctx, v.key(rec.Namespace, rec.Token), data, ttl).Err()
}

func (v *RedisVault) Get(ctx context.Context, namespace, token string) (VaultRecord, bool, error) {
	data, err := v.rdb.Get(ctx, v.key(namespace, token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return VaultRecord{}, false, nil
	}
	if err != nil {
		return VaultRecord{}, false, err
	}
	var rec VaultRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return VaultRecord{}, false, err
	}
	if time.Now().After(rec.ExpiresAt) {
		return VaultRecord{}, false, nil
	}
	return rec, true, nil
}

// TokenLabel extracts the vault token from a <TYPE_001> placeholder.
func TokenLabel(placeholder string) string {
	return strings.TrimSuffix(strings.TrimPrefix(placeholder, "<"), ">")
}
