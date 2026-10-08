package tokenization

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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
	Namespace     string    `json:"namespace"`
	Token         string    `json:"token"` // e.g. TH_CITIZEN_ID_001 (no raw value encoded)
	Type          string    `json:"type"`  // finding subtype
	Ciphertext    []byte    `json:"ciphertext"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Application   string    `json:"application,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	ScopeDigest   string    `json:"scope_digest,omitempty"`
	IndexDigest   string    `json:"index_digest,omitempty"`
	Purpose       string    `json:"purpose,omitempty"`
	DataCategory  string    `json:"data_category,omitempty"`
	KeyID         string    `json:"key_id,omitempty"`
	SingleUse     bool      `json:"single_use,omitempty"`
	MaxRetrievals int       `json:"max_retrievals,omitempty"`
	Retrievals    int       `json:"retrievals,omitempty"`
	IdleExpiresAt time.Time `json:"idle_expires_at,omitempty"`
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
	index map[string]map[string]struct{}
	clock func() time.Time
}

func NewInMemoryVault() *InMemoryVault {
	return &InMemoryVault{recs: map[string]VaultRecord{}, index: map[string]map[string]struct{}{}, clock: time.Now}
}

// SetClock overrides time for TTL tests.
func (v *InMemoryVault) SetClock(clock func() time.Time) { v.mu.Lock(); v.clock = clock; v.mu.Unlock() }

func vaultKey(namespace, token string) string { return namespace + "\x00" + token }

func (v *InMemoryVault) Put(_ context.Context, rec VaultRecord) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	key := vaultKey(rec.Namespace, rec.Token)
	v.recs[key] = rec
	if rec.IndexDigest != "" {
		if v.index[rec.IndexDigest] == nil {
			v.index[rec.IndexDigest] = map[string]struct{}{}
		}
		v.index[rec.IndexDigest][key] = struct{}{}
	}
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

// Retrieve atomically enforces the record's retrieval policy. It is used by
// the scoped runtime and intentionally keeps the legacy Get contract intact.
func (v *InMemoryVault) Retrieve(_ context.Context, namespace, token string) (VaultRecord, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	key := vaultKey(namespace, token)
	rec, ok := v.recs[key]
	if !ok || v.clock().After(rec.ExpiresAt) || (!rec.IdleExpiresAt.IsZero() && v.clock().After(rec.IdleExpiresAt)) {
		if ok {
			delete(v.recs, key)
		}
		return VaultRecord{}, false, nil
	}
	limit := rec.MaxRetrievals
	if rec.SingleUse && (limit == 0 || limit > 1) {
		limit = 1
	}
	if limit > 0 && rec.Retrievals >= limit {
		return VaultRecord{}, false, ErrRetrievalLimit
	}
	rec.Retrievals++
	v.recs[key] = rec
	return rec, true, nil
}

func (v *InMemoryVault) RevokeIndex(_ context.Context, index string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	for key := range v.index[index] {
		delete(v.recs, key)
	}
	delete(v.index, index)
	return nil
}

// RedisVault persists records in Redis with native TTL. Key names contain
// namespace and token label only — never raw values (T-020).
type RedisVault struct {
	rdb        redis.UniversalClient
	prefix     string
	defaultTTL time.Duration
	keyMAC     []byte
}

var redisRetrieveScript = redis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return {0, ''} end
local count = tonumber(redis.call('GET', KEYS[2]) or '0')
local limit = tonumber(ARGV[1])
if limit > 0 and count >= limit then return {2, ''} end
redis.call('INCR', KEYS[2])
redis.call('PEXPIRE', KEYS[2], ARGV[2])
return {1, value}
`)

func NewRedisVault(rdb redis.UniversalClient, prefix string, defaultTTL time.Duration) *RedisVault {
	if prefix == "" {
		prefix = "tokvault"
	}
	macKey := sha256.Sum256([]byte("aegisllm/redis-vault-key/" + prefix))
	return &RedisVault{rdb: rdb, prefix: prefix, defaultTTL: defaultTTL, keyMAC: macKey[:]}
}

func (v *RedisVault) key(namespace, token string) string {
	mac := hmac.New(sha256.New, v.keyMAC)
	_, _ = mac.Write([]byte(namespace))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(token))
	return fmt.Sprintf("%s:%x", v.prefix, mac.Sum(nil))
}

func (v *RedisVault) Put(ctx context.Context, rec VaultRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	ttl := time.Until(rec.ExpiresAt)
	if !rec.IdleExpiresAt.IsZero() && time.Until(rec.IdleExpiresAt) < ttl {
		ttl = time.Until(rec.IdleExpiresAt)
	}
	if ttl <= 0 {
		ttl = v.defaultTTL
	}
	key := v.key(rec.Namespace, rec.Token)
	if err := v.rdb.Set(ctx, key, data, ttl).Err(); err != nil {
		return err
	}
	if rec.IndexDigest != "" {
		if err := v.rdb.SAdd(ctx, v.indexKey(rec.IndexDigest), key).Err(); err != nil {
			return err
		}
		_ = v.rdb.Expire(ctx, v.indexKey(rec.IndexDigest), ttl).Err()
	}
	return nil
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
	if time.Now().After(rec.ExpiresAt) || (!rec.IdleExpiresAt.IsZero() && time.Now().After(rec.IdleExpiresAt)) {
		return VaultRecord{}, false, nil
	}
	return rec, true, nil
}

func (v *RedisVault) Retrieve(ctx context.Context, namespace, token string) (VaultRecord, bool, error) {
	key := v.key(namespace, token)
	countKey := key + ":r"
	var limit int
	// The record is read first only to obtain bounded policy metadata; the
	// counter update itself is performed atomically by Redis Lua.
	rec, ok, err := v.Get(ctx, namespace, token)
	if err != nil || !ok {
		return VaultRecord{}, ok, err
	}
	limit = rec.MaxRetrievals
	if rec.SingleUse && (limit == 0 || limit > 1) {
		limit = 1
	}
	result, err := redisRetrieveScript.Run(ctx, v.rdb, []string{key, countKey}, limit, maxInt64(1, int64(time.Until(rec.ExpiresAt)/time.Millisecond))).Result()
	if err != nil {
		return VaultRecord{}, false, err
	}
	items, ok := result.([]interface{})
	if !ok || len(items) != 2 {
		return VaultRecord{}, false, errors.New("vault retrieval failed")
	}
	status, _ := redisInt(items[0])
	if status == 2 {
		return VaultRecord{}, false, ErrRetrievalLimit
	}
	if status != 1 {
		return VaultRecord{}, false, nil
	}
	if n, err := v.rdb.Get(ctx, countKey).Int(); err == nil {
		rec.Retrievals = n
	}
	return rec, true, nil
}

func (v *RedisVault) RevokeIndex(ctx context.Context, index string) error {
	indexKey := v.indexKey(index)
	members, err := v.rdb.SMembers(ctx, indexKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	if len(members) > 0 {
		keys := make([]string, 0, len(members)*2+1)
		keys = append(keys, indexKey)
		for _, key := range members {
			keys = append(keys, key, key+":r")
		}
		if err := v.rdb.Del(ctx, keys...).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (v *RedisVault) indexKey(index string) string {
	mac := hmac.New(sha256.New, v.keyMAC)
	_, _ = mac.Write([]byte("index\x00" + index))
	return fmt.Sprintf("%s:%x", v.prefix, mac.Sum(nil))
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func redisInt(value interface{}) (int, bool) {
	switch n := value.(type) {
	case int64:
		return int(n), true
	case int:
		return n, true
	case string:
		var out int
		_, err := fmt.Sscan(n, &out)
		return out, err == nil
	default:
		return 0, false
	}
}

// TokenLabel extracts the vault token from a <TYPE_001> placeholder.
func TokenLabel(placeholder string) string {
	return strings.TrimSuffix(strings.TrimPrefix(placeholder, "<"), ">")
}
