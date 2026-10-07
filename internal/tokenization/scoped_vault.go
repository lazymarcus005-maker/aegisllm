package tokenization

// This file is the P1.9 runtime boundary. The older Vault/Reidentifier types
// remain solely for development and migration compatibility; production code
// uses ScopedVault and never addresses a record by request ID alone.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ScopeVersion       = 1
	PlaceholderVersion = 1
	PurposeResponse    = "trusted_response"
)

var (
	ErrInvalidPlaceholder = errors.New("invalid token placeholder")
	ErrScopeRequired      = errors.New("verified session binding required")
	ErrRetrievalLimit     = errors.New("token retrieval limit reached")
	ErrVaultUnavailable   = errors.New("token vault unavailable")
	ErrQuotaExceeded      = errors.New("token vault quota exceeded")
	ErrValueTooLarge      = errors.New("token value exceeds configured limit")
)

// Scope is assembled from verified gateway identity and policy state. Subject
// and session are represented by keyed digests so a serialized record never
// contains raw identity material.
type Scope struct {
	Version       int
	Tenant        string
	Application   string
	SubjectDigest string
	SessionDigest string
	PolicyID      string
	PolicyVersion int
	Purpose       string
	DataCategory  string
}

// ScopeInput contains verified values at the process boundary. It is never a
// record format and should not be logged.
type ScopeInput struct {
	Tenant, Application, Subject, SessionID string
	PolicyID, Purpose, DataCategory         string
	PolicyVersion                           int
}

func NewScope(input ScopeInput, macKey []byte) (Scope, error) {
	if len(macKey) == 0 || input.Tenant == "" || input.Application == "" || input.Subject == "" || input.SessionID == "" || input.PolicyID == "" || input.Purpose == "" || input.DataCategory == "" {
		return Scope{}, ErrScopeRequired
	}
	if input.PolicyVersion <= 0 {
		return Scope{}, ErrScopeRequired
	}
	return Scope{Version: ScopeVersion, Tenant: input.Tenant, Application: input.Application,
		SubjectDigest: keyedDigest(macKey, "subject", input.Subject),
		SessionDigest: keyedDigest(macKey, "session", input.SessionID), PolicyID: input.PolicyID,
		PolicyVersion: input.PolicyVersion, Purpose: input.Purpose, DataCategory: input.DataCategory}, nil
}

func keyedDigest(key []byte, label, value string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(label))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))
}

func (s Scope) canonical(includeCategory bool) []byte {
	category := ""
	if includeCategory {
		category = s.DataCategory
	}
	return []byte(strings.Join([]string{string(rune(s.Version)), s.Tenant, s.Application, s.SubjectDigest,
		s.SessionDigest, s.PolicyID, itoa(s.PolicyVersion), s.Purpose, category}, "\x00"))
}

func itoa(value int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(value))
	return hex.EncodeToString(buf[:])
}

func (s Scope) digest(key []byte, includeCategory bool) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(s.canonical(includeCategory))
	return hex.EncodeToString(m.Sum(nil))
}

func (s Scope) fullDigest(key []byte) string  { return s.digest(key, true) }
func (s Scope) indexDigest(key []byte) string { return s.digest(key, false) }
func (s Scope) sessionIndex(key []byte) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte("session-index\x00"))
	_, _ = m.Write([]byte(s.Tenant + "\x00" + s.Application + "\x00" + s.SubjectDigest + "\x00" + s.SessionDigest))
	return hex.EncodeToString(m.Sum(nil))
}

type Placeholder struct {
	Label    string
	TokenID  string
	Category string
	Visible  bool
}

// PlaceholderCodec creates opaque, random, MAC-protected placeholders. The
// token ID is generated independently for every issuance.
type PlaceholderCodec struct {
	active   []byte
	retained [][]byte
}

func NewPlaceholderCodec(active []byte, retained [][]byte) (*PlaceholderCodec, error) {
	if len(active) == 0 {
		return nil, errors.New("placeholder key is required")
	}
	all := make([][]byte, 0, len(retained)+1)
	all = append(all, append([]byte(nil), active...))
	for _, key := range retained {
		if len(key) > 0 {
			all = append(all, append([]byte(nil), key...))
		}
	}
	return &PlaceholderCodec{active: append([]byte(nil), active...), retained: all}, nil
}

func (c *PlaceholderCodec) Issue(category string, visible bool) (string, error) {
	id := make([]byte, 18)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	idText := hex.EncodeToString(id)
	parts := []string{"v1"}
	if visible {
		category = safeCategory(category)
		if category == "" {
			visible = false
		} else {
			parts = append(parts, category)
		}
	}
	parts = append(parts, idText)
	checksum := crc32.ChecksumIEEE([]byte(strings.Join(parts, ".")))
	mac := hmac.New(sha256.New, c.active)
	_, _ = mac.Write([]byte(strings.Join(parts, ".")))
	parts = append(parts, hex.EncodeToString([]byte{byte(checksum >> 24), byte(checksum >> 16), byte(checksum >> 8), byte(checksum)}), hex.EncodeToString(mac.Sum(nil)[:16]))
	return "<" + strings.Join(parts, ".") + ">", nil
}

func safeCategory(value string) string {
	if value == "" || len(value) > 64 {
		return ""
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == ':') {
			return ""
		}
	}
	return value
}

func (c *PlaceholderCodec) Parse(label string) (Placeholder, error) {
	// Keep all parse failures on one path and perform the same bounded work for
	// malformed input; callers intentionally receive no reason detail.
	clean := label
	if strings.HasPrefix(clean, "<") && strings.HasSuffix(clean, ">") {
		clean = clean[1 : len(clean)-1]
	}
	parts := strings.Split(clean, ".")
	if len(parts) != 4 && len(parts) != 5 {
		return Placeholder{}, ErrInvalidPlaceholder
	}
	if parts[0] != "v1" || len(parts[len(parts)-2]) != 8 || len(parts[len(parts)-1]) != 32 || len(parts[len(parts)-3]) != 36 {
		return Placeholder{}, ErrInvalidPlaceholder
	}
	category, id := "", parts[1]
	if len(parts) == 5 {
		category, id = parts[1], parts[2]
		if safeCategory(category) == "" {
			return Placeholder{}, ErrInvalidPlaceholder
		}
	}
	if len(id) != 36 {
		return Placeholder{}, ErrInvalidPlaceholder
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return Placeholder{}, ErrInvalidPlaceholder
		}
	}
	base := strings.Join(parts[:len(parts)-2], ".")
	wantCRC := crc32.ChecksumIEEE([]byte(base))
	gotCRC, err := hex.DecodeString(parts[len(parts)-2])
	if err != nil || len(gotCRC) != 4 || !hmac.Equal(gotCRC, []byte{byte(wantCRC >> 24), byte(wantCRC >> 16), byte(wantCRC >> 8), byte(wantCRC)}) {
		return Placeholder{}, ErrInvalidPlaceholder
	}
	wantMAC, err := hex.DecodeString(parts[len(parts)-1])
	if err != nil || len(wantMAC) != 16 {
		return Placeholder{}, ErrInvalidPlaceholder
	}
	valid := false
	for _, key := range c.retained {
		m := hmac.New(sha256.New, key)
		_, _ = m.Write([]byte(base))
		valid = valid || hmac.Equal(wantMAC, m.Sum(nil)[:16])
	}
	if !valid {
		return Placeholder{}, ErrInvalidPlaceholder
	}
	return Placeholder{Label: clean, TokenID: id, Category: category, Visible: len(parts) == 5}, nil
}

type scopedBackend interface {
	Put(context.Context, VaultRecord) error
	Retrieve(context.Context, string, string) (VaultRecord, bool, error)
	RevokeIndex(context.Context, string) error
}

type SecureVaultOptions struct {
	MACKey               []byte
	RequireSession       bool
	TTL                  time.Duration
	IdleTTL              time.Duration
	MaxValueBytes        int
	MaxRecordsPerScope   int
	MaxRecordsPerTenant  int
	MaxRecordsPerUser    int
	MaxRecordsPerSession int
	MaxRetrievals        int
	SingleUse            bool
	VisibleCategory      bool
}

// ScopedVault is the only production re-identification implementation. It
// authenticates identity/policy/purpose in both the record key and AES-GCM
// AAD, and delegates atomic counters/indexes to Redis or memory backends.
type ScopedVault struct {
	backend                                              scopedBackend
	cipher                                               AADCipher
	keys                                                 PlaceholderKeyProvider
	macKey                                               []byte
	opts                                                 SecureVaultOptions
	mu                                                   sync.Mutex
	counts                                               map[string]int
	created, reads, denied, expired, revoked, keyVersion atomic.Uint64
}

type VaultStatus struct {
	Created    uint64 `json:"created,omitempty"`
	Read       uint64 `json:"read,omitempty"`
	Denied     uint64 `json:"denied,omitempty"`
	Expired    uint64 `json:"expired,omitempty"`
	Revoked    uint64 `json:"revoked,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty"`
}

func (v *ScopedVault) Status() VaultStatus {
	return VaultStatus{Created: v.created.Load(), Read: v.reads.Load(), Denied: v.denied.Load(), Expired: v.expired.Load(), Revoked: v.revoked.Load(), KeyVersion: v.keyVersion.Load()}
}

// MACKey is a process-local copy used to derive the same scope digest at the
// response boundary. It is never serialized or suitable for operator output.
func (v *ScopedVault) MACKey() []byte { return append([]byte(nil), v.macKey...) }

func NewScopedVault(backend Vault, cipher Cipher, opts SecureVaultOptions) (*ScopedVault, error) {
	b, ok := backend.(scopedBackend)
	if !ok {
		return nil, ErrVaultUnavailable
	}
	aad, ok := cipher.(AADCipher)
	if !ok {
		return nil, errors.New("scoped vault requires AES-GCM AAD cipher")
	}
	provider, ok := cipher.(PlaceholderKeyProvider)
	if !ok {
		return nil, errors.New("scoped vault placeholder key unavailable")
	}
	active, retained := provider.PlaceholderKeys()
	if len(opts.MACKey) == 0 {
		if stable, ok := cipher.(ScopeKeyProvider); ok {
			opts.MACKey = stable.ScopeKey()
		} else {
			opts.MACKey = active
		}
	}
	if _, err := NewPlaceholderCodec(active, retained); err != nil {
		return nil, err
	}
	if opts.TTL <= 0 {
		opts.TTL = 24 * time.Hour
	}
	if opts.MaxValueBytes <= 0 {
		opts.MaxValueBytes = 64 * 1024
	}
	if opts.MaxRetrievals <= 0 && !opts.SingleUse {
		opts.MaxRetrievals = 10
	}
	return &ScopedVault{backend: b, cipher: aad, keys: provider, macKey: append([]byte(nil), opts.MACKey...), opts: opts, counts: map[string]int{}}, nil
}

func (v *ScopedVault) currentCodec() (*PlaceholderCodec, error) {
	active, retained := v.keys.PlaceholderKeys()
	return NewPlaceholderCodec(active, retained)
}

func (v *ScopedVault) Issue(ctx context.Context, scope Scope, value string) (string, error) {
	if v.opts.RequireSession && scope.SessionDigest == "" {
		return "", ErrScopeRequired
	}
	if len(value) > v.opts.MaxValueBytes {
		return "", ErrValueTooLarge
	}
	if scope.Version != ScopeVersion {
		return "", ErrScopeRequired
	}
	index := scope.indexDigest(v.macKey)
	v.mu.Lock()
	if v.opts.MaxRecordsPerScope > 0 && v.counts[index] >= v.opts.MaxRecordsPerScope {
		v.mu.Unlock()
		return "", ErrQuotaExceeded
	}
	tenantKey := keyedDigest(v.macKey, "tenant", scope.Tenant)
	userKey := keyedDigest(v.macKey, "user", scope.SubjectDigest)
	if v.opts.MaxRecordsPerTenant > 0 && v.counts[tenantKey] >= v.opts.MaxRecordsPerTenant {
		v.mu.Unlock()
		return "", ErrQuotaExceeded
	}
	if v.opts.MaxRecordsPerUser > 0 && v.counts[userKey] >= v.opts.MaxRecordsPerUser {
		v.mu.Unlock()
		return "", ErrQuotaExceeded
	}
	v.counts[tenantKey]++
	v.counts[userKey]++
	if v.opts.MaxRecordsPerSession > 0 {
		sessionKey := scope.sessionIndex(v.macKey)
		if v.counts[sessionKey] >= v.opts.MaxRecordsPerSession {
			v.mu.Unlock()
			return "", ErrQuotaExceeded
		}
		v.counts[sessionKey]++
	}
	v.counts[index]++
	v.mu.Unlock()
	codec, err := v.currentCodec()
	if err != nil {
		return "", err
	}
	label, err := codec.Issue(scope.DataCategory, v.opts.VisibleCategory)
	if err != nil {
		v.denied.Add(1)
		return "", err
	}
	now := time.Now().UTC()
	rec := VaultRecord{Namespace: index, Token: TokenLabel(label), Type: scope.DataCategory, CreatedAt: now,
		ExpiresAt: now.Add(v.opts.TTL), Purpose: scope.Purpose, DataCategory: scope.DataCategory,
		IndexDigest: scope.sessionIndex(v.macKey), SingleUse: v.opts.SingleUse, MaxRetrievals: v.opts.MaxRetrievals,
		ScopeDigest: scope.fullDigest(v.macKey)}
	if v.opts.IdleTTL > 0 {
		rec.IdleExpiresAt = now.Add(v.opts.IdleTTL)
	}
	aad := scopedAAD(scope, rec)
	ct, err := v.cipher.SealAAD([]byte(value), aad)
	if err != nil {
		return "", ErrVaultUnavailable
	}
	rec.Ciphertext = ct
	if err := v.backend.Put(ctx, rec); err != nil {
		return "", ErrVaultUnavailable
	}
	v.created.Add(1)
	v.keyVersion.Add(1)
	return label, nil
}

func (v *ScopedVault) Retrieve(ctx context.Context, scope Scope, placeholder string) (string, error) {
	codec, err := v.currentCodec()
	if err != nil {
		v.denied.Add(1)
		return "", ErrVaultUnavailable
	}
	p, err := codec.Parse(placeholder)
	if err != nil {
		v.denied.Add(1)
		return "", ErrInvalidPlaceholder
	}
	rec, ok, err := v.backend.Retrieve(ctx, scope.indexDigest(v.macKey), p.Label)
	if err != nil {
		if errors.Is(err, ErrRetrievalLimit) {
			v.denied.Add(1)
			return "", ErrRetrievalLimit
		}
		v.denied.Add(1)
		return "", ErrVaultUnavailable
	}
	if !ok {
		v.expired.Add(1)
		return "", ErrInvalidPlaceholder
	}
	if p.Visible && p.Category != rec.DataCategory {
		v.denied.Add(1)
		return "", ErrInvalidPlaceholder
	}
	if scope.DataCategory == "" || scope.DataCategory == "unknown" {
		scope.DataCategory = rec.DataCategory
	}
	if rec.ScopeDigest != scope.fullDigest(v.macKey) || rec.Purpose != scope.Purpose || rec.DataCategory == "" {
		v.denied.Add(1)
		return "", ErrInvalidPlaceholder
	}
	pt, err := v.cipher.OpenAAD(rec.Ciphertext, scopedAAD(scope, rec))
	if err != nil {
		v.denied.Add(1)
		return "", ErrInvalidPlaceholder
	}
	v.reads.Add(1)
	return string(pt), nil
}

func (v *ScopedVault) RevokeSession(ctx context.Context, tenant, application, subject, session string) error {
	if tenant == "" || application == "" || subject == "" || session == "" {
		return ErrScopeRequired
	}
	// Category/policy values are deliberately absent from the revocation index.
	base, err := NewScope(ScopeInput{Tenant: tenant, Application: application, Subject: subject, SessionID: session,
		PolicyID: "revocation", PolicyVersion: 1, Purpose: "revocation", DataCategory: "revocation"}, v.macKey)
	if err != nil {
		return err
	}
	err = v.backend.RevokeIndex(ctx, base.sessionIndex(v.macKey))
	if err == nil {
		v.revoked.Add(1)
	}
	return err
}

func scopedAAD(scope Scope, rec VaultRecord) []byte {
	value := struct {
		Scope                          Scope `json:"scope"`
		Token, Type, Purpose, Category string
		Created, Expires, Idle         string
		Single                         bool
		Max                            int
	}{scope, rec.Token, rec.Type, rec.Purpose, rec.DataCategory, rec.CreatedAt.UTC().Format(time.RFC3339Nano), rec.ExpiresAt.UTC().Format(time.RFC3339Nano), rec.IdleExpiresAt.UTC().Format(time.RFC3339Nano), rec.SingleUse, rec.MaxRetrievals}
	b, _ := json.Marshal(value)
	return b
}
