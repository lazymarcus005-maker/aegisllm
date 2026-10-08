// Package tokenization implements stable PII pseudonymization (FR-013/014):
// token placeholders with encrypted vault mappings, isolated from Laya and
// the target LLM (INV-007). Re-identification is a controlled, authorized
// interface only.
package tokenization

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aegisllm/gateway/internal/securetransport"
	"sync"
)

const (
	blobVersion        byte = 1
	keyringBlobVersion byte = 2
	aadBlobVersion     byte = 3
	aadKeyringVersion  byte = 4
	dekSize                 = 32
)

// Crypto implements envelope encryption: every record is sealed under a
// fresh random data-encryption key, and the data key is sealed under the
// master key (KEK) with AES-256-GCM. Blob layout:
//
//	version(1) | dekNonce(12) | encDEK(48) | dataNonce(12) | ciphertext(n)
type Crypto struct {
	kek []byte
}

// Cipher is the minimal envelope-encryption contract shared by the legacy
// single-key implementation and the rotating keyring.
type Cipher interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
}

// AADCipher authenticates metadata without putting it in the plaintext. The
// scoped vault requires this interface; legacy Cipher implementations remain
// usable only by the compatibility path.
type AADCipher interface {
	Cipher
	SealAAD([]byte, []byte) ([]byte, error)
	OpenAAD([]byte, []byte) ([]byte, error)
}

// PlaceholderKeyProvider supplies retained HMAC keys for placeholder reads
// during key rotation. Implementations return copies and never expose them in
// logs or serialized records.
type PlaceholderKeyProvider interface {
	PlaceholderKeys() (active []byte, retained [][]byte)
}

// ScopeKeyProvider supplies a stable derivation key. Keyrings select the
// lexically first retained key so rotation remains compatible while that key
// is retained; removal is safe only after dependent records expire.
type ScopeKeyProvider interface{ ScopeKey() []byte }

// ReloadingCipher preserves the legacy single-key envelope format while
// allowing a mounted 64-hex key file to rotate atomically.
type ReloadingCipher struct{ file *securetransport.File[string] }

func NewReloadingCipher(file *securetransport.File[string]) *ReloadingCipher {
	return &ReloadingCipher{file: file}
}
func (c *ReloadingCipher) current() (*Crypto, error) {
	encoded, err := c.file.Get()
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("vault key unavailable")
	}
	return NewCrypto(key)
}
func (c *ReloadingCipher) Seal(plaintext []byte) ([]byte, error) {
	crypto, err := c.current()
	if err != nil {
		return nil, err
	}
	return crypto.Seal(plaintext)
}
func (c *ReloadingCipher) SealAAD(plaintext, aad []byte) ([]byte, error) {
	crypto, err := c.current()
	if err != nil {
		return nil, err
	}
	return crypto.SealAAD(plaintext, aad)
}
func (c *ReloadingCipher) Open(blob []byte) ([]byte, error) {
	crypto, err := c.current()
	if err != nil {
		return nil, err
	}
	return crypto.Open(blob)
}
func (c *ReloadingCipher) OpenAAD(blob, aad []byte) ([]byte, error) {
	crypto, err := c.current()
	if err != nil {
		return nil, err
	}
	return crypto.OpenAAD(blob, aad)
}
func (c *ReloadingCipher) PlaceholderKeys() ([]byte, [][]byte) {
	crypto, err := c.current()
	if err != nil {
		return nil, nil
	}
	return crypto.PlaceholderKeys()
}
func (c *ReloadingCipher) ScopeKey() []byte {
	crypto, err := c.current()
	if err != nil {
		return nil
	}
	return crypto.ScopeKey()
}
func (c *ReloadingCipher) Status() securetransport.Status { return c.file.Status() }

// Keyring is a versioned envelope-encryption key set. The active key seals
// new records; all retained keys are decrypt-only candidates for old records.
// IDs are opaque labels and are never included in error messages.
type Keyring struct {
	mu       sync.RWMutex
	activeID string
	keys     map[string][]byte
}

type KeyringDocument struct {
	Version     int               `json:"version"`
	ActiveKeyID string            `json:"active_key_id"`
	Keys        map[string]string `json:"keys"`
}

func NewKeyring(activeID string, keys map[string][]byte) (*Keyring, error) {
	if activeID == "" || len(keys) == 0 {
		return nil, errors.New("keyring active key and keys are required")
	}
	copyKeys := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if id == "" || len(key) != dekSize {
			return nil, errors.New("keyring contains an invalid key")
		}
		copyKeys[id] = append([]byte(nil), key...)
	}
	if _, ok := copyKeys[activeID]; !ok {
		return nil, errors.New("keyring active key is missing")
	}
	return &Keyring{activeID: activeID, keys: copyKeys}, nil
}

func ParseKeyring(data []byte) (*Keyring, error) {
	var doc KeyringDocument
	if err := json.Unmarshal(data, &doc); err != nil || doc.Version < 1 {
		return nil, errors.New("invalid keyring")
	}
	keys := make(map[string][]byte, len(doc.Keys))
	for id, encoded := range doc.Keys {
		key, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("invalid keyring")
		}
		keys[id] = key
	}
	return NewKeyring(doc.ActiveKeyID, keys)
}

func (k *Keyring) ActiveKeyID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.activeID
}

func (k *Keyring) KeyIDs() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	return ids
}

func (k *Keyring) Seal(plaintext []byte) ([]byte, error) {
	return k.seal(plaintext, nil, keyringBlobVersion)
}

func (k *Keyring) SealAAD(plaintext, aad []byte) ([]byte, error) {
	return k.seal(plaintext, aad, aadKeyringVersion)
}

func (k *Keyring) seal(plaintext, aad []byte, version byte) ([]byte, error) {
	k.mu.RLock()
	activeID := k.activeID
	key := append([]byte(nil), k.keys[activeID]...)
	k.mu.RUnlock()
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	kekGCM, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	dekNonce, err := randomNonce(kekGCM)
	if err != nil {
		return nil, err
	}
	encDEK := kekGCM.Seal(nil, dekNonce, dek, nil)
	dataGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	dataNonce, err := randomNonce(dataGCM)
	if err != nil {
		return nil, err
	}
	ct := dataGCM.Seal(nil, dataNonce, plaintext, aad)
	if len(activeID) > 255 {
		return nil, errors.New("key id too long")
	}
	out := make([]byte, 0, 2+len(activeID)+12+len(encDEK)+12+len(ct))
	out = append(out, version, byte(len(activeID)))
	out = append(out, activeID...)
	out = append(out, dekNonce...)
	out = append(out, encDEK...)
	out = append(out, dataNonce...)
	out = append(out, ct...)
	return out, nil
}

func (k *Keyring) Open(blob []byte) ([]byte, error) {
	return k.open(blob, nil)
}

func (k *Keyring) OpenAAD(blob, aad []byte) ([]byte, error) {
	return k.open(blob, aad)
}

func (k *Keyring) open(blob, aad []byte) ([]byte, error) {
	if len(blob) > 0 && blob[0] == blobVersion {
		// Backward-compatible v1 records did not carry a key id, so try every
		// retained key without revealing which candidates were present.
		k.mu.RLock()
		keys := make([][]byte, 0, len(k.keys))
		for _, key := range k.keys {
			keys = append(keys, append([]byte(nil), key...))
		}
		k.mu.RUnlock()
		for _, key := range keys {
			legacy, err := NewCrypto(key)
			if err == nil {
				if plaintext, openErr := legacy.Open(blob); openErr == nil {
					return plaintext, nil
				}
			}
		}
		return nil, errors.New("record decryption failed")
	}
	if len(blob) < 2 || (blob[0] != keyringBlobVersion && blob[0] != aadKeyringVersion) {
		return nil, errors.New("unknown ciphertext version")
	}
	idLen := int(blob[1])
	if len(blob) < 2+idLen+12+48+12 {
		return nil, errors.New("ciphertext too short")
	}
	k.mu.RLock()
	key, ok := k.keys[string(blob[2:2+idLen])]
	key = append([]byte(nil), key...)
	k.mu.RUnlock()
	if !ok {
		return nil, errors.New("ciphertext key unavailable")
	}
	start := 2 + idLen
	dekNonce := blob[start : start+12]
	encDEK := blob[start+12 : start+12+48]
	dataNonce := blob[start+12+48 : start+12+48+12]
	ct := blob[start+12+48+12:]
	kekGCM, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	dek, err := kekGCM.Open(nil, dekNonce, encDEK, nil)
	if err != nil {
		return nil, errors.New("data key decryption failed")
	}
	dataGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if blob[0] == keyringBlobVersion && len(aad) != 0 {
		return nil, errors.New("record authentication failed")
	}
	pt, err := dataGCM.Open(nil, dataNonce, ct, aad)
	if err != nil {
		return nil, errors.New("record decryption failed")
	}
	return pt, nil
}

func (k *Keyring) PlaceholderKeys() ([]byte, [][]byte) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	active := append([]byte(nil), k.keys[k.activeID]...)
	retained := make([][]byte, 0, len(k.keys))
	for _, key := range k.keys {
		retained = append(retained, append([]byte(nil), key...))
	}
	return active, retained
}

func (k *Keyring) ScopeKey() []byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var selected []byte
	selectedID := ""
	for id, key := range k.keys {
		if selected == nil || id < selectedID {
			selectedID, selected = id, key
		}
	}
	return append([]byte(nil), selected...)
}

// NewCrypto validates and wraps a 32-byte master key.
func NewCrypto(masterKey []byte) (*Crypto, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes (AES-256)")
	}
	kek := make([]byte, dekSize)
	copy(kek, masterKey)
	return &Crypto{kek: kek}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomNonce(aead cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// Seal encrypts plaintext under a fresh data key.
func (c *Crypto) Seal(plaintext []byte) ([]byte, error) {
	return c.seal(plaintext, nil, blobVersion)
}

func (c *Crypto) SealAAD(plaintext, aad []byte) ([]byte, error) {
	return c.seal(plaintext, aad, aadBlobVersion)
}

func (c *Crypto) seal(plaintext, aad []byte, version byte) ([]byte, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	kekGCM, err := newGCM(c.kek)
	if err != nil {
		return nil, err
	}
	dekNonce, err := randomNonce(kekGCM)
	if err != nil {
		return nil, err
	}
	encDEK := kekGCM.Seal(nil, dekNonce, dek, nil)

	dataGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	dataNonce, err := randomNonce(dataGCM)
	if err != nil {
		return nil, err
	}
	ct := dataGCM.Seal(nil, dataNonce, plaintext, aad)

	out := make([]byte, 0, 1+12+len(encDEK)+12+len(ct))
	out = append(out, version)
	out = append(out, dekNonce...)
	out = append(out, encDEK...)
	out = append(out, dataNonce...)
	out = append(out, ct...)
	return out, nil
}

// Open decrypts a blob produced by Seal.
func (c *Crypto) Open(blob []byte) ([]byte, error) {
	return c.open(blob, nil)
}

func (c *Crypto) OpenAAD(blob, aad []byte) ([]byte, error) {
	return c.open(blob, aad)
}

func (c *Crypto) open(blob, aad []byte) ([]byte, error) {
	if len(blob) < 1+12+48+12 {
		return nil, errors.New("ciphertext too short")
	}
	if blob[0] != blobVersion && blob[0] != aadBlobVersion {
		return nil, fmt.Errorf("unknown ciphertext version %d", blob[0])
	}
	dekNonce := blob[1:13]
	encDEK := blob[13 : 13+48]
	dataNonce := blob[13+48 : 25+48]
	ct := blob[25+48:]

	kekGCM, err := newGCM(c.kek)
	if err != nil {
		return nil, err
	}
	dek, err := kekGCM.Open(nil, dekNonce, encDEK, nil)
	if err != nil {
		return nil, errors.New("data key decryption failed")
	}
	dataGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if blob[0] == blobVersion && len(aad) != 0 {
		return nil, errors.New("record authentication failed")
	}
	pt, err := dataGCM.Open(nil, dataNonce, ct, aad)
	if err != nil {
		return nil, errors.New("record decryption failed")
	}
	return pt, nil
}

func (c *Crypto) PlaceholderKeys() ([]byte, [][]byte) {
	return append([]byte(nil), c.kek...), [][]byte{append([]byte(nil), c.kek...)}
}

func (c *Crypto) ScopeKey() []byte { return append([]byte(nil), c.kek...) }
