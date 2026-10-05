// Package tokenization implements stable PII pseudonymization (FR-013/014):
// token placeholders with encrypted vault mappings, isolated from Laya and
// the target LLM (INV-007). Re-identification is a controlled, authorized
// interface only.
package tokenization

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	blobVersion byte = 1
	dekSize          = 32
)

// Crypto implements envelope encryption: every record is sealed under a
// fresh random data-encryption key, and the data key is sealed under the
// master key (KEK) with AES-256-GCM. Blob layout:
//
//	version(1) | dekNonce(12) | encDEK(48) | dataNonce(12) | ciphertext(n)
type Crypto struct {
	kek []byte
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

// Seal encrypts plaintext under a fresh data key.
func (c *Crypto) Seal(plaintext []byte) ([]byte, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	kekGCM, err := newGCM(c.kek)
	if err != nil {
		return nil, err
	}
	dekNonce := make([]byte, 12)
	if _, err := rand.Read(dekNonce); err != nil {
		return nil, err
	}
	encDEK := kekGCM.Seal(nil, dekNonce, dek, nil)

	dataGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	dataNonce := make([]byte, 12)
	if _, err := rand.Read(dataNonce); err != nil {
		return nil, err
	}
	ct := dataGCM.Seal(nil, dataNonce, plaintext, nil)

	out := make([]byte, 0, 1+12+len(encDEK)+12+len(ct))
	out = append(out, blobVersion)
	out = append(out, dekNonce...)
	out = append(out, encDEK...)
	out = append(out, dataNonce...)
	out = append(out, ct...)
	return out, nil
}

// Open decrypts a blob produced by Seal.
func (c *Crypto) Open(blob []byte) ([]byte, error) {
	if len(blob) < 1+12+48+12 {
		return nil, errors.New("ciphertext too short")
	}
	if blob[0] != blobVersion {
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
	pt, err := dataGCM.Open(nil, dataNonce, ct, nil)
	if err != nil {
		return nil, errors.New("record decryption failed")
	}
	return pt, nil
}
