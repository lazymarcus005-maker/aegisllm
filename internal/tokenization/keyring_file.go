package tokenization

import (
	"errors"
	"time"

	"github.com/aegisllm/gateway/internal/securetransport"
)

// KeyringFile atomically reloads a JSON keyring. By default it refuses any
// removal of a previously retained key; operators must explicitly enable the
// removal policy only after all records encrypted with that key have expired.
type KeyringFile struct {
	file *securetransport.File[*Keyring]
}

func NewKeyringFile(path string, interval time.Duration, allowRemoval bool, metrics securetransport.Metrics) (*KeyringFile, error) {
	var previous *Keyring
	file, err := securetransport.NewFile(path, interval, func(data []byte) (*Keyring, time.Time, error) {
		keyring, err := ParseKeyring(data)
		if err != nil {
			return nil, time.Time{}, err
		}
		if previous != nil && !allowRemoval {
			present := make(map[string]bool)
			for _, id := range keyring.KeyIDs() {
				present[id] = true
			}
			for _, oldID := range previous.KeyIDs() {
				if !present[oldID] {
					return nil, time.Time{}, errors.New("key removal requires expiry policy")
				}
			}
		}
		previous = keyring
		return keyring, time.Time{}, nil
	}, metrics)
	if err != nil {
		return nil, err
	}
	return &KeyringFile{file: file}, nil
}

func (k *KeyringFile) Get() (*Keyring, error)         { return k.file.Get() }
func (k *KeyringFile) Status() securetransport.Status { return k.file.Status() }
func (k *KeyringFile) Close()                         { k.file.Close() }
func (k *KeyringFile) Seal(plaintext []byte) ([]byte, error) {
	keyring, err := k.Get()
	if err != nil {
		return nil, err
	}
	return keyring.Seal(plaintext)
}
func (k *KeyringFile) Open(ciphertext []byte) ([]byte, error) {
	keyring, err := k.Get()
	if err != nil {
		return nil, err
	}
	return keyring.Open(ciphertext)
}
