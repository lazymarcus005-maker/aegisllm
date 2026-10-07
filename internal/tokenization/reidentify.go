package tokenization

import (
	"context"
	"errors"
)

// Sentinel errors for the re-identification path.
var (
	ErrTokenNotFound = errors.New("token not found in namespace")
	ErrUnauthorized  = errors.New("caller not authorized for token re-identification")
)

// Caller is the authorized identity attempting re-identification.
type Caller struct {
	Application string
	Subject     string
}

// Reidentifier is the controlled re-identification interface (T-023,
// FR-014). A placeholder coming back from the model must never be blindly
// replaced: only tokens issued in the matching namespace to an authorized
// caller can be resolved.
type Reidentifier struct {
	vault  Vault
	crypto Cipher
}

func NewReidentifier(vault Vault, crypto Cipher) *Reidentifier {
	return &Reidentifier{vault: vault, crypto: crypto}
}

// Reidentify resolves a token within a namespace for an authorized caller.
// Authorization: the caller's application must match the application recorded
// at issuance. The response-policy gate lives with the outbound pipeline
// (ticket 07).
func (r *Reidentifier) Reidentify(ctx context.Context, namespace, token string, caller Caller) (string, error) {
	rec, ok, err := r.vault.Get(ctx, namespace, token)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrTokenNotFound
	}
	if rec.Application != "" && rec.Application != caller.Application {
		return "", ErrUnauthorized
	}
	pt, err := r.crypto.Open(rec.Ciphertext)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
