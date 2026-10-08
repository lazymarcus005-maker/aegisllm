// Package policydistribution implements the signed, immutable policy bundle
// format used by gateways. Bundle verification is deliberately independent of
// the HTTP server so it can be used by policytool and offline release jobs.
package policydistribution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/securetransport"
	"gopkg.in/yaml.v3"
)

const FormatVersion = 1

// Manifest is the signed portion of a bundle. JSON encoding is used for the
// manifest because encoding/json sorts map keys, giving us a stable canonical
// representation without a second serialization dependency.
type Manifest struct {
	FormatVersion            int               `json:"format_version"`
	BundleID                 string            `json:"bundle_id"`
	Sequence                 uint64            `json:"sequence"`
	PolicyID                 string            `json:"policy_id"`
	PolicyVersion            int               `json:"policy_version"`
	PolicySHA256             string            `json:"policy_sha256"`
	SchemaVersion            string            `json:"schema_version,omitempty"`
	SchemaSHA256             string            `json:"schema_sha256,omitempty"`
	QuestionVersion          int               `json:"question_version,omitempty"`
	QuestionSHA256           string            `json:"question_sha256,omitempty"`
	ThresholdVersion         int               `json:"threshold_version,omitempty"`
	ThresholdSHA256          string            `json:"threshold_sha256,omitempty"`
	SemanticModelID          string            `json:"semantic_model_id,omitempty"`
	SemanticModelVersion     string            `json:"semantic_model_version,omitempty"`
	SemanticModelSHA256      string            `json:"semantic_model_sha256,omitempty"`
	SemanticModelState       string            `json:"semantic_model_state,omitempty"`
	Created                  string            `json:"created"`
	Expires                  string            `json:"expires,omitempty"`
	NotBefore                string            `json:"not_before,omitempty"`
	Issuer                   string            `json:"issuer"`
	KeyID                    string            `json:"key_id"`
	MinimumGatewayVersion    string            `json:"minimum_gateway_version,omitempty"`
	TargetEnvironments       []string          `json:"target_environments,omitempty"`
	TargetTenants            []string          `json:"target_tenants,omitempty"`
	Files                    map[string]string `json:"files"`
	EvaluationArtifactHashes map[string]string `json:"evaluation_artifact_hashes,omitempty"`
}

type Bundle struct {
	Manifest  Manifest
	Signature []byte
	Files     map[string][]byte
}

// Signer permits HSM/KMS adapters to sign without exposing a private key to
// the process. The policytool command uses the file/stdin path below.
type Signer interface{ Sign([]byte) ([]byte, error) }

type Snapshot struct {
	Bundle        *Bundle
	Policy        *policy.Policy
	Questions     *decision.QuestionSchema
	Thresholds    *policy.SemanticThresholds
	BundleHash    string
	SemanticModel ModelMetadata
}

// ModelMetadata is a content-free binding copied from a signed semantic
// registry record. We intentionally do not import the lifecycle package here:
// policy distribution is the lower-level signed bundle format.
type ModelMetadata struct {
	ID      string `json:"model_id,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"`
	State   string `json:"state,omitempty"`
}

func CanonicalManifest(m Manifest) ([]byte, error) {
	if m.Files == nil {
		m.Files = map[string]string{}
	}
	return json.Marshal(m)
}

func SigningBytes(m Manifest) ([]byte, error) { return CanonicalManifest(m) }

func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (b *Bundle) Hash() string {
	if b == nil {
		return ""
	}
	manifest, _ := CanonicalManifest(b.Manifest)
	h := sha256.New()
	_, _ = h.Write(manifest)
	_, _ = h.Write(b.Signature)
	return hex.EncodeToString(h.Sum(nil))
}

func (b *Bundle) Validate(now time.Time) error {
	if b == nil {
		return errors.New("bundle is nil")
	}
	m := b.Manifest
	if m.FormatVersion != FormatVersion || strings.TrimSpace(m.BundleID) == "" || m.Sequence == 0 {
		return errors.New("bundle manifest format, id, or sequence is invalid")
	}
	if strings.TrimSpace(m.PolicyID) == "" || m.PolicyVersion <= 0 || !isHash(m.PolicySHA256) {
		return errors.New("bundle policy metadata is invalid")
	}
	if m.SemanticModelID != "" {
		if m.SemanticModelVersion == "" || !isHash(m.SemanticModelSHA256) || m.SemanticModelState != "promoted" {
			return errors.New("policy bundle references an unpromoted or invalid semantic model")
		}
	}
	if strings.TrimSpace(m.Issuer) == "" || strings.TrimSpace(m.KeyID) == "" {
		return errors.New("bundle issuer and key_id are required")
	}
	created, err := time.Parse(time.RFC3339Nano, m.Created)
	if err != nil {
		return errors.New("bundle created timestamp is invalid")
	}
	if !now.IsZero() {
		if m.NotBefore != "" {
			nb, parseErr := time.Parse(time.RFC3339Nano, m.NotBefore)
			if parseErr != nil || now.Before(nb) {
				return errors.New("bundle is not yet valid")
			}
		}
		if m.Expires != "" {
			exp, parseErr := time.Parse(time.RFC3339Nano, m.Expires)
			if parseErr != nil || !now.Before(exp) {
				return errors.New("bundle is expired")
			}
		}
		if created.After(now.Add(5 * time.Minute)) {
			return errors.New("bundle created timestamp is in the future")
		}
	}
	if len(b.Signature) != ed25519.SignatureSize {
		return errors.New("bundle signature is invalid")
	}
	if len(b.Files) == 0 || len(m.Files) == 0 {
		return errors.New("bundle has no files")
	}
	for name, expected := range m.Files {
		if !safeFileName(name) || !isHash(expected) {
			return fmt.Errorf("bundle file entry %q is invalid", name)
		}
		data, ok := b.Files[name]
		if !ok || HashBytes(data) != strings.ToLower(expected) {
			return fmt.Errorf("bundle file hash mismatch: %s", name)
		}
	}
	for name, expected := range m.EvaluationArtifactHashes {
		if !isHash(expected) || b.Files[name] == nil || HashBytes(b.Files[name]) != strings.ToLower(expected) {
			return fmt.Errorf("evaluation artifact hash mismatch: %s", name)
		}
	}
	for name := range b.Files {
		if _, ok := m.Files[name]; !ok {
			return fmt.Errorf("bundle contains unsigned file: %s", name)
		}
	}
	return nil
}

func (b *Bundle) Verify(key ed25519.PublicKey, now time.Time) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("public key is invalid")
	}
	if err := b.Validate(now); err != nil {
		return err
	}
	data, err := SigningBytes(b.Manifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, data, b.Signature) {
		return errors.New("bundle signature verification failed")
	}
	return nil
}

func (b *Bundle) Snapshot() (*Snapshot, error) {
	if err := b.Validate(time.Time{}); err != nil {
		return nil, err
	}
	policyData := b.Files["policy.yaml"]
	pol, err := policy.Load(policyData)
	if err != nil {
		return nil, fmt.Errorf("policy artifact: %w", err)
	}
	if pol.ID != b.Manifest.PolicyID || pol.Version != b.Manifest.PolicyVersion {
		return nil, errors.New("policy metadata does not match manifest")
	}
	s := &Snapshot{Bundle: b, Policy: pol, BundleHash: b.Hash()}
	s.SemanticModel = ModelMetadata{ID: b.Manifest.SemanticModelID, Version: b.Manifest.SemanticModelVersion, Digest: b.Manifest.SemanticModelSHA256, State: b.Manifest.SemanticModelState}
	if data := b.Files["questions.yaml"]; len(data) > 0 {
		s.Questions, err = decision.LoadQuestions(data)
		if err != nil {
			return nil, fmt.Errorf("question artifact: %w", err)
		}
		if s.Questions.Version != b.Manifest.QuestionVersion || HashBytes(data) != b.Manifest.QuestionSHA256 {
			return nil, errors.New("question metadata does not match manifest")
		}
	}
	if data := b.Files["thresholds.yaml"]; len(data) > 0 {
		s.Thresholds, err = policy.LoadSemanticThresholds(data)
		if err != nil {
			return nil, fmt.Errorf("threshold artifact: %w", err)
		}
		if s.Thresholds.Version != b.Manifest.ThresholdVersion || HashBytes(data) != b.Manifest.ThresholdSHA256 {
			return nil, errors.New("threshold metadata does not match manifest")
		}
	}
	return s, nil
}

func WriteDirectory(dir string, b *Bundle) error {
	if b == nil {
		return errors.New("bundle is nil")
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	manifest, err := CanonicalManifest(b.Manifest)
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(dir, "manifest.json"), manifest, 0640); err != nil {
		return err
	}
	for name, data := range b.Files {
		if err := atomicWrite(filepath.Join(dir, name), data, 0640); err != nil {
			return err
		}
	}
	if len(b.Signature) > 0 {
		if err := atomicWrite(filepath.Join(dir, "signature.ed25519"), []byte(base64.StdEncoding.EncodeToString(b.Signature)+"\n"), 0640); err != nil {
			return err
		}
	}
	return nil
}

func ReadDirectory(dir string) (*Bundle, error) {
	manifestData, err := securetransport.ReadTrustedFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("bundle manifest: %w", err)
	}
	var m Manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return nil, fmt.Errorf("bundle manifest: %w", err)
	}
	files := map[string][]byte{}
	for name := range m.Files {
		if !safeFileName(name) {
			return nil, errors.New("bundle contains unsafe file name")
		}
		data, readErr := securetransport.ReadTrustedFile(filepath.Join(dir, name))
		if readErr != nil {
			return nil, fmt.Errorf("bundle file %s: %w", name, readErr)
		}
		files[name] = data
	}
	sigData, err := securetransport.ReadTrustedFile(filepath.Join(dir, "signature.ed25519"))
	if err != nil {
		if os.IsNotExist(err) {
			return &Bundle{Manifest: m, Files: files}, nil
		}
		return nil, errors.New("bundle signature is unreadable")
	}
	sigData = bytes.TrimSpace(sigData)
	sig, err := base64.StdEncoding.DecodeString(string(sigData))
	if err != nil {
		return nil, errors.New("bundle signature is malformed")
	}
	return &Bundle{Manifest: m, Signature: sig, Files: files}, nil
}

// TrustKey is a public verification key. Revoked or expired keys remain in
// the file so an audit can explain why an old bundle was rejected.
type TrustKey struct {
	KeyID     string `json:"key_id" yaml:"key_id"`
	PublicKey string `json:"public_key" yaml:"public_key"`
	NotBefore string `json:"not_before,omitempty" yaml:"not_before,omitempty"`
	Expires   string `json:"expires,omitempty" yaml:"expires,omitempty"`
	Revoked   bool   `json:"revoked,omitempty" yaml:"revoked,omitempty"`
}

type TrustStore struct {
	Keys    []TrustKey `json:"keys" yaml:"keys"`
	path    string
	mu      sync.Mutex
	modTime time.Time
	keys    map[string]TrustKey
}

func NewTrustStore(path string) *TrustStore { return &TrustStore{path: path} }

func (t *TrustStore) Load() error {
	if t == nil || strings.TrimSpace(t.path) == "" {
		return errors.New("trust store path is required")
	}
	stat, err := os.Stat(t.path)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.modTime.IsZero() && stat.ModTime().Equal(t.modTime) {
		return nil
	}
	data, err := securetransport.ReadTrustedFile(t.path)
	if err != nil {
		return err
	}
	var doc TrustStore
	if strings.HasSuffix(strings.ToLower(t.path), ".yaml") || strings.HasSuffix(strings.ToLower(t.path), ".yml") {
		err = yaml.Unmarshal(data, &doc)
	} else {
		err = json.Unmarshal(data, &doc)
	}
	if err != nil {
		return fmt.Errorf("trust store: %w", err)
	}
	keys := make(map[string]TrustKey, len(doc.Keys))
	for _, key := range doc.Keys {
		if key.KeyID == "" || len(parseKey(key.PublicKey, ed25519.PublicKeySize)) != ed25519.PublicKeySize {
			return errors.New("trust store contains an invalid key")
		}
		keys[key.KeyID] = key
	}
	t.Keys, t.keys, t.modTime = doc.Keys, keys, stat.ModTime()
	return nil
}

func (t *TrustStore) Key(id string, now time.Time) (ed25519.PublicKey, error) {
	if err := t.Load(); err != nil {
		return nil, err
	}
	t.mu.Lock()
	key, ok := t.keys[id]
	t.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown signing key")
	}
	if key.Revoked {
		return nil, errors.New("signing key is revoked")
	}
	if !now.IsZero() {
		if key.NotBefore != "" {
			n, err := time.Parse(time.RFC3339Nano, key.NotBefore)
			if err != nil || now.Before(n) {
				return nil, errors.New("signing key is not yet valid")
			}
		}
		if key.Expires != "" {
			e, err := time.Parse(time.RFC3339Nano, key.Expires)
			if err != nil || !now.Before(e) {
				return nil, errors.New("signing key is expired")
			}
		}
	}
	return parseKey(key.PublicKey, ed25519.PublicKeySize), nil
}

func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	data = bytes.TrimSpace(data)
	if block, _ := pem.Decode(data); block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			if k, ok := key.(ed25519.PrivateKey); ok {
				return k, nil
			}
		}
		if len(block.Bytes) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(block.Bytes), nil
		}
	}
	key := parseKey(string(data), ed25519.PrivateKeySize)
	if len(key) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(key), nil
	}
	return nil, errors.New("private key must be Ed25519 PKCS8 PEM, hex, or base64")
}

func ParsePublicKey(data string) ed25519.PublicKey {
	return ed25519.PublicKey(parseKey(data, ed25519.PublicKeySize))
}

func Create(policyData, questionData, thresholdData []byte, opts Manifest) (*Bundle, error) {
	pol, err := policy.Load(policyData)
	if err != nil {
		return nil, err
	}
	if opts.FormatVersion == 0 {
		opts.FormatVersion = FormatVersion
	}
	if opts.PolicyID == "" {
		opts.PolicyID = pol.ID
	}
	if opts.PolicyVersion == 0 {
		opts.PolicyVersion = pol.Version
	}
	if opts.BundleID == "" {
		opts.BundleID = fmt.Sprintf("%s-%d", opts.PolicyID, opts.Sequence)
	}
	if opts.Created == "" {
		created := time.Unix(0, 0).UTC()
		if parsed, parseErr := time.Parse("2006-01-02", pol.EffectiveDate); parseErr == nil {
			created = parsed.UTC()
		}
		opts.Created = created.Format(time.RFC3339Nano)
	}
	files := map[string][]byte{"policy.yaml": append([]byte(nil), policyData...)}
	for name, data := range files {
		if containsPrivateMaterial(data) {
			return nil, fmt.Errorf("bundle artifact %s contains private key material", name)
		}
	}
	if len(questionData) > 0 {
		qs, e := decision.LoadQuestions(questionData)
		if e != nil {
			return nil, e
		}
		if containsPrivateMaterial(questionData) {
			return nil, errors.New("bundle question artifact contains private key material")
		}
		files["questions.yaml"] = append([]byte(nil), questionData...)
		if opts.SchemaVersion == "" {
			opts.SchemaVersion = qs.Schema
		}
		if opts.QuestionVersion == 0 {
			opts.QuestionVersion = qs.Version
		}
	}
	if len(thresholdData) > 0 {
		th, e := policy.LoadSemanticThresholds(thresholdData)
		if e != nil {
			return nil, e
		}
		if containsPrivateMaterial(thresholdData) {
			return nil, errors.New("bundle threshold artifact contains private key material")
		}
		files["thresholds.yaml"] = append([]byte(nil), thresholdData...)
		if opts.ThresholdVersion == 0 {
			opts.ThresholdVersion = th.Version
		}
	}
	opts.Files = map[string]string{}
	for name, data := range files {
		opts.Files[name] = HashBytes(data)
	}
	opts.PolicySHA256 = opts.Files["policy.yaml"]
	if questionData != nil {
		opts.QuestionSHA256 = opts.Files["questions.yaml"]
		opts.SchemaSHA256 = opts.QuestionSHA256
	}
	if thresholdData != nil {
		opts.ThresholdSHA256 = opts.Files["thresholds.yaml"]
	}
	if opts.EvaluationArtifactHashes == nil {
		opts.EvaluationArtifactHashes = map[string]string{}
	}
	if err := (&Bundle{Manifest: opts, Files: files, Signature: make([]byte, ed25519.SignatureSize)}).Validate(time.Time{}); err != nil {
		return nil, err
	}
	return &Bundle{Manifest: opts, Files: files}, nil
}

func Sign(b *Bundle, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("private key is invalid")
	}
	return SignWith(b, privateKeySigner{key})
}

func SignWith(b *Bundle, signer Signer) error {
	if signer == nil {
		return errors.New("external signer is required")
	}
	data, err := SigningBytes(b.Manifest)
	if err != nil {
		return err
	}
	signature, err := signer.Sign(data)
	if err != nil {
		return err
	}
	if len(signature) != ed25519.SignatureSize {
		return errors.New("external signer returned an invalid signature")
	}
	b.Signature = append([]byte(nil), signature...)
	return nil
}

type privateKeySigner struct{ key ed25519.PrivateKey }

func (s privateKeySigner) Sign(data []byte) ([]byte, error) { return ed25519.Sign(s.key, data), nil }

func AddFile(b *Bundle, name string, data []byte, evaluation bool) error {
	if b == nil || !safeFileName(name) {
		return errors.New("bundle file name is invalid")
	}
	if containsPrivateMaterial(data) {
		return errors.New("bundle artifact contains private key material")
	}
	if b.Files == nil {
		b.Files = map[string][]byte{}
	}
	if b.Manifest.Files == nil {
		b.Manifest.Files = map[string]string{}
	}
	b.Files[name] = append([]byte(nil), data...)
	b.Manifest.Files[name] = HashBytes(data)
	if evaluation {
		if b.Manifest.EvaluationArtifactHashes == nil {
			b.Manifest.EvaluationArtifactHashes = map[string]string{}
		}
		b.Manifest.EvaluationArtifactHashes[name] = HashBytes(data)
	}
	return nil
}

func AuthorizationSigningBytes(a Authorization) ([]byte, error) {
	a.Signature = nil
	return json.Marshal(a)
}

func SignAuthorization(a *Authorization, key ed25519.PrivateKey) error {
	if a == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("rollback authorization is invalid")
	}
	data, err := AuthorizationSigningBytes(*a)
	if err != nil {
		return err
	}
	a.Signature = ed25519.Sign(key, data)
	return nil
}

func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func containsPrivateMaterial(data []byte) bool {
	upper := strings.ToUpper(string(data))
	return strings.Contains(upper, "PRIVATE KEY") || strings.Contains(upper, "BEGIN RSA") || strings.Contains(upper, "BEGIN OPENSSH")
}
func safeFileName(name string) bool {
	return name != "" && filepath.Base(name) == name && !strings.Contains(name, "\\") && name != "manifest.json" && name != "signature.ed25519"
}
func parseKey(value string, size int) []byte {
	value = strings.TrimSpace(value)
	if data, err := hex.DecodeString(value); err == nil && len(data) == size {
		return data
	}
	if data, err := base64.StdEncoding.DecodeString(value); err == nil && len(data) == size {
		return data
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bundle-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// SortedFileNames is useful for deterministic CLI output and tests.
func (b *Bundle) SortedFileNames() []string {
	names := make([]string, 0, len(b.Files))
	for name := range b.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
