package policydistribution

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const testPolicy = `id: test
version: 1
owner: test
effective_date: "2026-10-01"
default: {action: allow}
safe_default: {action: block}
`

func testBundle(t *testing.T, sequence uint64, keyID string, key ed25519.PrivateKey) *Bundle {
	t.Helper()
	b, err := Create([]byte(testPolicy), nil, nil, Manifest{BundleID: "test-" + keyID, Sequence: sequence, Issuer: "test", KeyID: keyID})
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(b, key); err != nil {
		t.Fatal(err)
	}
	return b
}

func trustFile(t *testing.T, path string, keys ...TrustKey) {
	t.Helper()
	data, _ := json.Marshal(TrustStore{Keys: keys})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func publicString(key ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(key) }

func TestBundleDeterminismAndTamper(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	one := testBundle(t, 1, "k1", private)
	two := testBundle(t, 1, "k1", private)
	a, _ := CanonicalManifest(one.Manifest)
	b, _ := CanonicalManifest(two.Manifest)
	if string(a) != string(b) || one.Hash() != two.Hash() {
		t.Fatal("bundle output is not deterministic")
	}
	if err := one.Verify(public, time.Now()); err != nil {
		t.Fatal(err)
	}
	one.Files["policy.yaml"][0] ^= 1
	if err := one.Verify(public, time.Now()); err == nil {
		t.Fatal("tampered artifact was accepted")
	}
}

func TestTrustRotationAndRevocation(t *testing.T) {
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	newPublic, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "trust.json")
	trustFile(t, path, TrustKey{KeyID: "old", PublicKey: publicString(oldPublic), Revoked: true}, TrustKey{KeyID: "new", PublicKey: publicString(newPublic)})
	store := NewTrustStore(path)
	if _, err := store.Key("old", time.Now()); err == nil {
		t.Fatal("revoked key accepted")
	}
	b := testBundle(t, 1, "new", newPrivate)
	key, err := store.Key("new", time.Now())
	if err != nil || b.Verify(key, time.Now()) != nil {
		t.Fatal("rotated trust key did not verify")
	}
	_ = oldPrivate
}

func TestManagerReplayRollbackAndCanary(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	trustPath := filepath.Join(dir, "trust.json")
	statePath := filepath.Join(dir, "state.json")
	trustFile(t, trustPath, TrustKey{KeyID: "k1", PublicKey: publicString(public)})
	for _, item := range []struct {
		name     string
		sequence uint64
	}{{"a", 1}, {"b", 2}} {
		if err := WriteDirectory(filepath.Join(dir, item.name), testBundle(t, item.sequence, "k1", private)); err != nil {
			t.Fatal(err)
		}
	}
	m, err := NewManager(Config{BundlePath: filepath.Join(dir, "a"), TrustStorePath: trustPath, StatePath: statePath, CanaryPercent: 25}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.LoadInitial(nilContext{}); err != nil {
		t.Fatal(err)
	}
	first := m.IsCanary("gateway-1", "tenant", "app")
	if first != m.IsCanary("gateway-1", "tenant", "app") {
		t.Fatal("canary assignment is not stable")
	}
	if err := m.SetCandidate(mustSnapshot(t, filepath.Join(dir, "b"), trustPath)); err != nil {
		t.Fatal(err)
	}
	if err := m.Promote("reviewed"); err != nil {
		t.Fatal(err)
	}
	if m.Status().Active.Sequence != 2 {
		t.Fatal("candidate did not promote")
	}
	restarted, err := NewManager(Config{BundlePath: filepath.Join(dir, "a"), TrustStorePath: trustPath, StatePath: statePath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.LoadInitial(nilContext{}); err == nil {
		t.Fatal("replay after restart was accepted")
	}
	// A retained older snapshot can be restored only with a signed authorization.
	rollback := Authorization{Version: 1, Action: "rollback", TargetSequence: 1, TargetHash: m.history[0].BundleHash, Reason: "incident", Role: "aegis.operator", Issuer: "test", KeyID: "k1", Issued: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := SignAuthorization(&rollback, private); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollback(rollback, nil); err != nil {
		t.Fatal(err)
	}
	if m.Status().Active.Sequence != 1 {
		t.Fatal("rollback did not restore complete snapshot")
	}
}

func TestManagerETagAndLastKnownGood(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	trustPath := filepath.Join(dir, "trust.json")
	trustFile(t, trustPath, TrustKey{KeyID: "k", PublicKey: publicString(public)})
	b := testBundle(t, 1, "k", private)
	envelope := bundleEnvelope(b)
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if w.Header().Get("ETag") == "" {
			w.Header().Set("ETag", "v1")
		}
		if calls.Load() > 1 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(envelope)
	}))
	defer srv.Close()
	m, err := NewManager(Config{ControlPlaneURL: srv.URL, TrustStorePath: trustPath, HTTPClient: srv.Client(), Timeout: time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.LoadInitial(nilContext{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Poll(nilContext{}); err != nil {
		t.Fatal(err)
	}
	if m.Current() == nil || calls.Load() != 2 {
		t.Fatal("ETag polling did not preserve active bundle")
	}
}

type nilContext struct{}

func (nilContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (nilContext) Done() <-chan struct{}       { return nil }
func (nilContext) Err() error                  { return nil }
func (nilContext) Value(any) any               { return nil }

func mustSnapshot(t *testing.T, path, trustPath string) *Snapshot {
	t.Helper()
	b, err := ReadDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewTrustStore(trustPath)
	key, err := store.Key(b.Manifest.KeyID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(key, time.Now()); err != nil {
		t.Fatal(err)
	}
	s, err := b.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func bundleEnvelope(b *Bundle) []byte {
	encoded := map[string]string{}
	for name, data := range b.Files {
		encoded[name] = base64.StdEncoding.EncodeToString(data)
	}
	out, _ := json.Marshal(struct {
		Manifest  Manifest          `json:"manifest"`
		Signature string            `json:"signature"`
		Files     map[string]string `json:"files"`
	}{b.Manifest, base64.StdEncoding.EncodeToString(b.Signature), encoded})
	return out
}
