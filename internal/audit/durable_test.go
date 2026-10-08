package audit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testEvent(id string) Event {
	return Event{EventID: id, RequestID: "req-" + id, Timestamp: time.Now().UTC(), Direction: "REQUEST", Mode: "enforce", Action: "ALLOW", Code: "ALLOW"}
}
func testWAL(t *testing.T, dir string) *WAL {
	t.Helper()
	w, err := OpenWAL(WALConfig{Dir: dir, SegmentBytes: 512, MaxBytes: 1 << 20, Fsync: DurabilitySync, HMACKey: []byte(strings.Repeat("h", 32))})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWALAppendRestartReplayAndCheckpoint(t *testing.T) {
	dir := t.TempDir()
	w := testWAL(t, dir)
	for i := 0; i < 3; i++ {
		if _, err := w.Append(context.Background(), testEvent(string(rune('a'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w = testWAL(t, dir)
	defer w.Close()
	var got []string
	if err := w.Replay(context.Background(), func(e Event) error { got = append(got, e.EventID); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "a" || w.Status().NextSequence != 4 {
		t.Fatalf("replay=%v status=%+v", got, w.Status())
	}
}

func TestWALConcurrentWriters(t *testing.T) {
	w := testWAL(t, t.TempDir())
	defer w.Close()
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			if _, err := w.Append(context.Background(), testEvent(string(rune('a'+i)))); err != nil {
				t.Errorf("append: %v", err)
			}
		}(i)
	}
	group.Wait()
	if w.Status().Records != 16 {
		t.Fatalf("records=%d", w.Status().Records)
	}
	if err := w.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWALTornTailIsRecovered(t *testing.T) {
	dir := t.TempDir()
	w := testWAL(t, dir)
	_, _ = w.Append(context.Background(), testEvent("one"))
	_ = w.Close()
	entries, _ := os.ReadDir(dir)
	var path string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".wal") {
			path = filepath.Join(dir, e.Name())
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("torn"))
	_ = f.Close()
	w = testWAL(t, dir)
	defer w.Close()
	if w.Status().Records != 1 {
		t.Fatalf("records=%d", w.Status().Records)
	}
}

func TestWALDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	w := testWAL(t, dir)
	_, _ = w.Append(context.Background(), testEvent("one"))
	_ = w.Close()
	entries, _ := os.ReadDir(dir)
	var path string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".wal") {
			path = filepath.Join(dir, e.Name())
		}
	}
	b, _ := os.ReadFile(path)
	b[len(b)-5] ^= 0x7f
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWAL(WALConfig{Dir: dir, HMACKey: []byte(strings.Repeat("h", 32))}); err == nil || !strings.Contains(err.Error(), ErrCorrupt.Error()) {
		t.Fatalf("tamper error=%v", err)
	}
}

func TestWALEncryptionKeyRotation(t *testing.T) {
	dir := t.TempDir()
	keyring := filepath.Join(dir, "keys.json")
	k1, k2 := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(k1)
	_, _ = rand.Read(k2)
	writeKeys := func(active string, keys map[string][]byte) {
		encoded := map[string]string{}
		for id, key := range keys {
			encoded[id] = base64.StdEncoding.EncodeToString(key)
		}
		data, _ := json.Marshal(map[string]any{"active": active, "keys": encoded})
		if err := os.WriteFile(keyring, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeKeys("one", map[string][]byte{"one": k1})
	w, err := OpenWAL(WALConfig{Dir: dir, HMACKey: []byte(strings.Repeat("h", 32)), EncryptionKeyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Append(context.Background(), testEvent("encrypted"))
	_ = w.Close()
	writeKeys("two", map[string][]byte{"one": k1, "two": k2})
	w, err = OpenWAL(WALConfig{Dir: dir, HMACKey: []byte(strings.Repeat("h", 32)), EncryptionKeyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestExporterRetryStableIDAndDLQ(t *testing.T) {
	var calls atomic.Int32
	var idempotency string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idempotency = r.Header.Get("Idempotency-Key")
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	dir := t.TempDir()
	w := testWAL(t, dir)
	defer w.Close()
	event, _ := w.Append(context.Background(), testEvent("export"))
	e, err := NewExporter(w, ExporterConfig{URL: server.URL, BatchSize: 1, MaxRetries: 2, RetryBase: time.Millisecond, RetryMax: 2 * time.Millisecond, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || idempotency == "" || e.Status().Exported != 1 {
		t.Fatalf("calls=%d key=%q status=%+v event=%+v", calls.Load(), idempotency, e.Status(), event)
	}
}

func TestExporterPermanentErrorQuarantinesAndCheckpoints(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "rejected", http.StatusBadRequest)
	}))
	defer server.Close()
	dir := t.TempDir()
	w := testWAL(t, dir)
	defer w.Close()
	_, _ = w.Append(context.Background(), testEvent("dead"))
	e, err := NewExporter(w, ExporterConfig{URL: server.URL, BatchSize: 1, MaxRetries: 1, RetryBase: time.Millisecond, RetryMax: time.Millisecond, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.Status().DeadLetter != 1 {
		t.Fatalf("status=%+v", e.Status())
	}
	if _, err := os.Stat(filepath.Join(dir, "dead-letter")); err != nil {
		t.Fatal(err)
	}
	e2, err := NewExporter(w, ExporterConfig{URL: server.URL, BatchSize: 1, MaxRetries: 0, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := e2.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("checkpoint did not suppress replay: calls=%d", calls.Load())
	}
}
