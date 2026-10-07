package credentialbroker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHeaderCredentialRotation(t *testing.T) {
	dir := t.TempDir()
	secret := dir + "/secret"
	if err := os.WriteFile(secret, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	registry := dir + "/registry.yaml"
	writeBrokerFile(t, registry, fmt.Sprintf(`schema: aegisllm.credentials/v1
version: 1
profiles:
  - id: header
    type: header
    header: X-Credential
    secret_file: %s
`, secret))
	broker, err := New(registry, Config{PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	got, err := broker.Get(context.Background(), "header")
	if err != nil {
		t.Fatal(err)
	}
	if got.Headers.Get("X-Credential") != "first" {
		t.Fatalf("initial credential=%q", got.Headers.Get("X-Credential"))
	}
	if err := os.WriteFile(secret, []byte("rotated"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got, err = broker.Get(context.Background(), "header")
		if err == nil && got.Headers.Get("X-Credential") == "rotated" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("rotated credential did not become active: %v", err)
}

func TestOAuthClientCredentialsSingleflightAndFailClosed(t *testing.T) {
	var requests atomic.Int32
	var fail atomic.Bool
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if fail.Load() {
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		time.Sleep(40 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"oauth-token","token_type":"Bearer","expires_in":60}`))
	}))
	defer tokenServer.Close()
	dir := t.TempDir()
	secret := dir + "/client-secret"
	if err := os.WriteFile(secret, []byte("client-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	registry := dir + "/registry.yaml"
	writeBrokerFile(t, registry, fmt.Sprintf(`schema: aegisllm.credentials/v1
version: 1
profiles:
  - id: oauth
    type: oauth2_client_credentials
    token_url: %s
    client_id: agent
    client_secret_file: %s
`, tokenServer.URL, secret))
	broker, err := New(registry, Config{PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, callErr := broker.Get(context.Background(), "oauth")
			if callErr != nil || got.Headers.Get("Authorization") != "Bearer oauth-token" {
				t.Errorf("oauth result=%v err=%v", got.Headers, callErr)
			}
		}()
	}
	wg.Wait()
	if got := requests.Load(); got != 1 {
		t.Fatalf("expected one token request, got %d", got)
	}
	// Expire the cached token and make the provider fail; the broker must not
	// return a stale token after safe-before-expiry refresh has failed.
	fail.Store(true)
	broker.mu.Lock()
	broker.states["oauth"].mu.Lock()
	broker.states["oauth"].expires = time.Now().Add(-time.Second)
	broker.states["oauth"].mu.Unlock()
	broker.mu.Unlock()
	if _, err := broker.Get(context.Background(), "oauth"); err == nil {
		t.Fatal("OAuth failure returned a credential")
	}
}

func writeBrokerFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
