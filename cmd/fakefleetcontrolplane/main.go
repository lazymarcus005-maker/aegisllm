// Command fakefleetcontrolplane is deterministic test infrastructure only.
// Its signer is generated at process start and is never a production key.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aegisllm/gateway/internal/fleet"
)

func main() {
	addr := flag.String("addr", ":8092", "listen address")
	flag.Parse()
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		slog.Error("fake fleet signer failed", "error", err)
		os.Exit(1)
	}
	cp, err := fleet.NewFakeControlPlane(fleet.FakeConfig{Signer: signer, Issuer: "fake-fleet-controller", KeyID: "fake-fleet-key", TrustDomain: "fake-fleet"})
	if err != nil {
		slog.Error("fake fleet configuration failed", "error", err)
		os.Exit(1)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "evidence": "fake-contract-only"})
			return
		}
		cp.ServeHTTP(w, r)
	})
	slog.Warn("fake fleet control plane is non-production test infrastructure")
	server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		slog.Error("fake fleet server stopped", "error", err)
		os.Exit(1)
	}
}
