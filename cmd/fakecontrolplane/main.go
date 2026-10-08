// Command fakecontrolplane is a deliberately non-production HTTPS/control
// plane fixture. It serves one signed bundle envelope and supports ETag
// polling so integration tests can exercise gateway distribution behavior.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/aegisllm/gateway/internal/policydistribution"
	"github.com/aegisllm/gateway/internal/securetransport"
)

func main() {
	bundlePath := flag.String("bundle", "", "signed bundle directory")
	addr := flag.String("addr", ":8091", "listen address")
	cert := flag.String("cert", "", "optional TLS certificate")
	key := flag.String("key", "", "optional TLS private key")
	flag.Parse()
	if *bundlePath == "" {
		slog.Error("fake control plane requires -bundle")
		os.Exit(2)
	}
	bundle, err := policydistribution.ReadDirectory(*bundlePath)
	if err != nil {
		slog.Error("bundle unavailable", "error", err)
		os.Exit(1)
	}
	files := map[string]string{}
	for name, data := range bundle.Files {
		files[name] = base64.StdEncoding.EncodeToString(data)
	}
	envelope, _ := json.Marshal(struct {
		Manifest  policydistribution.Manifest `json:"manifest"`
		Signature string                      `json:"signature"`
		Files     map[string]string           `json:"files"`
	}{bundle.Manifest, base64.StdEncoding.EncodeToString(bundle.Signature), files})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("ETag", "\""+bundle.Hash()+"\"")
		if r.Header.Get("If-None-Match") == "\""+bundle.Hash()+"\"" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelope)
	})
	slog.Warn("fake control plane is non-production test infrastructure")
	if err := securetransport.ServeHTTPServer(securetransport.NewHTTPServer(*addr, handler), *cert, *key); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
