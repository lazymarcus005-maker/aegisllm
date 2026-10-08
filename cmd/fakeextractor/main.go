// Command fakeextractor is a bounded, local-only extraction contract fixture.
// It is for integration tests and conformance labs; it is not an OCR engine
// and must never be used as a production promotion dependency.
package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"
)

type request struct {
	MIMEType string `json:"mime_type"`
	Data     string `json:"data"`
}
type response struct {
	Text     string            `json:"text,omitempty"`
	Pages    int               `json:"pages,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func main() {
	max := int64(6 << 20)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/extract" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
		if err != nil || int64(len(body)) > max {
			http.Error(w, "request rejected", http.StatusRequestEntityTooLarge)
			return
		}
		var in request
		if json.Unmarshal(body, &in) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		data, err := base64.RawStdEncoding.DecodeString(in.Data)
		if err != nil || int64(len(data)) > max {
			http.Error(w, "invalid data", http.StatusBadRequest)
			return
		}
		out := response{Metadata: map[string]string{"profile": "fake", "mime_type": in.MIMEType}}
		if in.MIMEType == "text/plain" || in.MIMEType == "application/json" {
			out.Text = string(data)
		}
		if in.MIMEType == "application/pdf" {
			out.Pages = 1
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	addr := os.Getenv("FAKE_EXTRACTOR_ADDR")
	if addr == "" {
		addr = ":8421"
	}
	server := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		os.Exit(1)
	}
}
