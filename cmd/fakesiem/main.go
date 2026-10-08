// Command fakesiem is a small in-repository SIEM webhook for integration
// tests. It records only batch metadata and never logs request bodies.
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/aegisllm/gateway/internal/securetransport"
)

var calls atomic.Int64

func main() {
	fails, _ := strconv.ParseInt(os.Getenv("FAKE_SIEM_FAILS"), 10, 64)
	h := http.NewServeMux()
	h.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		var batch struct {
			Events []json.RawMessage `json:"events"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&batch) != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		if calls.Add(1) <= fails {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	cert, key := os.Getenv("FAKE_SIEM_CERT_FILE"), os.Getenv("FAKE_SIEM_KEY_FILE")
	if err := securetransport.ServeHTTPServer(securetransport.NewHTTPServer(":9200", h), cert, key); err != nil {
		panic(err)
	}
}
