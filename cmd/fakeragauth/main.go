// Command fakeragauth is a deterministic, non-production RAG authorization
// fixture. It authorizes only well-formed, content-free contracts and never
// logs queries, document text, labels, or identities.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/ragauth"
	"github.com/aegisllm/gateway/internal/securetransport"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/authorize", authorize)
	log.Println("fake RAG authorization service listening on :8500")
	if err := securetransport.ServeHTTPServer(securetransport.NewHTTPServer(":8500", mux), "", ""); err != nil {
		log.Fatal(err)
	}
}

func authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in ragauth.Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&in); err != nil || in.Version != 1 || in.RequestID == "" || in.Identity.Tenant == "" || in.Identity.Application == "" || in.Retrieval.QueryDigest == "" {
		http.Error(w, "invalid authorization contract", http.StatusBadRequest)
		return
	}
	if in.Identity.Tenant == "tenant-denied" {
		writeDecision(w, in, ragauth.ActionDeny)
		return
	}
	if in.Resource != nil && (in.Resource.DocumentID == "" || in.Resource.ContentDigest == "") {
		http.Error(w, "invalid resource contract", http.StatusBadRequest)
		return
	}
	writeDecision(w, in, ragauth.ActionAllow)
}

func writeDecision(w http.ResponseWriter, in ragauth.Request, action string) {
	expires := time.Now().Add(10 * time.Second)
	d := ragauth.Decision{DecisionID: "fake-" + strings.ReplaceAll(in.Retrieval.Operation, "_", "-"), Action: action, ExpiresAt: expires}
	d.Binding = ragauth.Binding(in, d.DecisionID, d.Action, d.ExpiresAt)
	_ = json.NewEncoder(w).Encode(ragauth.AuthorizeResponse{Version: 1, Decision: d})
}
