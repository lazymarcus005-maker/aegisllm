package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwardPreservesPathBodyAndContentType(t *testing.T) {
	var gotPath, gotBody, gotCT, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	p, err := NewProxy(Config{UpstreamBaseURL: upstream.URL, UpstreamAuthMode: "none"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://gateway.local/v1/chat/completions", nil)
	req = req.WithContext(context.Background())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer client-credential-that-must-not-leak")

	resp, err := p.Forward(req, []byte(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if gotPath != "/v1/chat/completions" {
		t.Fatalf("path: %s", gotPath)
	}
	if gotBody != `{"model":"m"}` {
		t.Fatalf("body: %s", gotBody)
	}
	if gotCT != "application/json" {
		t.Fatalf("content type: %s", gotCT)
	}
	// Inbound credentials must never reach the upstream in none mode.
	if gotAuth != "" {
		t.Fatalf("inbound authorization leaked upstream: %s", gotAuth)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("response body: %s", body)
	}
}

func TestForwardBearerAuthMode(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	p, err := NewProxy(Config{UpstreamBaseURL: upstream.URL, UpstreamAuthMode: "bearer", UpstreamAPIKey: "upstream-secret"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://g/v1/chat/completions", nil)
	if _, err := p.Forward(req, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer upstream-secret" {
		t.Fatalf("auth: %s", gotAuth)
	}
}

func TestForwardStripsConfiguredPathPrefix(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p, err := NewProxy(Config{UpstreamBaseURL: upstream.URL, UpstreamAuthMode: "none", UpstreamChatPathPrefix: "/generic"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://gateway.local/generic/v1/messages", nil)
	resp, err := p.Forward(req, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotPath != "/v1/messages" {
		t.Fatalf("path: %s", gotPath)
	}
}

func TestNewProxyValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing base url", Config{UpstreamAuthMode: "none"}},
		{"bad scheme url", Config{UpstreamBaseURL: "://bad", UpstreamAuthMode: "none"}},
		{"bearer without key", Config{UpstreamBaseURL: "http://x", UpstreamAuthMode: "bearer"}},
		{"header mode incomplete", Config{UpstreamBaseURL: "http://x", UpstreamAuthMode: "header", UpstreamAuthHeaderName: "H"}},
		{"unknown mode", Config{UpstreamBaseURL: "http://x", UpstreamAuthMode: "magic"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewProxy(tc.cfg); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func BenchmarkProxyForward(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	p, err := NewProxy(Config{UpstreamBaseURL: upstream.URL, UpstreamAuthMode: "none"})
	if err != nil {
		b.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/chat/completions", nil)
	body := []byte(`{"model":"m"}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp, err := p.Forward(req, body)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
