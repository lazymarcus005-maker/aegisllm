package pii

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeSpansUnicodeUnits(t *testing.T) {
	text := "A😀 กํา ไทย"
	got, err := NormalizeSpans(text, []RawSpan{{Label: "PERSON", Start: 3, End: 6, Confidence: .9, Unit: OffsetCodepoints}})
	if err != nil || len(got) != 1 || text[got[0].Start:got[0].End] != "กํา" {
		t.Fatalf("codepoint conversion: %+v %v", got, err)
	}
	got, err = NormalizeSpans("A😀B", []RawSpan{{Label: "PERSON", Start: 1, End: 3, Confidence: .9, Unit: OffsetUTF16}})
	if err != nil || len(got) != 1 || "A😀B"[got[0].Start:got[0].End] != "😀" {
		t.Fatalf("UTF-16 conversion: %+v %v", got, err)
	}
	if _, err := NormalizeSpans("ไทย", []RawSpan{{Label: "X", Start: 1, End: 4, Confidence: .9, Unit: OffsetBytes}}); err == nil {
		t.Fatal("misaligned byte span must be rejected")
	}
	if _, err := NormalizeSpans("abcdef", []RawSpan{{Label: "A", Start: 0, End: 3, Confidence: .9, Unit: OffsetBytes}, {Label: "B", Start: 2, End: 4, Confidence: .9, Unit: OffsetBytes}}); err == nil {
		t.Fatal("overlapping provider spans must be rejected")
	}
}

func TestAegisAdapterChunkOverlapAndOffsets(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var in struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		var spans []map[string]any
		if i := strings.Index(in.Text, "needle"); i >= 0 {
			spans = append(spans, map[string]any{"entity": "PERSON", "start": i, "end": i + 6, "confidence": .91, "offset_unit": "byte"})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"schema": ProviderSchema, "version": 1, "spans": spans})
	}))
	defer server.Close()
	p, err := NewAegisNERAdapter(HTTPProviderConfig{ID: "fake", URL: server.URL, Timeout: time.Second, MaxChars: 12, ChunkOverlap: 6, MaxConcurrent: 2, Breaker: 3, BreakerOpen: time.Second, FailBehavior: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.SpansContext(context.Background(), "prefix needle and a long tail")
	if err != nil || len(got) != 1 {
		t.Fatalf("spans=%+v err=%v", got, err)
	}
	if got[0].Start != strings.Index("prefix needle and a long tail", "needle") {
		t.Fatalf("offset was not reassembled: %+v", got[0])
	}
	if calls.Load() < 2 {
		t.Fatalf("expected chunked calls, got %d", calls.Load())
	}
}

func TestPresidioAdapterContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/analyze" || r.Header.Get("X-Aegis-Correlation-ID") == "" {
			t.Fatalf("presidio request contract: path=%s correlation=%q", r.URL.Path, r.Header.Get("X-Aegis-Correlation-ID"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"entity":"PERSON","start":3,"end":6,"score":0.95}]`))
	}))
	defer server.Close()
	p, err := NewPresidioHTTPAdapter(HTTPProviderConfig{ID: "presidio", URL: server.URL, Timeout: time.Second, MaxChars: 100, MaxConcurrent: 1, Breaker: 2, BreakerOpen: time.Second, FailBehavior: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	text := "A😀 กํา"
	spans, err := p.SpansContext(context.Background(), text)
	if err != nil || len(spans) != 1 || text[spans[0].Start:spans[0].End] != "กํา" {
		t.Fatalf("Presidio span: %+v err=%v", spans, err)
	}
}

func TestRemoteTimeoutAndBreaker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
		case <-time.After(50 * time.Millisecond):
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	p, err := NewAegisNERAdapter(HTTPProviderConfig{ID: "slow", URL: server.URL, Timeout: 10 * time.Millisecond, MaxChars: 100, MaxConcurrent: 1, Breaker: 1, BreakerOpen: time.Minute, FailBehavior: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.SpansContext(context.Background(), "hello"); err == nil {
		t.Fatal("timeout must fail")
	}
	if _, err := p.SpansContext(context.Background(), "hello"); err == nil {
		t.Fatal("open breaker must fail")
	}
	if p.Status().Breaker != "open" {
		t.Fatalf("breaker status: %+v", p.Status())
	}
}
