package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This is intentionally a tolerance check: scheduler and HTTP transport
// internals vary by Go release, but repeated cancellation must not grow
// process resources without bound.
func TestCanceledRequestResourceGrowthWithinTolerance(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Millisecond):
		}
	}))
	defer upstream.Close()
	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	baseFDs := fdCount(t)
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	for i := 0; i < 80; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		path := []string{"/stream", "/mcp/cloud", "/exporter"}[i%3]
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL+path, strings.NewReader(cleanRequest))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, _ := http.DefaultClient.Do(req)
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		cancel()
	}
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if got := runtime.NumGoroutine(); got > baseGoroutines+40 {
		t.Fatalf("canceled requests grew goroutines beyond tolerance: before=%d after=%d", baseGoroutines, got)
	}
	if got := fdCount(t); got > baseFDs+12 {
		t.Fatalf("canceled requests grew file descriptors beyond tolerance: before=%d after=%d", baseFDs, got)
	}
	if after.HeapAlloc > base.HeapAlloc+32<<20 {
		t.Fatalf("canceled requests grew heap beyond tolerance: before=%d after=%d", base.HeapAlloc, after.HeapAlloc)
	}
}

func fdCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}
