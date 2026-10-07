package dashboard

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRollingAggregatorRotatesAndCapsDimensions(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	agg := NewRollingAggregator(time.Minute, 5, clock)
	for i := 0; i < MaxDimension+8; i++ {
		agg.RecordFindingAt(now, "PII", "subtype-"+time.Duration(i).String())
	}
	agg.RecordRequestAt(now, "BLOCK", "enforce")
	now = now.Add(6 * time.Minute)
	agg.RecordRequestAt(now, "ALLOW", "enforce")
	if len(agg.buckets) != 5 {
		t.Fatalf("bucket memory grew: %d", len(agg.buckets))
	}
	for _, b := range agg.buckets {
		if len(b.findings) > MaxDimension {
			t.Fatalf("finding cardinality exceeded cap: %d", len(b.findings))
		}
	}
	v := &V2{aggregator: agg}
	query := Query{Window: 5 * time.Minute, Bucket: time.Minute}
	overview, series, breakdown := v.snapshot(query)
	if overview.Funnel.Inspected != 1 || overview.Funnel.Forwarded != 1 {
		t.Fatalf("rotation retained expired events: %+v", overview.Funnel)
	}
	if len(series.Points) != 6 || len(breakdown.Categories) != 0 {
		t.Fatalf("unexpected snapshot shape: points=%d breakdown=%+v", len(series.Points), breakdown)
	}
}

func TestRollingAggregatorConcurrentWritesRemainBounded(t *testing.T) {
	agg := NewRollingAggregator(time.Minute, 10, time.Now)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				agg.ObserveDashboardRequest("TOKENIZE", "enforce")
				agg.ObserveDashboardRuntime("rate_limited")
			}
		}()
	}
	wg.Wait()
	v := &V2{aggregator: agg}
	overview, _, _ := v.snapshot(Query{Window: time.Minute, Bucket: time.Minute})
	if overview.Funnel.Inspected != 2000 {
		t.Fatalf("concurrent inspected=%d, want 2000", overview.Funnel.Inspected)
	}
}

func TestDashboardQueryValidationAndVersionedHandlers(t *testing.T) {
	for _, raw := range []string{"?window=25h", "?window=1h&bucket=10s", "?window=1h&bucket=1m&action=not-an-action"} {
		req := httptest.NewRequest("GET", "/api/dashboard/v2/overview"+raw, nil)
		if _, err := ParseQuery(req); err == nil {
			t.Fatalf("query %q was accepted", raw)
		}
	}
	clock := time.Now
	v := &V2{aggregator: NewRollingAggregator(time.Minute, 10, clock)}
	req := httptest.NewRequest("GET", "/api/dashboard/v2/overview?window=15m", nil)
	resp := httptest.NewRecorder()
	v.HandleOverview(resp, req)
	if resp.Code != 200 || resp.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("handler response=%d cache=%q", resp.Code, resp.Header().Get("Cache-Control"))
	}
	if got := resp.Body.String(); len(got) < len(APIVersion) || !contains(got, APIVersion) {
		t.Fatalf("versioned response missing: %s", got)
	}
}

func contains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
