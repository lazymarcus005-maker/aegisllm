package dashboard

import (
	"testing"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/observability"
)

func TestSnapshotProjectsProtectionCountersAndSortsFindings(t *testing.T) {
	metrics := observability.New()
	metrics.ObserveRequest(core.ActionBlock, "enforce")
	metrics.ObserveRequest(core.ActionBlock, "shadow")
	metrics.ObserveRequest(core.ActionTokenize, "enforce")
	metrics.ObserveRequest(core.ActionRedact, "enforce")
	metrics.ObserveRequest(core.ActionReview, "enforce")
	metrics.ObserveRequest(core.ActionAllow, "enforce")
	metrics.ObserveRequest(core.ActionAllow, "shadow")
	metrics.ObserveFindings(string(core.CategorySecret), "api_key")
	metrics.ObserveFindings(string(core.CategoryPII), "phone")
	metrics.ObserveFindings(string(core.CategoryPII), "phone")

	stats := Snapshot(metrics)
	if stats.TotalPrevented != 5 {
		t.Fatalf("total prevented = %d, want 5", stats.TotalPrevented)
	}
	if stats.Blocked != 2 || stats.Tokenized != 1 || stats.Redacted != 1 || stats.Review != 1 {
		t.Fatalf("action counters = %+v", stats)
	}
	if stats.Allowed != 2 {
		t.Fatalf("allowed = %d, want 2", stats.Allowed)
	}
	if len(stats.ByCategory) != 2 || stats.ByCategory[0].Subtype != "phone" || stats.ByCategory[0].Count != 2 {
		t.Fatalf("findings not sorted/projected: %+v", stats.ByCategory)
	}
	if stats.UpdatedAt.IsZero() {
		t.Fatal("updated_at must be populated")
	}
}

func TestNilSnapshotIsWellFormed(t *testing.T) {
	stats := Snapshot(nil)
	if stats.TotalPrevented != 0 || stats.Allowed != 0 || stats.ByCategory == nil {
		t.Fatalf("unexpected empty snapshot: %+v", stats)
	}
}
