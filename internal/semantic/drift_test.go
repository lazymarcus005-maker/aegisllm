package semantic

import (
	"testing"
	"time"
)

func driftFixture(t *testing.T) *Monitor {
	m, err := NewMonitor(ModelRef{ID: "m", Version: "1", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, Policy{MinSamples: 10, MinLabelSamples: 5, Window: time.Hour, PSIWarning: .1, PSIAction: .2, JSWarning: .1, KSWarning: .2, SustainedWindows: 2, Cooldown: time.Hour, AutoRollback: true, HealthyRollbackTarget: true}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func TestLowVolumeAndTransientDriftSuppression(t *testing.T) {
	m := driftFixture(t)
	if err := m.Observe(Sample{TenantScope: "tenant-a", Features: []Distribution{{Feature: "language", Samples: 2, Buckets: []Bucket{{Label: "en", Count: 2}}}}}); err != nil {
		t.Fatal(err)
	}
	if st := m.Evaluate([]Distribution{{Feature: "language", Samples: 100, Buckets: []Bucket{{Label: "en", Count: 100}}}}, nil); !st.Suppressed {
		t.Fatal("low volume drift was not suppressed")
	}
	for i := 0; i < 10; i++ {
		if err := m.Observe(Sample{TenantScope: "tenant-a", Features: []Distribution{{Feature: "language", Samples: 10, Buckets: []Bucket{{Label: "th", Count: 10}}}}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Observe(Sample{TenantScope: "tenant-b", Features: []Distribution{{Feature: "language", Samples: 10, Buckets: []Bucket{{Label: "th", Count: 10}}}}}); err != nil {
		t.Fatal(err)
	}
	st := m.Evaluate([]Distribution{{Feature: "language", Samples: 100, Buckets: []Bucket{{Label: "en", Count: 100}}}}, nil)
	if st.Action != "warning" {
		t.Fatalf("transient first action=%s", st.Action)
	}
	st = m.Evaluate([]Distribution{{Feature: "language", Samples: 100, Buckets: []Bucket{{Label: "en", Count: 100}}}}, nil)
	if st.Action != "rollback_champion" {
		t.Fatalf("sustained action=%s", st.Action)
	}
}
func TestDriftLabelsAndPrivacyBounds(t *testing.T) {
	m := driftFixture(t)
	if err := m.Observe(Sample{TenantScope: "tenant-a", Features: []Distribution{{Feature: "prompt text", Samples: 1, Buckets: []Bucket{{Label: "x", Count: 1}}}}}); err == nil {
		t.Fatal("raw-like feature accepted")
	}
	if err := m.Observe(Sample{TenantScope: "tenant-a", Features: []Distribution{{Feature: "language", Samples: 1, Buckets: []Bucket{{Label: "x", Count: 2}}}}}); err == nil {
		t.Fatal("inconsistent distribution accepted")
	}
}
