package observability

import "testing"

func TestQuarantineMetricsRemainBounded(t *testing.T) {
	m := New()
	for i := 0; i < 2000; i++ {
		m.ObserveQuarantine("attacker-controlled-"+string(rune(i)), "attacker-level", "attacker-scope")
		m.ObserveQuarantineDecision("attacker-outcome")
	}
	families, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "quarantine_events_total" && len(family.GetMetric()) > 1 {
			t.Fatalf("unbounded quarantine event labels: %d", len(family.GetMetric()))
		}
		if family.GetName() == "quarantine_decisions_total" && len(family.GetMetric()) > 1 {
			t.Fatalf("unbounded quarantine outcome labels: %d", len(family.GetMetric()))
		}
	}
}
