// Package dashboard exposes the sanitized protection statistics used by the
// leaderboard UI.
package dashboard

import (
	"sort"
	"time"

	"github.com/aegisllm/gateway/internal/observability"
)

// CategoryStat is one leaderboard row. It contains metric labels, never raw
// inspected content.
type CategoryStat struct {
	Category string `json:"category"`
	Subtype  string `json:"subtype"`
	Count    uint64 `json:"count"`
}

// Stats is the complete JSON response for the protection leaderboard.
type Stats struct {
	TotalPrevented uint64         `json:"total_prevented"`
	Blocked        uint64         `json:"blocked"`
	Tokenized      uint64         `json:"tokenized"`
	Redacted       uint64         `json:"redacted"`
	Review         uint64         `json:"review"`
	Allowed        uint64         `json:"allowed"`
	StreamBytes    uint64         `json:"stream_bytes_inspected"`
	StreamEvents   uint64         `json:"stream_events_inspected"`
	ByCategory     []CategoryStat `json:"by_category"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// Dashboard reads protection counters from the Prometheus implementation.
type Dashboard struct {
	metrics *observability.Metrics
}

// MetricsProvider is implemented by the metrics HTTP handler so the gateway
// can wire the dashboard without a second metrics configuration path.
type MetricsProvider interface {
	ProtectionMetrics() *observability.Metrics
}

// New creates a dashboard backed by metrics. A nil metrics pointer is valid
// and produces an empty, well-formed snapshot.
func New(metrics *observability.Metrics) *Dashboard {
	return &Dashboard{metrics: metrics}
}

// Snapshot returns a point-in-time, content-free dashboard view.
func (d *Dashboard) Snapshot() Stats {
	if d == nil {
		return Snapshot(nil)
	}
	return Snapshot(d.metrics)
}

// Snapshot projects the observability registry into the public dashboard
// contract. Applied stream actions are included alongside request actions;
// shadow predictions do not increment prevented totals.
func Snapshot(metrics *observability.Metrics) Stats {
	metricSnapshot := metrics.Snapshot()
	stats := Stats{
		Blocked:     metricSnapshot.Blocked,
		Tokenized:   metricSnapshot.Tokenized,
		Redacted:    metricSnapshot.Redacted,
		Review:      metricSnapshot.Review,
		Allowed:     metricSnapshot.Allowed,
		StreamBytes: metricSnapshot.StreamBytes, StreamEvents: metricSnapshot.StreamEvents,
		ByCategory: []CategoryStat{},
		UpdatedAt:  time.Now().UTC(),
	}
	stats.TotalPrevented = stats.Blocked + stats.Tokenized + stats.Redacted + stats.Review
	for _, finding := range metricSnapshot.Findings {
		stats.ByCategory = append(stats.ByCategory, CategoryStat{
			Category: finding.Category,
			Subtype:  finding.Subtype,
			Count:    finding.Count,
		})
	}
	sort.Slice(stats.ByCategory, func(i, j int) bool {
		if stats.ByCategory[i].Count != stats.ByCategory[j].Count {
			return stats.ByCategory[i].Count > stats.ByCategory[j].Count
		}
		if stats.ByCategory[i].Category != stats.ByCategory[j].Category {
			return stats.ByCategory[i].Category < stats.ByCategory[j].Category
		}
		return stats.ByCategory[i].Subtype < stats.ByCategory[j].Subtype
	})
	return stats
}
