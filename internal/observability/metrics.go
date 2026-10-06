// Package observability exposes the spec §15 metrics surface. Counters and
// histograms are Prometheus-compatible; a Noop recorder keeps pipeline call
// sites free of nil checks in tests.
package observability

import (
	"net/http"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Recorder receives pipeline observability events. Implementations must
// never receive raw content.
type Recorder interface {
	ObserveRequest(action core.Action, mode string)
	ObserveFindings(category, subtype string)
	ObserveLaya(ms float64, failed bool)
	ObserveScanner(ms float64)
	ObserveSecurityLatency(ms float64)
	ObserveShadowDisagreement(predicted core.Action)
	ObserveFallback()
	ObserveTokens(n int, action string)
	ObserveFalsePositiveSample()
}

// Metrics is the Prometheus implementation of Recorder (spec §15). The
// action-specific counters (blocked/tokenized/redacted/review) are redundant
// with requests_total{action,mode} but the spec names them explicitly, so
// they are provided verbatim.
type Metrics struct {
	requestsTotal       *prometheus.CounterVec
	blockedTotal        prometheus.Counter
	tokenizedTotal      prometheus.Counter
	redactedTotal       prometheus.Counter
	reviewTotal         prometheus.Counter
	findingsTotal       *prometheus.CounterVec
	layaCallsTotal      prometheus.Counter
	layaErrorsTotal     prometheus.Counter
	layaLatency         prometheus.Histogram
	scannerLatency      prometheus.Histogram
	securityLatency     prometheus.Histogram
	shadowDisagreements prometheus.Counter
	falsePositiveSample prometheus.Counter
	fallbackTotal       prometheus.Counter
	transformations     *prometheus.CounterVec
	registry            *prometheus.Registry
}

// New builds the metric set and registers it on a private registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "requests_total", Help: "Security gateway requests by action and mode (spec §15 requests_total).",
		}, []string{"action", "mode"}),
		blockedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "blocked_total", Help: "Requests whose policy action was BLOCK.",
		}),
		tokenizedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tokenized_total", Help: "Requests whose policy action was TOKENIZE.",
		}),
		redactedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "redacted_total", Help: "Requests whose policy action was REDACT.",
		}),
		reviewTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "review_total", Help: "Requests whose policy action was REVIEW.",
		}),
		findingsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "findings_total", Help: "Security findings by category and subtype.",
		}, []string{"category", "subtype"}),
		layaCallsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "laya_calls_total", Help: "Semantic provider calls.",
		}),
		layaErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "laya_errors_total", Help: "Semantic provider failures.",
		}),
		layaLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "laya_latency_ms",
			Help:    "Semantic provider latency (ms).",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
		}),
		scannerLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "scanner_latency_ms",
			Help:    "Deterministic scan latency (ms).",
			Buckets: []float64{0.5, 1, 2, 5, 10, 25, 50, 100},
		}),
		securityLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "gateway_security_latency_ms",
			Help:    "Total security pipeline latency excluding Laya (ms).",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250},
		}),
		shadowDisagreements: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "shadow_disagreements_total", Help: "Shadow-mode predictions that would change the incumbent path (predicted action not ALLOW), across request, response, and tool boundaries.",
		}),
		falsePositiveSample: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "false_positive_sample_total", Help: "Shadow-mode predicted blocks with no deterministic finding, sampled for FP review.",
		}),
		fallbackTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fallback_total", Help: "Policy fallback executions (e.g. Laya unavailable).",
		}),
		transformations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "transformations_total", Help: "Content transformations applied.",
		}, []string{"action"}),
		registry: reg,
	}
	reg.MustRegister(m.requestsTotal, m.blockedTotal, m.tokenizedTotal, m.redactedTotal,
		m.reviewTotal, m.findingsTotal, m.layaCallsTotal, m.layaErrorsTotal,
		m.layaLatency, m.scannerLatency, m.securityLatency, m.shadowDisagreements,
		m.falsePositiveSample, m.fallbackTotal, m.transformations)
	return m
}

// Handler serves the Prometheus exposition format on /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) ObserveRequest(action core.Action, mode string) {
	m.requestsTotal.WithLabelValues(string(action), mode).Inc()
	switch action {
	case core.ActionBlock:
		m.blockedTotal.Inc()
	case core.ActionTokenize:
		m.tokenizedTotal.Inc()
	case core.ActionRedact:
		m.redactedTotal.Inc()
	case core.ActionReview:
		m.reviewTotal.Inc()
	}
}

// ObserveFalsePositiveSample records a shadow-mode predicted block with no
// deterministic finding — the FP-review sample stream (spec §15).
func (m *Metrics) ObserveFalsePositiveSample() { m.falsePositiveSample.Inc() }

func (m *Metrics) ObserveFindings(category, subtype string) {
	m.findingsTotal.WithLabelValues(string(category), subtype).Inc()
}

func (m *Metrics) ObserveLaya(ms float64, failed bool) {
	m.layaCallsTotal.Inc()
	if failed {
		m.layaErrorsTotal.Inc()
		return
	}
	m.layaLatency.Observe(ms)
}

func (m *Metrics) ObserveScanner(ms float64) { m.scannerLatency.Observe(ms) }

func (m *Metrics) ObserveSecurityLatency(ms float64) { m.securityLatency.Observe(ms) }

func (m *Metrics) ObserveShadowDisagreement(predicted core.Action) {
	if predicted != core.ActionAllow {
		m.shadowDisagreements.Inc()
	}
}

func (m *Metrics) ObserveFallback() { m.fallbackTotal.Inc() }

func (m *Metrics) ObserveTokens(n int, action string) {
	if n > 0 {
		m.transformations.WithLabelValues(action).Add(float64(n))
	}
}

// Noop is a Recorder that discards everything (tests, metrics disabled).
type Noop struct{}

func (Noop) ObserveRequest(core.Action, string)    {}
func (Noop) ObserveFindings(string, string)        {}
func (Noop) ObserveLaya(float64, bool)             {}
func (Noop) ObserveScanner(float64)                {}
func (Noop) ObserveSecurityLatency(float64)        {}
func (Noop) ObserveShadowDisagreement(core.Action) {}
func (Noop) ObserveFallback()                      {}
func (Noop) ObserveTokens(int, string)             {}
func (Noop) ObserveFalsePositiveSample()           {}
