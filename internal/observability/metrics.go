// Package observability exposes the spec §15 metrics surface. Counters and
// histograms are Prometheus-compatible; a Noop recorder keeps pipeline call
// sites free of nil checks in tests.
package observability

import (
	"fmt"
	"net/http"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
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
	ObserveFallbackReason(reason string)
	ObserveSemanticRejected(reason string)
	ObserveSchemaMismatch()
	ObserveCheckpointMismatch()
	ObserveMissingDecision()
	ObserveTokens(n int, action string)
	ObserveFalsePositiveSample()
}

// RuntimeRecorder contains content-free counters and gauges for admission and
// dependency protection. Labels are deliberately omitted to avoid tenant or
// application cardinality.
type RuntimeRecorder interface {
	ObserveRateLimited()
	ObserveConcurrencyRejected()
	ObservePromptBudgetRejected()
	ObserveResponseTooLarge()
	ObserveUpstreamTimeout()
	ObserveBreakerOpen()
	IncActiveRequests()
	DecActiveRequests()
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
	rateLimited         prometheus.Counter
	concurrencyRejected prometheus.Counter
	promptRejected      prometheus.Counter
	responseTooLarge    prometheus.Counter
	upstreamTimeout     prometheus.Counter
	breakerOpen         prometheus.Counter
	activeRequests      prometheus.Gauge
	activeLaya          prometheus.Gauge
	calibrationInfo     *prometheus.GaugeVec
	semanticRejected    *prometheus.CounterVec
	schemaMismatch      prometheus.Counter
	checkpointMismatch  prometheus.Counter
	missingDecisions    prometheus.Counter
	fallbackReasons     *prometheus.CounterVec
	streamActions       *prometheus.CounterVec
	streamBytes         *prometheus.CounterVec
	streamEvents        *prometheus.CounterVec
	reloadFailures      *prometheus.CounterVec
	certExpiring        *prometheus.CounterVec
	routeSelected       *prometheus.CounterVec
	routeFailover       *prometheus.CounterVec
	routeHealth         *prometheus.GaugeVec
	routeRejected       *prometheus.CounterVec
	routeUnavailable    *prometheus.CounterVec
	nerCalls            *prometheus.CounterVec
	nerLatency          *prometheus.HistogramVec
	evasion             *prometheus.CounterVec
	distribution        *prometheus.CounterVec
	auditEnqueued       prometheus.Counter
	auditDurable        prometheus.Counter
	auditExported       prometheus.Counter
	auditRetried        prometheus.Counter
	auditDeadLetter     prometheus.Counter
	auditCorruption     prometheus.Counter
	auditDropped        prometheus.Counter
	auditQueueBytes     prometheus.Gauge
	auditOldestAge      prometheus.Gauge
	auditExporterState  *prometheus.GaugeVec
	registry            *prometheus.Registry
}

// MetricSnapshot is the dashboard-safe projection of the Prometheus registry.
// It contains counts and metric labels only; it never contains inspected
// request content.
type MetricSnapshot struct {
	Blocked      uint64
	Tokenized    uint64
	Redacted     uint64
	Review       uint64
	Allowed      uint64
	Findings     []FindingSnapshot
	StreamBytes  uint64
	StreamEvents uint64
	LocalApplied uint64
	CloudApplied uint64
}

// FindingSnapshot is one findings_total{category,subtype} sample.
type FindingSnapshot struct {
	Category string
	Subtype  string
	Count    uint64
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
		rateLimited:         prometheus.NewCounter(prometheus.CounterOpts{Name: "rate_limited_total", Help: "Requests rejected by the per-identity rate limiter."}),
		concurrencyRejected: prometheus.NewCounter(prometheus.CounterOpts{Name: "concurrency_rejected_total", Help: "Requests rejected by the per-identity concurrency limiter."}),
		promptRejected:      prometheus.NewCounter(prometheus.CounterOpts{Name: "prompt_budget_rejected_total", Help: "Requests rejected by the normalized prompt character budget."}),
		responseTooLarge:    prometheus.NewCounter(prometheus.CounterOpts{Name: "response_too_large_total", Help: "Upstream responses rejected for exceeding the configured byte budget."}),
		upstreamTimeout:     prometheus.NewCounter(prometheus.CounterOpts{Name: "upstream_timeout_total", Help: "Upstream requests that timed out."}),
		breakerOpen:         prometheus.NewCounter(prometheus.CounterOpts{Name: "breaker_open_total", Help: "Requests rejected because the upstream circuit breaker is open."}),
		activeRequests:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "active_requests", Help: "Current admitted gateway requests."}),
		activeLaya:          prometheus.NewGauge(prometheus.GaugeOpts{Name: "active_laya_evaluations", Help: "Current in-flight Laya evaluations."}),
		calibrationInfo:     prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "semantic_calibration_artifact_info", Help: "Bounded metadata for the loaded semantic calibration artifact."}, []string{"artifact_id", "artifact_version", "provider", "checkpoint", "schema_version", "state", "calibration_timestamp"}),
		semanticRejected:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "semantic_rejected_evidence_total", Help: "Semantic evidence rejected for a bounded reason."}, []string{"reason"}),
		schemaMismatch:      prometheus.NewCounter(prometheus.CounterOpts{Name: "semantic_schema_mismatch_total", Help: "Semantic question schema binding mismatches."}),
		checkpointMismatch:  prometheus.NewCounter(prometheus.CounterOpts{Name: "semantic_checkpoint_mismatch_total", Help: "Semantic checkpoint binding mismatches."}),
		missingDecisions:    prometheus.NewCounter(prometheus.CounterOpts{Name: "semantic_missing_decisions_total", Help: "Semantic evidence missing required decisions."}),
		fallbackReasons:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "semantic_fallback_total", Help: "Semantic fallback actions by bounded reason."}, []string{"reason"}),
		streamActions:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "stream_actions_total", Help: "Streaming predicted and applied actions by bounded direction and endpoint family."}, []string{"direction", "endpoint_family", "predicted_action", "applied_action", "mode"}),
		streamBytes:         prometheus.NewCounterVec(prometheus.CounterOpts{Name: "stream_bytes_inspected_total", Help: "Streaming response bytes inspected."}, []string{"direction", "endpoint_family"}),
		streamEvents:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "stream_events_inspected_total", Help: "Streaming SSE events inspected."}, []string{"direction", "endpoint_family"}),
		reloadFailures:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "secure_material_reload_failures_total", Help: "Secure material reload failures by bounded kind."}, []string{"kind"}),
		certExpiring:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "secure_certificate_expiring_total", Help: "Secure certificates nearing expiry by bounded kind."}, []string{"kind"}),
		routeSelected:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "route_selected_total", Help: "Selected upstream routes by bounded route, class, and endpoint family."}, []string{"route_id", "class", "family"}),
		routeFailover:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "route_failover_total", Help: "Explicit configured route failovers."}, []string{"route_id", "class", "family"}),
		routeHealth:         prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "route_health", Help: "Current sanitized upstream route health."}, []string{"route_id", "class", "state"}),
		routeRejected:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "route_rejected_total", Help: "Route selection rejections by bounded reason and endpoint family."}, []string{"reason", "family"}),
		routeUnavailable:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "route_unavailable_total", Help: "Route selection unavailability by bounded class and endpoint family."}, []string{"class", "family"}),
		nerCalls:            prometheus.NewCounterVec(prometheus.CounterOpts{Name: "pii_ner_calls_total", Help: "Local NER calls by bounded provider/entity/language/confidence and outcome."}, []string{"provider", "entity", "language", "confidence_bucket", "error", "fallback"}),
		nerLatency:          prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "pii_ner_latency_ms", Help: "Local NER latency by bounded provider and language."}, []string{"provider", "language"}),
		evasion:             prometheus.NewCounterVec(prometheus.CounterOpts{Name: "evasion_events_total", Help: "Bounded canonicalization/evasion events by type, depth, action, and budget outcome."}, []string{"type", "encoding_depth", "action", "budget_rejected"}),
		distribution:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "policy_distribution_events_total", Help: "Signed policy distribution events by bounded event, reason, and key ID."}, []string{"event", "reason", "key_id"}),
		auditEnqueued:       prometheus.NewCounter(prometheus.CounterOpts{Name: "audit_enqueue_total", Help: "Audit events accepted by the audit API."}),
		auditDurable:        prometheus.NewCounter(prometheus.CounterOpts{Name: "audit_durable_total", Help: "Audit events durably appended to the WAL."}),
		auditExported:       prometheus.NewCounter(prometheus.CounterOpts{Name: "audit_export_total", Help: "Audit events accepted by the SIEM."}),
		auditRetried:        prometheus.NewCounter(prometheus.CounterOpts{Name: "audit_retry_total", Help: "Audit export retries."}),
		auditDeadLetter:     prometheus.NewCounter(prometheus.CounterOpts{Name: "audit_dead_letter_total", Help: "Audit batches quarantined after export failure."}),
		auditCorruption:     prometheus.NewCounter(prometheus.CounterOpts{Name: "audit_corruption_total", Help: "Audit WAL integrity failures."}),
		auditDropped:        prometheus.NewCounter(prometheus.CounterOpts{Name: "audit_dropped_total", Help: "Audit events dropped; expected to remain zero in production."}),
		auditQueueBytes:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "audit_queue_bytes", Help: "Durable audit WAL bytes."}),
		auditOldestAge:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "audit_oldest_age_seconds", Help: "Age of oldest durable audit event."}),
		auditExporterState:  prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "audit_exporter_state", Help: "Current audit exporter state."}, []string{"state"}),
		registry:            reg,
	}
	reg.MustRegister(m.requestsTotal, m.blockedTotal, m.tokenizedTotal, m.redactedTotal,
		m.reviewTotal, m.findingsTotal, m.layaCallsTotal, m.layaErrorsTotal,
		m.layaLatency, m.scannerLatency, m.securityLatency, m.shadowDisagreements,
		m.falsePositiveSample, m.fallbackTotal, m.transformations, m.rateLimited,
		m.concurrencyRejected, m.promptRejected, m.responseTooLarge, m.upstreamTimeout,
		m.breakerOpen, m.activeRequests, m.activeLaya, m.calibrationInfo, m.semanticRejected,
		m.schemaMismatch, m.checkpointMismatch, m.missingDecisions, m.fallbackReasons, m.distribution,
		m.streamActions, m.streamBytes, m.streamEvents, m.reloadFailures, m.certExpiring, m.routeSelected, m.routeFailover, m.routeHealth, m.routeRejected, m.routeUnavailable, m.nerCalls, m.nerLatency, m.evasion,
		m.auditEnqueued, m.auditDurable, m.auditExported, m.auditRetried, m.auditDeadLetter, m.auditCorruption, m.auditDropped, m.auditQueueBytes, m.auditOldestAge, m.auditExporterState)
	return m
}

func (m *Metrics) ObserveAuditEnqueue() { m.auditEnqueued.Inc() }
func (m *Metrics) ObserveAuditDurable(bytes int64) {
	m.auditDurable.Inc()
	m.auditQueueBytes.Set(float64(bytes))
}
func (m *Metrics) ObserveAuditExported(n int)   { m.auditExported.Add(float64(n)) }
func (m *Metrics) ObserveAuditRetry()           { m.auditRetried.Inc() }
func (m *Metrics) ObserveAuditDeadLetter(n int) { m.auditDeadLetter.Add(float64(n)) }
func (m *Metrics) ObserveAuditCorruption()      { m.auditCorruption.Inc() }
func (m *Metrics) ObserveAuditDropped()         { m.auditDropped.Inc() }
func (m *Metrics) ObserveAuditQueue(bytes, oldestSeconds int64) {
	m.auditQueueBytes.Set(float64(bytes))
	m.auditOldestAge.Set(float64(oldestSeconds))
}
func (m *Metrics) ObserveAuditExporterState(state string) {
	m.auditExporterState.Reset()
	m.auditExporterState.WithLabelValues(boundedMetadata(state)).Set(1)
}

// RecordDistribution implements the signed policy manager observer without
// exposing bundle contents or unbounded error strings.
func (m *Metrics) RecordDistribution(event, reason, keyID string) {
	m.distribution.WithLabelValues(boundedMetadata(event), boundedReason(reason), boundedMetadata(keyID)).Inc()
}

// Handler serves the Prometheus exposition format on /metrics.
func (m *Metrics) Handler() http.Handler {
	return metricsHandler{metrics: m, next: promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})}
}

type metricsHandler struct {
	metrics *Metrics
	next    http.Handler
}

func (h metricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.next.ServeHTTP(w, r)
}

// ProtectionMetrics exposes the owning recorder to the gateway wiring without
// exposing the private Prometheus registry.
func (h metricsHandler) ProtectionMetrics() *Metrics { return h.metrics }

// RuntimeMetrics exposes the content-free runtime recorder to the gateway
// admission layer without exposing the Prometheus registry.
func (h metricsHandler) RuntimeMetrics() RuntimeRecorder { return h.metrics }

// Snapshot gathers the private registry and returns only the counters needed
// by the protection dashboard. Registry gathering is safe while counters are
// being updated by request handlers.
func (m *Metrics) Snapshot() MetricSnapshot {
	if m == nil || m.registry == nil {
		return MetricSnapshot{}
	}
	families, err := m.registry.Gather()
	if err != nil {
		return MetricSnapshot{}
	}

	var snapshot MetricSnapshot
	for _, family := range families {
		switch family.GetName() {
		case "requests_total":
			for _, metric := range family.GetMetric() {
				if labelValue(metric, "action") != string(core.ActionAllow) {
					continue
				}
				snapshot.Allowed += counterValue(metric)
			}
		case "blocked_total":
			snapshot.Blocked = familyValue(family)
		case "tokenized_total":
			snapshot.Tokenized = familyValue(family)
		case "redacted_total":
			snapshot.Redacted = familyValue(family)
		case "review_total":
			snapshot.Review = familyValue(family)
		case "findings_total":
			for _, metric := range family.GetMetric() {
				snapshot.Findings = append(snapshot.Findings, FindingSnapshot{
					Category: labelValue(metric, "category"),
					Subtype:  labelValue(metric, "subtype"),
					Count:    counterValue(metric),
				})
			}
		case "stream_bytes_inspected_total":
			for _, metric := range family.GetMetric() {
				snapshot.StreamBytes += counterValue(metric)
			}
		case "stream_events_inspected_total":
			for _, metric := range family.GetMetric() {
				snapshot.StreamEvents += counterValue(metric)
			}
		case "route_selected_total":
			for _, metric := range family.GetMetric() {
				switch labelValue(metric, "class") {
				case "local":
					snapshot.LocalApplied += counterValue(metric)
				case "cloud":
					snapshot.CloudApplied += counterValue(metric)
				}
			}
		}
	}
	return snapshot
}

func familyValue(family *dto.MetricFamily) uint64 {
	metrics := family.GetMetric()
	if len(metrics) == 0 {
		return 0
	}
	return counterValue(metrics[0])
}

func counterValue(metric *dto.Metric) uint64 {
	return uint64(metric.GetCounter().GetValue())
}

func labelValue(metric *dto.Metric, name string) string {
	for _, label := range metric.GetLabel() {
		if label.GetName() == name {
			return label.GetValue()
		}
	}
	return ""
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

func (m *Metrics) ObserveFallbackReason(reason string) {
	m.fallbackTotal.Inc()
	m.fallbackReasons.WithLabelValues(boundedReason(reason)).Inc()
}

func (m *Metrics) ObserveSemanticRejected(reason string) {
	m.semanticRejected.WithLabelValues(boundedReason(reason)).Inc()
}

func (m *Metrics) ObserveSchemaMismatch() {
	m.schemaMismatch.Inc()
	m.ObserveSemanticRejected("schema")
}

func (m *Metrics) ObserveCheckpointMismatch() {
	m.checkpointMismatch.Inc()
	m.ObserveSemanticRejected("checkpoint")
}

func (m *Metrics) ObserveMissingDecision() {
	m.missingDecisions.Inc()
	m.ObserveSemanticRejected("missing_decision")
}

func (m *Metrics) ObserveCalibrationArtifact(id string, version int, provider, checkpoint, schemaVersion, state, timestamp string) {
	m.calibrationInfo.Reset()
	m.calibrationInfo.WithLabelValues(boundedMetadata(id), fmt.Sprintf("%d", version), boundedMetadata(provider), boundedMetadata(checkpoint), boundedMetadata(schemaVersion), boundedMetadata(state), boundedMetadata(timestamp)).Set(1)
}

func (m *Metrics) ObserveTokens(n int, action string) {
	if n > 0 {
		m.transformations.WithLabelValues(action).Add(float64(n))
	}
}

// ObserveEvasion exposes only bounded labels; it never receives canonical or
// decoded content.
func (m *Metrics) ObserveEvasion(evasionType string, depth int, action core.Action, budgetRejected bool) {
	if depth < 0 {
		depth = 0
	}
	if depth > 8 {
		depth = 8
	}
	if evasionType == "" {
		evasionType = "other"
	}
	m.evasion.WithLabelValues(boundedMetadata(evasionType), fmt.Sprintf("%d", depth), string(action), boolLabel(budgetRejected)).Inc()
}

// ObserveStream records both the policy prediction and the mode-dependent
// applied action. Endpoint family is selected from a fixed provider matrix;
// callers must not pass arbitrary request-derived labels.
func (m *Metrics) ObserveStream(direction core.Direction, family string, predicted, applied core.Action, mode string, bytes int64, events int) {
	m.streamActions.WithLabelValues(string(direction), family, string(predicted), string(applied), mode).Inc()
	if bytes > 0 {
		m.streamBytes.WithLabelValues(string(direction), family).Add(float64(bytes))
	}
	if events > 0 {
		m.streamEvents.WithLabelValues(string(direction), family).Add(float64(events))
	}
	if mode != "shadow" {
		switch applied {
		case core.ActionAllow:
			m.requestsTotal.WithLabelValues(string(core.ActionAllow), "stream").Inc()
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
}

func (m *Metrics) ObserveReloadFailure(kind string) {
	m.reloadFailures.WithLabelValues(boundedMetadata(kind)).Inc()
}

func (m *Metrics) ObserveCertificateExpiring(kind string) {
	m.certExpiring.WithLabelValues(boundedMetadata(kind)).Inc()
}

func (m *Metrics) ObserveRouteSelected(id, class, family string, failover bool) {
	id, class, family = boundedMetadata(id), boundedMetadata(class), boundedMetadata(family)
	m.routeSelected.WithLabelValues(id, class, family).Inc()
	if failover {
		m.routeFailover.WithLabelValues(id, class, family).Inc()
	}
}

func (m *Metrics) ObserveRouteHealth(id, class, state string, healthy bool) {
	m.routeHealth.WithLabelValues(boundedMetadata(id), boundedMetadata(class), boundedMetadata(state)).Set(boolFloat(healthy))
}

func (m *Metrics) ObserveRouteRejected(reason, family string) {
	m.routeRejected.WithLabelValues(boundedMetadata(reason), boundedMetadata(family)).Inc()
}

func (m *Metrics) ObserveRouteUnavailable(class, family string) {
	m.routeUnavailable.WithLabelValues(boundedMetadata(class), boundedMetadata(family)).Inc()
}

// ObserveNER records only bounded metadata. It is deliberately not part of
// Recorder so existing pipeline test recorders remain source-compatible.
func (m *Metrics) ObserveNER(provider, entity, language, confidenceBucket string, latencyMS float64, failed, fallback bool) {
	m.nerCalls.WithLabelValues(boundedMetadata(provider), boundedMetadata(entity), boundedMetadata(language), boundedMetadata(confidenceBucket), boolLabel(failed), boolLabel(fallback)).Inc()
	m.nerLatency.WithLabelValues(boundedMetadata(provider), boundedMetadata(language)).Observe(latencyMS)
}

func boolLabel(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func (m *Metrics) ObserveRateLimited()            { m.rateLimited.Inc() }
func (m *Metrics) ObserveConcurrencyRejected()    { m.concurrencyRejected.Inc() }
func (m *Metrics) ObservePromptBudgetRejected()   { m.promptRejected.Inc() }
func (m *Metrics) ObserveResponseTooLarge()       { m.responseTooLarge.Inc() }
func (m *Metrics) ObserveUpstreamTimeout()        { m.upstreamTimeout.Inc() }
func (m *Metrics) ObserveBreakerOpen()            { m.breakerOpen.Inc() }
func (m *Metrics) IncActiveRequests()             { m.activeRequests.Inc() }
func (m *Metrics) DecActiveRequests()             { m.activeRequests.Dec() }
func (m *Metrics) SetActiveLayaEvaluations(n int) { m.activeLaya.Set(float64(n)) }

func boundedReason(reason string) string {
	switch reason {
	case "provider", "schema", "checkpoint", "unknown_question", "confidence", "missing_decision", "semantic_evidence_rejected", "ready", "rejected", "initial", "promoted", "operator_authorized", "candidate":
		return reason
	default:
		return "other"
	}
}

func boundedMetadata(value string) string {
	if len(value) > 64 {
		value = value[:64]
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == ':' || r == '-' {
			continue
		}
		value = value[:i] + "_" + value[i+len(string(r)):]
	}
	return value
}

// Noop is a Recorder that discards everything (tests, metrics disabled).
type Noop struct{}

func (Noop) ObserveRequest(core.Action, string)                                                 {}
func (Noop) ObserveFindings(string, string)                                                     {}
func (Noop) ObserveLaya(float64, bool)                                                          {}
func (Noop) ObserveScanner(float64)                                                             {}
func (Noop) ObserveSecurityLatency(float64)                                                     {}
func (Noop) ObserveShadowDisagreement(core.Action)                                              {}
func (Noop) ObserveFallback()                                                                   {}
func (Noop) ObserveFallbackReason(string)                                                       {}
func (Noop) ObserveSemanticRejected(string)                                                     {}
func (Noop) ObserveSchemaMismatch()                                                             {}
func (Noop) ObserveCheckpointMismatch()                                                         {}
func (Noop) ObserveMissingDecision()                                                            {}
func (Noop) ObserveTokens(int, string)                                                          {}
func (Noop) ObserveStream(core.Direction, string, core.Action, core.Action, string, int64, int) {}
func (Noop) ObserveFalsePositiveSample()                                                        {}
func (Noop) ObserveRateLimited()                                                                {}
func (Noop) ObserveConcurrencyRejected()                                                        {}
func (Noop) ObservePromptBudgetRejected()                                                       {}
func (Noop) ObserveResponseTooLarge()                                                           {}
func (Noop) ObserveUpstreamTimeout()                                                            {}
func (Noop) ObserveBreakerOpen()                                                                {}
func (Noop) IncActiveRequests()                                                                 {}
func (Noop) DecActiveRequests()                                                                 {}
