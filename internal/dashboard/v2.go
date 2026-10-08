package dashboard

// This file is the operator dashboard v2 data plane. It intentionally owns a
// small rolling aggregate rather than reading the Prometheus exposition or
// durable audit records. All labels are allow-listed and every dimension has a
// hard cardinality cap.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	APIVersion        = "aegisllm.dashboard/v2"
	DefaultWindow     = time.Hour
	MaxWindow         = 24 * time.Hour
	DefaultResolution = time.Minute
	MaxPoints         = 120
	MaxDimension      = 32
	otherBucket       = "other"
)

var allowedActions = map[string]bool{
	"ALLOW": true, "BLOCK": true, "TOKENIZE": true, "REDACT": true,
	"REVIEW": true, "RESTRICT_TOOLS": true, "FORCE_LOCAL_MODEL": true,
}

var allowedCategories = map[string]bool{
	"PII": true, "SECRET": true, "PROMPT_SECURITY": true, "TOOL_SECURITY": true,
	"CONFIDENTIAL_DATA": true, "POLICY": true, "OTHER": true,
}

var allowedProviders = map[string]bool{"LOCAL": true, "CLOUD": true, "OTHER": true}
var allowedStages = map[string]bool{"REQUEST": true, "RESPONSE": true, "DETECTOR": true, "ROUTING": true, "OTHER": true}

type bucket struct {
	start      time.Time
	actions    map[string]uint64
	findings   map[string]uint64
	providers  map[string]uint64
	stages     map[string]uint64
	modes      map[string]uint64
	runtime    map[string]uint64
	streams    uint64
	streamByte uint64
	canary     uint64
	audit      map[string]uint64
}

func newBucket(start time.Time) bucket {
	return bucket{
		start: start, actions: map[string]uint64{}, findings: map[string]uint64{},
		providers: map[string]uint64{}, stages: map[string]uint64{}, modes: map[string]uint64{},
		runtime: map[string]uint64{}, audit: map[string]uint64{},
	}
}

// RollingAggregator is a fixed-size, process-local time series. It never
// stores request bodies, identities, rule text, or arbitrary caller labels.
type RollingAggregator struct {
	mu         sync.RWMutex
	resolution time.Duration
	maxBuckets int
	buckets    []bucket
	clock      func() time.Time
	createdAt  time.Time
	lastEvent  time.Time
	resetAt    time.Time
}

func NewAggregator() *RollingAggregator {
	return NewRollingAggregator(DefaultResolution, int(MaxWindow/DefaultResolution), time.Now)
}

func NewRollingAggregator(resolution time.Duration, maxBuckets int, clock func() time.Time) *RollingAggregator {
	if resolution <= 0 {
		resolution = DefaultResolution
	}
	if maxBuckets <= 0 {
		maxBuckets = int(MaxWindow / resolution)
	}
	if maxBuckets > int(MaxWindow/resolution) {
		maxBuckets = int(MaxWindow / resolution)
	}
	if maxBuckets < 1 {
		maxBuckets = 1
	}
	if clock == nil {
		clock = time.Now
	}
	now := clock().UTC()
	return &RollingAggregator{
		resolution: resolution, maxBuckets: maxBuckets, buckets: make([]bucket, maxBuckets),
		clock: clock, createdAt: now, lastEvent: now, resetAt: now,
	}
}

func (a *RollingAggregator) now() time.Time { return a.clock().UTC() }

func (a *RollingAggregator) currentLocked(now time.Time) *bucket {
	start := now.Truncate(a.resolution)
	index := int((start.UnixNano() / a.resolution.Nanoseconds()) % int64(a.maxBuckets))
	if index < 0 {
		index = -index
	}
	if a.buckets[index].start != start {
		a.buckets[index] = newBucket(start)
	}
	a.lastEvent = now
	return &a.buckets[index]
}

func boundedLabel(value, fallback string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	if len(value) > 48 {
		return "OTHER"
	}
	for _, r := range value {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return fallback
	}
	return value
}

func addBounded(values map[string]uint64, value string, amount uint64) {
	if amount == 0 {
		return
	}
	// Reserve one slot for the overflow bucket so the cap is never exceeded.
	if _, ok := values[value]; !ok && len(values) >= MaxDimension-1 {
		value = otherBucket
	}
	values[value] += amount
}

func (a *RollingAggregator) record(at time.Time, fn func(*bucket)) {
	at = at.UTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	if at.Before(a.now().Add(-MaxWindow)) {
		return
	}
	fn(a.currentLocked(at))
}

func (a *RollingAggregator) ObserveDashboardRequest(action, mode string) {
	a.RecordRequestAt(a.now(), action, mode)
}
func (a *RollingAggregator) RecordRequestAt(at time.Time, action, mode string) {
	action = boundedLabel(action, "OTHER")
	if !allowedActions[action] {
		action = "OTHER"
	}
	mode = boundedLabel(mode, "OTHER")
	a.record(at, func(b *bucket) {
		addBounded(b.actions, action, 1)
		addBounded(b.modes, mode, 1)
		addBounded(b.stages, "REQUEST", 1)
	})
}

func (a *RollingAggregator) ObserveDashboardFinding(category, subtype string) {
	a.RecordFindingAt(a.now(), category, subtype)
}
func (a *RollingAggregator) RecordFindingAt(at time.Time, category, subtype string) {
	category = boundedLabel(category, "OTHER")
	subtype = boundedLabel(subtype, "OTHER")
	a.record(at, func(b *bucket) {
		addBounded(b.findings, category, 1)
		addBounded(b.stages, "DETECTOR", 1)
		_ = subtype // subtype remains available in the bounded category key below.
		addBounded(b.findings, category+":"+subtype, 1)
	})
}

func (a *RollingAggregator) ObserveDashboardStream(direction, family, predicted, applied, mode string, bytes int64, events int) {
	a.RecordStreamAt(a.now(), direction, family, predicted, applied, mode, bytes, events)
}
func (a *RollingAggregator) RecordStreamAt(at time.Time, direction, family, predicted, applied, mode string, bytes int64, events int) {
	a.record(at, func(b *bucket) {
		if events > 0 {
			b.streams += uint64(events)
		}
		if bytes > 0 {
			b.streamByte += uint64(bytes)
		}
		addBounded(b.stages, boundedLabel(direction, "OTHER"), 1)
		addBounded(b.modes, boundedLabel(mode, "OTHER"), 1)
	})
}

func (a *RollingAggregator) ObserveDashboardRoute(class, family string, failover bool) {
	a.RecordRouteAt(a.now(), class, family, failover)
}
func (a *RollingAggregator) RecordRouteAt(at time.Time, class, family string, failover bool) {
	a.record(at, func(b *bucket) {
		addBounded(b.providers, boundedLabel(class, "OTHER"), 1)
		addBounded(b.stages, "ROUTING", 1)
		if failover {
			addBounded(b.runtime, "ROUTE_FAILOVER", 1)
		}
	})
}

func (a *RollingAggregator) ObserveDashboardRuntime(kind string) {
	a.RecordRuntimeAt(a.now(), kind)
}
func (a *RollingAggregator) RecordRuntimeAt(at time.Time, kind string) {
	a.record(at, func(b *bucket) { addBounded(b.runtime, boundedLabel(kind, "OTHER"), 1) })
}

func (a *RollingAggregator) ObserveDashboardCanaryDisagreement() {
	a.record(a.now(), func(b *bucket) { b.canary++ })
}
func (a *RollingAggregator) ObserveDashboardAudit(kind string, value uint64) {
	a.record(a.now(), func(b *bucket) { addBounded(b.audit, boundedLabel(kind, "OTHER"), value) })
}

type Query struct {
	Window        time.Duration
	Bucket        time.Duration
	Action        string
	Category      string
	ProviderClass string
	SourceStage   string
}

func ParseQuery(r *http.Request) (Query, error) {
	q := Query{Window: DefaultWindow}
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 || d > MaxWindow {
			return Query{}, errors.New("window must be a positive duration no longer than 24h")
		}
		q.Window = d
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("bucket")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < DefaultResolution || d > q.Window {
			return Query{}, errors.New("bucket must be between 1m and the selected window")
		}
		q.Bucket = d
	}
	if q.Bucket == 0 {
		q.Bucket = q.Window / MaxPoints
		if q.Bucket < DefaultResolution {
			q.Bucket = DefaultResolution
		}
		if q.Window%q.Bucket != 0 {
			q.Bucket += DefaultResolution
		}
	}
	if q.Window/q.Bucket > MaxPoints {
		return Query{}, errors.New("window and bucket exceed the 120 point limit")
	}
	q.Action, q.Category, q.ProviderClass, q.SourceStage = boundedFilter(r, "action"), boundedFilter(r, "category"), boundedFilter(r, "provider_class"), boundedFilter(r, "source_stage")
	if q.Action != "" && !allowedActions[q.Action] {
		return Query{}, errors.New("action is not a supported bounded value")
	}
	if q.Category != "" && !allowedCategories[q.Category] {
		return Query{}, errors.New("category is not a supported bounded value")
	}
	if q.ProviderClass != "" && !allowedProviders[q.ProviderClass] {
		return Query{}, errors.New("provider_class is not a supported bounded value")
	}
	if q.SourceStage != "" && !allowedStages[q.SourceStage] {
		return Query{}, errors.New("source_stage is not a supported bounded value")
	}
	return q, nil
}

func boundedFilter(r *http.Request, key string) string {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return ""
	}
	return boundedLabel(value, "INVALID")
}

type Window struct {
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	Bucket    string    `json:"bucket"`
	Requested string    `json:"requested"`
}
type Freshness struct {
	Status      string    `json:"status"`
	LastEventAt time.Time `json:"last_event_at"`
	AgeSeconds  int64     `json:"age_seconds"`
}
type ResetInfo struct {
	ResetAt time.Time `json:"reset_at"`
	Reason  string    `json:"reason"`
	Durable bool      `json:"durable"`
}
type RuntimeStatus struct {
	DeploymentProfile string            `json:"deployment_profile"`
	SecurityMode      string            `json:"security_mode"`
	Policy            PolicyStatus      `json:"policy"`
	Readiness         ComponentStatus   `json:"readiness"`
	Components        []ComponentStatus `json:"components"`
	Audit             RuntimeAudit      `json:"audit"`
	Quarantine        QuarantineStatus  `json:"quarantine"`
}
type QuarantineStatus struct {
	State        string `json:"state"`
	Active       int    `json:"active"`
	Acknowledged int    `json:"acknowledged"`
	Probation    int    `json:"probation"`
}
type RuntimeAudit struct {
	State            string `json:"state"`
	QueueBytes       int64  `json:"queue_bytes"`
	OldestAgeSeconds int64  `json:"oldest_age_seconds"`
	ExporterState    string `json:"exporter_state"`
}
type PolicyStatus struct {
	Sequence uint64 `json:"sequence,omitempty"`
	Hash     string `json:"hash,omitempty"`
	ID       string `json:"id,omitempty"`
	Version  int    `json:"version,omitempty"`
}
type ComponentStatus struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Detail    string `json:"detail,omitempty"`
	DetailURL string `json:"detail_url,omitempty"`
}
type KPI struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Value        uint64 `json:"value"`
	Previous     uint64 `json:"previous"`
	Comparison   bool   `json:"comparison_available"`
	DeltaPercent int64  `json:"delta_percent"`
	Trend        string `json:"trend"`
	Definition   string `json:"definition"`
	OwnerAction  string `json:"owner_action"`
}
type Funnel struct {
	Inspected            uint64 `json:"inspected"`
	Findings             uint64 `json:"findings"`
	TransformedOrBlocked uint64 `json:"transformed_or_blocked"`
	Forwarded            uint64 `json:"forwarded"`
}
type SeriesPoint struct {
	Timestamp time.Time         `json:"timestamp"`
	Actions   map[string]uint64 `json:"actions"`
	Findings  uint64            `json:"findings"`
	Protected uint64            `json:"protected"`
	Forwarded uint64            `json:"forwarded"`
}
type Overview struct {
	Version     string        `json:"version"`
	GeneratedAt time.Time     `json:"generated_at"`
	Window      Window        `json:"window"`
	Freshness   Freshness     `json:"freshness"`
	Reset       ResetInfo     `json:"reset"`
	Status      RuntimeStatus `json:"status"`
	KPIs        []KPI         `json:"kpis"`
	Funnel      Funnel        `json:"funnel"`
}
type Timeseries struct {
	Version     string        `json:"version"`
	GeneratedAt time.Time     `json:"generated_at"`
	Window      Window        `json:"window"`
	Points      []SeriesPoint `json:"points"`
}
type Count struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
}
type Breakdown struct {
	Version             string    `json:"version"`
	GeneratedAt         time.Time `json:"generated_at"`
	Window              Window    `json:"window"`
	Actions             []Count   `json:"actions"`
	Categories          []Count   `json:"categories"`
	Subtypes            []Count   `json:"rule_subtypes"`
	Providers           []Count   `json:"provider_classes"`
	Stages              []Count   `json:"source_stages"`
	OtherIncluded       bool      `json:"other_included"`
	CanaryDisagreements uint64    `json:"canary_disagreements"`
	Audit               []Count   `json:"audit"`
	Runtime             []Count   `json:"runtime_limits"`
}
type Alert struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	DetailURL string `json:"detail_url"`
}
type Alerts struct {
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Alerts      []Alert   `json:"alerts"`
}

type V2 struct {
	aggregator     *RollingAggregator
	statusMu       sync.RWMutex
	statusProvider func() RuntimeStatus
}

func NewV2() *V2 { return &V2{aggregator: NewAggregator()} }
func (v *V2) Aggregator() *RollingAggregator {
	if v == nil {
		return nil
	}
	return v.aggregator
}
func (v *V2) SetStatusProvider(provider func() RuntimeStatus) {
	v.statusMu.Lock()
	v.statusProvider = provider
	v.statusMu.Unlock()
}
func (v *V2) status() RuntimeStatus {
	v.statusMu.RLock()
	provider := v.statusProvider
	v.statusMu.RUnlock()
	if provider == nil {
		return RuntimeStatus{Readiness: ComponentStatus{Name: "readiness", State: "unavailable"}}
	}
	return provider()
}

func (v *V2) snapshot(q Query) (Overview, Timeseries, Breakdown) {
	now := v.aggregator.now()
	end := now
	start := end.Add(-q.Window)
	window := Window{Start: start, End: end, Bucket: q.Bucket.String(), Requested: q.Window.String()}
	points := make([]SeriesPoint, 0, int(q.Window/q.Bucket)+1)
	allActions, allCategories, allSubtypes, allProviders, allStages := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	allAudit, allRuntime := map[string]uint64{}, map[string]uint64{}
	var total, findings, protected, forwarded, canary uint64
	v.aggregator.mu.RLock()
	for pointStart := start.Truncate(q.Bucket); !pointStart.After(end); pointStart = pointStart.Add(q.Bucket) {
		pointEnd := pointStart.Add(q.Bucket)
		point := SeriesPoint{Timestamp: pointStart, Actions: map[string]uint64{}}
		for _, b := range v.aggregator.buckets {
			if b.start.Before(pointStart) || !b.start.Before(pointEnd) {
				continue
			}
			for key, value := range b.actions {
				if q.Action == "" || q.Action == key {
					point.Actions[key] += value
					allActions[key] += value
					total += value
				}
			}
			for key, value := range b.findings {
				if !strings.Contains(key, ":") {
					if q.Category == "" || q.Category == key {
						point.Findings += value
						allCategories[key] += value
						findings += value
					}
				} else {
					allSubtypes[key] += value
				}
			}
			for key, value := range b.providers {
				if q.ProviderClass == "" || q.ProviderClass == key {
					allProviders[key] += value
				}
			}
			for key, value := range b.stages {
				if q.SourceStage == "" || q.SourceStage == key {
					allStages[key] += value
				}
			}
			for key, value := range b.audit {
				allAudit[key] += value
			}
			for key, value := range b.runtime {
				allRuntime[key] += value
			}
			canary += b.canary
		}
		for key, value := range point.Actions {
			if key != "ALLOW" && key != "OTHER" {
				point.Protected += value
			} else if key == "ALLOW" {
				point.Forwarded += value
			}
		}
		protected += point.Protected
		forwarded += point.Forwarded
		points = append(points, point)
	}
	lastEvent := v.aggregator.lastEvent
	resetAt := v.aggregator.resetAt
	previousStart := start.Add(-q.Window)
	previousAvailable := !previousStart.Before(now.Add(-MaxWindow))
	previousActions := map[string]uint64{}
	if previousAvailable {
		for _, b := range v.aggregator.buckets {
			if b.start.Before(previousStart) || !b.start.Before(start) {
				continue
			}
			for key, value := range b.actions {
				if q.Action == "" || q.Action == key {
					previousActions[key] += value
				}
			}
		}
	}
	v.aggregator.mu.RUnlock()
	status := v.status()
	age := int64(now.Sub(lastEvent).Seconds())
	if age < 0 {
		age = 0
	}
	freshStatus := "fresh"
	if age > 60 {
		freshStatus = "stale"
	}
	if status.Readiness.State == "unavailable" {
		freshStatus = "unavailable"
	}
	previousProtected := protectedActions(previousActions)
	previousBlocked := previousActions["BLOCK"]
	previousTransformed := previousActions["TOKENIZE"] + previousActions["REDACT"]
	previousPrevented := previousActions["BLOCK"] + previousActions["REVIEW"] + previousActions["RESTRICT_TOOLS"]
	kpis := []KPI{
		comparisonKPI("protected_events", "Protected events", protected, previousProtected, previousAvailable, "BLOCK, TOKENIZE, REDACT, REVIEW, or RESTRICT_TOOLS actions in the selected window.", "Security Operations: investigate spikes by action and category."),
		comparisonKPI("blocked_high_risk", "Blocked high risk", sumAction(allActions, "BLOCK"), previousBlocked, previousAvailable, "Events whose enforced action is BLOCK; the policy action is the high-risk proxy.", "Security Operations: inspect policy and provider changes."),
		comparisonKPI("tokenized_redacted", "Tokenized / redacted", sumAction(allActions, "TOKENIZE")+sumAction(allActions, "REDACT"), previousTransformed, previousAvailable, "Requests transformed before forwarding.", "Privacy Operations: verify transformation coverage."),
		comparisonKPI("requests_prevented", "Upstream / tool requests prevented", sumAction(allActions, "BLOCK")+sumAction(allActions, "REVIEW")+sumAction(allActions, "RESTRICT_TOOLS"), previousPrevented, previousAvailable, "Requests stopped or tool access restricted before upstream forwarding.", "Security Operations: investigate the bounded alert detail."),
		{ID: "control_health", Label: "Control health / SLO", Value: healthValue(status), Trend: healthTrend(status), Definition: "Readiness and required control status; target is 100% ready during the window.", OwnerAction: "Platform Operations: restore degraded or unavailable controls."},
	}
	overview := Overview{Version: APIVersion, GeneratedAt: now, Window: window, Freshness: Freshness{Status: freshStatus, LastEventAt: lastEvent, AgeSeconds: age}, Reset: ResetInfo{ResetAt: resetAt, Reason: "process_restart", Durable: false}, Status: status, KPIs: kpis, Funnel: Funnel{Inspected: total, Findings: findings, TransformedOrBlocked: protected, Forwarded: forwarded}}
	return overview, Timeseries{Version: APIVersion, GeneratedAt: now, Window: window, Points: points}, Breakdown{Version: APIVersion, GeneratedAt: now, Window: window, Actions: counts(allActions), Categories: counts(allCategories), Subtypes: counts(allSubtypes), Providers: counts(allProviders), Stages: counts(allStages), OtherIncluded: true, CanaryDisagreements: canary, Audit: counts(allAudit), Runtime: counts(allRuntime)}
}

func sumAction(values map[string]uint64, key string) uint64 { return values[key] }

func protectedActions(values map[string]uint64) uint64 {
	return values["BLOCK"] + values["TOKENIZE"] + values["REDACT"] + values["REVIEW"] + values["RESTRICT_TOOLS"]
}

func comparisonKPI(id, label string, value, previous uint64, available bool, definition, ownerAction string) KPI {
	trend := "unavailable"
	var delta int64
	if available {
		switch {
		case value > previous:
			trend = "up"
		case value < previous:
			trend = "down"
		default:
			trend = "flat"
		}
		if previous == 0 {
			if value > 0 {
				delta = 100
			}
		} else {
			deltaFloat := float64(value)*100/float64(previous) - 100
			switch {
			case deltaFloat >= float64(math.MaxInt64):
				delta = math.MaxInt64
			case deltaFloat <= float64(math.MinInt64):
				delta = math.MinInt64
			default:
				delta = int64(deltaFloat)
			}
		}
	}
	return KPI{ID: id, Label: label, Value: value, Previous: previous, Comparison: available, DeltaPercent: delta, Trend: trend, Definition: definition, OwnerAction: ownerAction}
}

func healthValue(s RuntimeStatus) uint64 {
	if s.Readiness.State == "healthy" || s.Readiness.State == "ready" {
		return 100
	}
	return 0
}
func healthTrend(s RuntimeStatus) string {
	if healthValue(s) == 100 {
		return "flat"
	}
	return "down"
}
func counts(values map[string]uint64) []Count {
	out := make([]Count, 0, len(values))
	for key, value := range values {
		out = append(out, Count{Key: key, Count: value})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func (v *V2) HandleOverview(w http.ResponseWriter, r *http.Request) {
	q, err := ParseQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	overview, _, _ := v.snapshot(q)
	writeV2JSON(w, overview)
}
func (v *V2) HandleTimeseries(w http.ResponseWriter, r *http.Request) {
	q, err := ParseQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, series, _ := v.snapshot(q)
	writeV2JSON(w, series)
}
func (v *V2) HandleBreakdown(w http.ResponseWriter, r *http.Request) {
	q, err := ParseQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, _, breakdown := v.snapshot(q)
	writeV2JSON(w, breakdown)
}
func (v *V2) HandleAlerts(w http.ResponseWriter, r *http.Request) {
	q, err := ParseQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	overview, _, _ := v.snapshot(q)
	alerts := []Alert{}
	if overview.Status.Readiness.State != "healthy" && overview.Status.Readiness.State != "ready" {
		alerts = append(alerts, Alert{ID: "readiness", Severity: "high", Status: overview.Status.Readiness.State, Title: "Protection readiness is degraded", Detail: "One or more required controls are not ready.", DetailURL: "/ready"})
	}
	if overview.Freshness.Status != "fresh" {
		alerts = append(alerts, Alert{ID: "freshness", Severity: "medium", Status: overview.Freshness.Status, Title: "Dashboard data is stale", Detail: "No new bounded aggregate events were observed recently.", DetailURL: "/dashboard"})
	}
	for _, component := range overview.Status.Components {
		if component.State != "healthy" && component.State != "ready" && component.State != "disabled" {
			alerts = append(alerts, Alert{ID: "component_" + component.Name, Severity: "medium", Status: component.State, Title: component.Name + " requires attention", Detail: "The optional or dependent control is not healthy.", DetailURL: component.DetailURL})
		}
	}
	writeV2JSON(w, Alerts{Version: APIVersion, GeneratedAt: overview.GeneratedAt, Alerts: alerts})
}

func writeV2JSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

// Compile-time contract check: the metrics package binds this interface
// without creating an import cycle.
var _ interface{ ObserveDashboardRequest(string, string) } = (*RollingAggregator)(nil)

func (q Query) String() string { return fmt.Sprintf("window=%s bucket=%s", q.Window, q.Bucket) }
