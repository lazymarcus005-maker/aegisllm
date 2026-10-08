package semantic

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

const MaxBuckets = 32

type Bucket struct {
	Label string `json:"label"`
	Count uint64 `json:"count"`
}
type Distribution struct {
	Feature string   `json:"feature"`
	Samples uint64   `json:"samples"`
	Buckets []Bucket `json:"buckets"`
}
type Outcome struct {
	Label string `json:"label"`
	Count uint64 `json:"count"`
}

// Sample is pre-aggregated evidence. Callers must classify into the bounded
// allowlisted buckets before submission; raw prompts, embeddings, labels, and
// identifiers are not accepted by this API.
type Sample struct {
	TenantScope string
	Features    []Distribution
	Outcomes    []Outcome
	HasLabel    bool
	At          time.Time
}

type Metric struct {
	Feature    string  `json:"feature"`
	PSI        float64 `json:"psi,omitempty"`
	JS         float64 `json:"js,omitempty"`
	KS         float64 `json:"ks,omitempty"`
	Samples    uint64  `json:"samples"`
	LowerBound float64 `json:"lower_bound,omitempty"`
	UpperBound float64 `json:"upper_bound,omitempty"`
	Suppressed bool    `json:"suppressed"`
	Breach     bool    `json:"breach"`
	Reason     string  `json:"reason,omitempty"`
}

type Status struct {
	Baseline      ModelRef `json:"baseline"`
	Window        string   `json:"window"`
	Samples       uint64   `json:"samples"`
	LabelSamples  uint64   `json:"label_samples"`
	Suppressed    bool     `json:"suppressed"`
	Sustained     int      `json:"sustained_windows"`
	Action        string   `json:"action"`
	Metrics       []Metric `json:"metrics"`
	LastEvaluated string   `json:"last_evaluated,omitempty"`
}

type Policy struct {
	MinSamples            uint64
	MinLabelSamples       uint64
	Window                time.Duration
	PSIWarning            float64
	PSIAction             float64
	JSWarning             float64
	KSWarning             float64
	SustainedWindows      int
	Cooldown              time.Duration
	Hysteresis            float64
	RequireFleetConfirm   bool
	AutoRollback          bool
	AllowQuarantine       bool
	HealthyRollbackTarget bool
}

func (p Policy) validate() error {
	if p.MinSamples == 0 || p.Window <= 0 || p.Window > 24*time.Hour || p.SustainedWindows <= 0 {
		return errors.New("drift policy minimums are invalid")
	}
	if p.PSIWarning <= 0 || p.PSIAction < p.PSIWarning || p.JSWarning <= 0 || p.KSWarning <= 0 || p.Cooldown < 0 || p.Hysteresis < 0 || p.Hysteresis >= 1 {
		return errors.New("drift policy thresholds are invalid")
	}
	return nil
}

type Action string

const (
	ActionNone       Action = "none"
	ActionWarning    Action = "warning"
	ActionFreeze     Action = "freeze_promotion"
	ActionPause      Action = "pause_canary"
	ActionRollback   Action = "rollback_champion"
	ActionQuarantine Action = "incident_quarantine"
)

type Monitor struct {
	mu                    sync.Mutex
	baseline              ModelRef
	policy                Policy
	clock                 func() time.Time
	features              map[string]Distribution
	outcomes              map[string]uint64
	samples, labelSamples uint64
	sustained             int
	lastAction            Action
	lastActionAt          time.Time
	last                  Status
	maxFeatures           int
	scopes                map[string]struct{}
	windowStart           time.Time
}

func NewMonitor(baseline ModelRef, p Policy, clock func() time.Time) (*Monitor, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if !validRef(baseline) {
		return nil, errors.New("drift baseline is invalid")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Monitor{baseline: baseline, policy: p, clock: clock, features: map[string]Distribution{}, outcomes: map[string]uint64{}, maxFeatures: MaxBuckets, scopes: map[string]struct{}{}}, nil
}

func validRef(r ModelRef) bool { return r.ID != "" && r.Version != "" && len(r.Digest) == 64 }

func ValidateSample(s Sample) error {
	if len(s.Features) > MaxBuckets {
		return errors.New("too many drift features")
	}
	if len(s.Outcomes) > MaxBuckets {
		return errors.New("too many drift outcomes")
	}
	for _, d := range s.Features {
		if !validLabel(d.Feature) || d.Samples == 0 || len(d.Buckets) == 0 || len(d.Buckets) > MaxBuckets {
			return errors.New("invalid drift feature distribution")
		}
		var total uint64
		seen := map[string]bool{}
		for _, b := range d.Buckets {
			if !validLabel(b.Label) || seen[b.Label] {
				return errors.New("invalid drift bucket")
			}
			seen[b.Label] = true
			total += b.Count
		}
		if total != d.Samples {
			return errors.New("drift feature counts do not sum to samples")
		}
	}
	for _, o := range s.Outcomes {
		if !validLabel(o.Label) {
			return errors.New("invalid drift outcome label")
		}
	}
	return nil
}

func validLabel(v string) bool {
	if v == "" || len(v) > 32 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func (m *Monitor) Observe(s Sample) error {
	if err := ValidateSample(s); err != nil {
		return err
	}
	if !validLabel(s.TenantScope) {
		return errors.New("verified tenant scope is required for drift evidence")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.scopes) < 64 {
		m.scopes[s.TenantScope] = struct{}{}
	}
	if s.At.IsZero() {
		s.At = m.clock().UTC()
	}
	if now := m.clock(); s.At.Before(now.Add(-m.policy.Window)) {
		return nil
	}
	if m.windowStart.IsZero() {
		m.windowStart = s.At
	}
	if s.At.Sub(m.windowStart) >= m.policy.Window {
		m.features = map[string]Distribution{}
		m.outcomes = map[string]uint64{}
		m.samples = 0
		m.labelSamples = 0
		m.sustained = 0
		m.scopes = map[string]struct{}{}
		m.windowStart = s.At
	}
	batchSamples := uint64(1)
	for _, d := range s.Features {
		if d.Samples > batchSamples {
			batchSamples = d.Samples
		}
	}
	m.samples += batchSamples
	for _, d := range s.Features {
		existing := m.features[d.Feature]
		if existing.Feature == "" {
			existing = Distribution{Feature: d.Feature, Buckets: []Bucket{}}
		}
		existing.Samples += d.Samples
		for _, b := range d.Buckets {
			mergeBucket(&existing, b)
		}
		m.features[d.Feature] = existing
	}
	if s.HasLabel {
		m.labelSamples++
		for _, o := range s.Outcomes {
			m.outcomes[o.Label] += o.Count
		}
	}
	return nil
}

func mergeBucket(d *Distribution, b Bucket) {
	for i := range d.Buckets {
		if d.Buckets[i].Label == b.Label {
			d.Buckets[i].Count += b.Count
			return
		}
	}
	if len(d.Buckets) < MaxBuckets {
		d.Buckets = append(d.Buckets, b)
	} else {
		for i := range d.Buckets {
			if d.Buckets[i].Label == "other" {
				d.Buckets[i].Count += b.Count
				return
			}
		}
		// The caller's first MaxBuckets labels are retained; overflow is
		// intentionally suppressed rather than growing unbounded state.
		return
	}
}

func (m *Monitor) Evaluate(baseline []Distribution, baselineOutcomes []Outcome) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock().UTC()
	st := Status{Baseline: m.baseline, Window: m.policy.Window.String(), Samples: m.samples, LabelSamples: m.labelSamples, LastEvaluated: now.Format(time.RFC3339Nano)}
	if m.samples < m.policy.MinSamples {
		st.Suppressed = true
		st.Action = string(ActionNone)
		st.Metrics = []Metric{{Feature: "all", Samples: m.samples, Suppressed: true, Reason: "minimum sample guardrail"}}
		m.last = st
		return st
	}
	base := map[string]Distribution{}
	for _, d := range baseline {
		base[d.Feature] = d
	}
	breach := false
	for name, d := range m.features {
		b, ok := base[name]
		if !ok {
			continue
		}
		metric := compareDistribution(d, b)
		metric.Feature = name
		metric.Samples = d.Samples
		metric.LowerBound, metric.UpperBound = wilson(m.samples)
		metric.Breach = metric.PSI >= m.policy.PSIAction || metric.JS >= m.policy.JSWarning || metric.KS >= m.policy.KSWarning
		breach = breach || metric.Breach
		st.Metrics = append(st.Metrics, metric)
	}
	if m.labelSamples >= m.policy.MinLabelSamples && len(baselineOutcomes) > 0 {
		metric := compareOutcome(m.outcomes, baselineOutcomes)
		metric.Feature = "outcome"
		metric.Samples = m.labelSamples
		metric.LowerBound, metric.UpperBound = wilson(m.labelSamples)
		metric.Breach = metric.PSI >= m.policy.PSIAction
		breach = breach || metric.Breach
		st.Metrics = append(st.Metrics, metric)
	}
	sort.Slice(st.Metrics, func(i, j int) bool { return st.Metrics[i].Feature < st.Metrics[j].Feature })
	if breach {
		m.sustained++
	} else if m.sustained > 0 {
		m.sustained--
	}
	st.Sustained = m.sustained
	st.Action = string(ActionWarning)
	if m.sustained >= m.policy.SustainedWindows {
		st.Action = string(ActionFreeze)
		if m.policy.AutoRollback && m.policy.HealthyRollbackTarget && len(m.scopes) >= 2 && m.cooldownOK(now) {
			st.Action = string(ActionRollback)
			m.lastAction = ActionRollback
			m.lastActionAt = now
		} else if m.cooldownOK(now) {
			st.Action = string(ActionPause)
			m.lastAction = ActionPause
			m.lastActionAt = now
		}
		if st.Action == string(ActionRollback) && m.policy.AllowQuarantine {
			st.Action = string(ActionQuarantine)
		}
	}
	m.last = st
	return st
}

func (m *Monitor) cooldownOK(now time.Time) bool {
	return m.policy.Cooldown == 0 || m.lastActionAt.IsZero() || now.Sub(m.lastActionAt) >= m.policy.Cooldown
}
func (m *Monitor) Status() Status { m.mu.Lock(); defer m.mu.Unlock(); return m.last }

func compareDistribution(a, b Distribution) Metric {
	am := distMap(a)
	bm := distMap(b)
	labels := map[string]bool{}
	for k := range am {
		labels[k] = true
	}
	for k := range bm {
		labels[k] = true
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pa, pb := []float64{}, []float64{}
	for _, k := range keys {
		pa = append(pa, am[k])
		pb = append(pb, bm[k])
	}
	return Metric{PSI: psi(pa, pb), JS: js(pa, pb), KS: ks(pa, pb)}
}
func compareOutcome(a map[string]uint64, b []Outcome) Metric {
	bm := map[string]uint64{}
	for _, o := range b {
		bm[o.Label] += o.Count
	}
	am := []float64{}
	bb := []float64{}
	labels := map[string]bool{}
	for k := range a {
		labels[k] = true
	}
	for k := range bm {
		labels[k] = true
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		am = append(am, float64(a[k]))
		bb = append(bb, float64(bm[k]))
	}
	return Metric{PSI: psi(normalize(am), normalize(bb)), JS: js(normalize(am), normalize(bb)), KS: ks(normalize(am), normalize(bb))}
}
func distMap(d Distribution) map[string]float64 {
	out := map[string]float64{}
	for _, b := range d.Buckets {
		out[b.Label] += float64(b.Count)
	}
	return normalizeMap(out)
}
func normalizeMap(in map[string]float64) map[string]float64 {
	var total float64
	for _, v := range in {
		total += v
	}
	out := map[string]float64{}
	if total == 0 {
		return out
	}
	for k, v := range in {
		out[k] = v / total
	}
	return out
}
func normalize(in []float64) []float64 {
	var t float64
	for _, v := range in {
		t += v
	}
	if t == 0 {
		return in
	}
	out := make([]float64, len(in))
	for i, v := range in {
		out[i] = v / t
	}
	return out
}
func psi(a, b []float64) float64 {
	sum := 0.
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		if x < 1e-9 {
			x = 1e-9
		}
		if y < 1e-9 {
			y = 1e-9
		}
		sum += (x - y) * math.Log(x/y)
	}
	return sum
}
func js(a, b []float64) float64 {
	sum := 0.
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		m := (x + y) / 2
		if x > 0 {
			sum += x * math.Log(x/m) / 2
		}
		if y > 0 {
			sum += y * math.Log(y/m) / 2
		}
	}
	return sum
}
func ks(a, b []float64) float64 {
	ca, cb, ret := 0., 0., 0.
	for i := 0; i < len(a) && i < len(b); i++ {
		ca += a[i]
		cb += b[i]
		if d := math.Abs(ca - cb); d > ret {
			ret = d
		}
	}
	return ret
}
func wilson(n uint64) (float64, float64) {
	if n == 0 {
		return 0, 0
	}
	p := 0.5
	z := 1.96
	den := 1 + z*z/float64(n)
	center := (p + z*z/(2*float64(n))) / den
	half := z * math.Sqrt(p*(1-p)/float64(n)+z*z/(4*float64(n)*float64(n))) / den
	return math.Max(0, center-half), math.Min(1, center+half)
}

func (m *Monitor) Explain() string {
	st := m.Status()
	if st.Suppressed {
		return "drift suppressed by minimum sample guardrail"
	}
	if st.Action == "" {
		return fmt.Sprintf("drift status unavailable for %s", strings.TrimSpace(st.Baseline.ID))
	}
	return st.Action
}
