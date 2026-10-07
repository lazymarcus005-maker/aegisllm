// Package detectors holds the deterministic detection framework and the
// secret/PII detectors. Detectors emit findings — never policy actions
// (architecture §6.3). All byte offsets in findings are UTF-8 byte offsets
// into the scanned text part.
package detectors

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aegisllm/gateway/internal/core"
)

// Detector scans a normalized envelope and returns findings.
type Detector interface {
	Name() string
	Detect(env *core.InspectionEnvelope) []core.SecurityFinding
}

// TimingHook receives per-detector scan durations (wired to metrics later).
type TimingHook func(detector string, d time.Duration)

// Registry runs detectors in registration order and assigns finding IDs.
type Registry struct {
	detectors []Detector
	timing    TimingHook
}

func NewRegistry(hook TimingHook) *Registry {
	return &Registry{timing: hook}
}

// ProductionRegistry returns the detector set used by the gateway runtime.
// Keeping this constructor shared prevents simulators and runtime from
// silently drifting in subtype coverage.
func ProductionRegistry(telemetryKey string, hook TimingHook) *Registry {
	r := NewRegistry(hook)
	for _, d := range SecretDetectors(telemetryKey) {
		r.Register(d)
	}
	for _, d := range PiiDetectors(telemetryKey) {
		r.Register(d)
	}
	return r
}

// Register appends a detector; order defines evaluation order.
func (r *Registry) Register(d Detector) {
	r.detectors = append(r.detectors, d)
}

// Names lists registered detector names in evaluation order.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.detectors))
	for _, d := range r.detectors {
		out = append(out, d.Name())
	}
	return out
}

// RunAll executes every detector against the envelope, timing each one, and
// assigns deterministic sequential finding IDs scoped to the request.
func (r *Registry) RunAll(env *core.InspectionEnvelope) []core.SecurityFinding {
	var out []core.SecurityFinding
	for _, d := range r.detectors {
		start := time.Now()
		findings := d.Detect(env)
		if r.timing != nil {
			r.timing(d.Name(), time.Since(start))
		}
		for _, f := range findings {
			f.ID = fmt.Sprintf("finding-%s-%d", env.RequestID, len(out))
			out = append(out, f)
		}
	}
	return out
}

// HashValue returns a keyed hash for finding correlation (T-006): HMAC-SHA256
// under a dedicated telemetry key, never a bare SHA of a low-entropy value.
// An empty key disables hashing; findings then carry no value_hash.
func HashValue(telemetryKey, value string) string {
	if telemetryKey == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(telemetryKey))
	mac.Write([]byte(value))
	return "sha256:" + hex.EncodeToString(mac.Sum(nil))
}
