package semantic

import (
	"encoding/json"
	"testing"
	"time"
)

func FuzzCanonicalMetadata(f *testing.F) {
	f.Add(`{"format_version":1,"model_id":"m","version":"1","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	f.Fuzz(func(t *testing.T, data string) {
		var m Metadata
		if err := json.Unmarshal([]byte(data), &m); err == nil {
			_ = ValidateMetadata(m, time.Time{}, "")
		}
	})
}

func FuzzDriftSample(f *testing.F) {
	f.Add("tenant-a", "language", "en", uint64(1))
	f.Fuzz(func(t *testing.T, tenant, feature, label string, count uint64) {
		_ = ValidateSample(Sample{TenantScope: tenant, Features: []Distribution{{Feature: feature, Samples: count, Buckets: []Bucket{{Label: label, Count: count}}}}})
	})
}
