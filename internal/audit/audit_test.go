package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aegisllm/gateway/internal/core"
)

func TestEventSerializationCarriesNoRawContent(t *testing.T) {
	secret := "glpat-SuperSecretValue123456"
	citizenID := "1234567890123"

	findings := []core.SecurityFinding{
		{
			ID: "finding-1", Category: core.CategorySecret, Subtype: "GITLAB_PAT",
			Detector: "pattern", Confidence: 1.0,
			Location:  core.Span{MessageIndex: 0, PartIndex: 0, Start: 4, End: 30},
			ValueHash: "sha256:deadbeef",
		},
	}

	ev := Event{
		RequestID:     "req-1",
		Timestamp:     mustTime(t),
		Direction:     core.DirectionRequest,
		Application:   "agent-x",
		PolicyID:      "enterprise-default",
		PolicyVersion: 1,
		Mode:          "enforce",
		Action:        core.ActionBlock,
		Code:          "SECRET_DETECTED",
		MatchedRule:   "secrets.GITLAB_PAT",
		FindingTypes:  FindingTypes(findings),
		FindingCount:  len(findings),
		LatencyMS:     map[string]int64{"deterministic": 2, "total_security": 3},
	}

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, leak := range []string{secret, citizenID, "deadbeef", "glpat"} {
		// deadbeef would be a hash prefix leak; hashes are correlation data
		// allowed under a dedicated telemetry key, but the full hash value
		// must not appear when not configured.
		if strings.Contains(out, leak) {
			t.Fatalf("audit event leaked %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, `"finding_types":["GITLAB_PAT"]`) {
		t.Fatalf("finding types missing: %s", out)
	}
}

func TestRAGAuditProjectionCarriesOnlyBoundedMetadata(t *testing.T) {
	b, err := json.Marshal(Event{RequestID: "req-rag", Component: "rag_authorization", RAG: true, RAGOperation: "retrieve", RAGChunks: 2,
		Code: "RAG_AUTH_ALLOWED", Action: core.ActionAllow, Reason: "retrieval authorization succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, forbidden := range []string{"secret query", "document text", "bearer-token", "sensitive-label", "doc-123"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("RAG audit leaked %q: %s", forbidden, out)
		}
	}
	if !strings.Contains(out, `"rag":true`) || !strings.Contains(out, `"rag_chunks":2`) {
		t.Fatalf("RAG metadata missing: %s", out)
	}
}

func TestFindingTypesDistinctInOrder(t *testing.T) {
	fs := []core.SecurityFinding{
		{Subtype: "GITLAB_PAT"},
		{Subtype: "JWT"},
		{Subtype: "GITLAB_PAT"},
	}
	got := FindingTypes(fs)
	if len(got) != 2 || got[0] != "GITLAB_PAT" || got[1] != "JWT" {
		t.Fatalf("finding types: %v", got)
	}
}

func TestWriterSinkOneJSONPerLine(t *testing.T) {
	var buf bytes.Buffer
	sink := NewWriterSink(&buf)
	sink.Record(Event{RequestID: "req-1", Mode: "shadow", Action: core.ActionAllow})
	sink.Record(Event{RequestID: "req-2", Mode: "enforce", Action: core.ActionBlock})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	var back Event
	if err := json.Unmarshal([]byte(lines[1]), &back); err != nil {
		t.Fatal(err)
	}
	if back.RequestID != "req-2" || back.Action != core.ActionBlock {
		t.Fatalf("round trip mismatch: %+v", back)
	}
}

func mustTime(t *testing.T) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, "2026-10-05T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return tm
}
