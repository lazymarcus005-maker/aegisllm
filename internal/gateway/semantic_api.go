package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aegisllm/gateway/internal/auth"
	semanticcontrol "github.com/aegisllm/gateway/internal/semantic"
)

func (s *Server) handleSemanticModels(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if _, err := fmt.Sscan(raw, &limit); err != nil {
			limit = 100
		}
	}
	out := make([]semanticcontrol.RecordView, 0, limit)
	for _, record := range s.semanticRegistry.List(limit) {
		out = append(out, semanticcontrol.View(record))
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": s.semanticRegistry.Revision(), "models": out})
}

func (s *Server) handleSemanticStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.semanticRegistry.Status())
}
func (s *Server) handleSemanticHistory(w http.ResponseWriter, r *http.Request) {
	limit := 100
	_ = r
	writeJSON(w, http.StatusOK, map[string]any{"history": s.semanticRegistry.History(limit)})
}
func (s *Server) handleSemanticDrift(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.semanticDrift.Status())
}

func decodeSemanticBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid semantic lifecycle request"})
		return false
	}
	return true
}

func actorForSemantic(r *http.Request) (string, bool) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		return "", false
	}
	if p.Subject != "" {
		return p.Subject, true
	}
	return "operator", true
}

func (s *Server) handleSemanticValidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Artifact semanticcontrol.Artifact `json:"artifact"`
	}
	if !decodeSemanticBody(w, r, &req) {
		return
	}
	if err := s.semanticRegistry.ValidateArtifact(req.Artifact); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "semantic artifact rejected"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "validated"})
}

func (s *Server) handleSemanticRegister(w http.ResponseWriter, r *http.Request) {
	actor, ok := actorForSemantic(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "verified operator identity required"})
		return
	}
	var req struct {
		Artifact         semanticcontrol.Artifact `json:"artifact"`
		Provenance       string                   `json:"provenance"`
		IdempotencyKey   string                   `json:"idempotency_key"`
		ExpectedRevision uint64                   `json:"expected_revision"`
	}
	if !decodeSemanticBody(w, r, &req) {
		return
	}
	record, err := s.semanticRegistry.Register(semanticcontrol.Request{Artifact: req.Artifact, Actor: actor, Provenance: boundedSemantic(req.Provenance), IdempotencyKey: req.IdempotencyKey, ExpectedRevision: req.ExpectedRevision})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "semantic registration rejected"})
		return
	}
	writeJSON(w, http.StatusCreated, semanticcontrol.View(record))
}

func (s *Server) handleSemanticTransition(w http.ResponseWriter, r *http.Request) {
	actor, ok := actorForSemantic(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "verified operator identity required"})
		return
	}
	var req struct {
		Model            semanticcontrol.ModelRef `json:"model"`
		To               semanticcontrol.State    `json:"to"`
		Reason           string                   `json:"reason"`
		Provenance       string                   `json:"provenance"`
		IdempotencyKey   string                   `json:"idempotency_key"`
		ExpectedRevision uint64                   `json:"expected_revision"`
		Confirm          bool                     `json:"confirm"`
	}
	if !decodeSemanticBody(w, r, &req) {
		return
	}
	if req.To == "" {
		switch strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/semantic/"), "/") {
		case "shadow":
			req.To = semanticcontrol.Shadow
		case "canary":
			req.To = semanticcontrol.Canary
		case "promote":
			req.To = semanticcontrol.Promoted
		case "pause":
			req.To = semanticcontrol.Paused
		case "rollback":
			req.To = semanticcontrol.RolledBack
		case "retire":
			req.To = semanticcontrol.Retired
		case "revoke":
			req.To = semanticcontrol.Revoked
		}
	}
	record, exists := s.semanticRegistry.Get(req.Model)
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "semantic model not found"})
		return
	}
	record, err := s.semanticRegistry.Transition(semanticcontrol.Request{Artifact: record.Artifact, Actor: actor, Provenance: boundedSemantic(req.Provenance + ":" + req.Reason), IdempotencyKey: req.IdempotencyKey, ExpectedRevision: req.ExpectedRevision, Confirm: req.Confirm}, req.To)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "semantic transition rejected"})
		return
	}
	writeJSON(w, http.StatusOK, semanticcontrol.View(record))
}

func (s *Server) handleSemanticCompare(w http.ResponseWriter, r *http.Request) {
	a := semanticcontrol.ModelRef{ID: r.URL.Query().Get("a_id"), Version: r.URL.Query().Get("a_version"), Digest: r.URL.Query().Get("a_digest")}
	b := semanticcontrol.ModelRef{ID: r.URL.Query().Get("b_id"), Version: r.URL.Query().Get("b_version"), Digest: r.URL.Query().Get("b_digest")}
	ra, oka := s.semanticRegistry.Get(a)
	rb, okb := s.semanticRegistry.Get(b)
	if !oka || !okb {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "semantic model not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"a": semanticcontrol.View(ra), "b": semanticcontrol.View(rb), "same_detector": ra.Artifact.Metadata.Detector == rb.Artifact.Metadata.Detector, "same_task": ra.Artifact.Metadata.Task == rb.Artifact.Metadata.Task, "same_threshold_artifact": ra.Artifact.Metadata.ThresholdDigest == rb.Artifact.Metadata.ThresholdDigest})
}

func boundedSemantic(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 96 {
		return v[:96]
	}
	return v
}
