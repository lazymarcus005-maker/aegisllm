package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/streaming"
)

type streamQueuedEvent struct {
	event        streaming.Event
	fragments    []streaming.Fragment
	replacements map[int]string
	assigned     map[int]bool
}

type streamPendingPart struct {
	queueIndex int
	fragment   int
	text       string
}

type streamState struct {
	server       *Server
	w            http.ResponseWriter
	resp         *http.Response
	env          *core.InspectionEnvelope
	family       string
	queue        []streamQueuedEvent
	pending      string
	pendingParts []streamPendingPart
	committed    bool
	bytes        int64
	events       int
}

func (s *Server) copyStreamResponse(w http.ResponseWriter, resp *http.Response, env *core.InspectionEnvelope, normalizer Normalizer) {
	if resp.StatusCode != http.StatusOK || !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		body, tooLarge, err := readBounded(resp.Body, s.cfg.MaxResponseBytes)
		if err != nil || tooLarge {
			if tooLarge {
				s.runtimeMetrics.ObserveResponseTooLarge()
			}
			s.writeUpstreamError(w, errOrResponseTooLarge(err, tooLarge), env.RequestID)
			return
		}
		if s.pipeline != nil && s.cfg.SecurityMode == ModeEnforce && resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
			out, processErr := s.processOutbound(w, env, normalizer, body)
			if processErr != nil {
				return
			}
			copyResponseHeaders(w, resp.Header)
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(out)
			return
		}
		copyResponseHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return
	}

	state := &streamState{server: s, w: w, resp: resp, env: env, family: streaming.FamilyFor(env.Metadata["endpoint_path"])}
	env.Metadata["endpoint_family"] = state.family
	parser := streaming.NewParser(resp.Body, streaming.Config{
		MaxEventBytes: s.cfg.MaxSSEEventBytes, HoldbackBytes: s.cfg.StreamInspectionWindow,
		MaxBufferedBytes: s.cfg.MaxBufferedStreamBytes,
	})
	defer resp.Body.Close()

	for {
		if resp.Request != nil {
			select {
			case <-resp.Request.Context().Done():
				return
			default:
			}
		}
		event, err := parser.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if err := state.finish(); err != nil && !errors.Is(err, context.Canceled) {
					state.terminalError("STREAM_INCOMPLETE", http.StatusBadGateway)
				}
				return
			}
			if resp.Request != nil && resp.Request.Context().Err() != nil {
				s.proxy.RecordFailure()
				s.runtimeMetrics.ObserveUpstreamTimeout()
			}
			state.terminalError("STREAM_MALFORMED", http.StatusBadGateway)
			return
		}
		state.events++
		state.bytes += int64(len(event.Raw))
		if state.bytes > s.cfg.MaxResponseBytes || state.bytes > s.cfg.MaxBufferedStreamBytes+s.cfg.MaxResponseBytes {
			state.terminalError("STREAM_BUDGET_EXCEEDED", http.StatusBadGateway)
			return
		}
		if event.IsDone {
			if err := state.finish(); err != nil {
				if !errors.Is(err, context.Canceled) {
					state.terminalError(streamErrorCode(err, "STREAM_INCOMPLETE"), http.StatusBadGateway)
				}
				return
			}
			_ = state.write(event.Raw)
			return
		}
		if streamDataHasAttachment([]byte(event.Data)) {
			// SSE reconstruction is text-fragment aware but cannot safely
			// rebuild arbitrary binary protocol blocks. Do not release an
			// attachment-shaped event through the text-only stream path.
			state.terminalError("STREAM_ATTACHMENT_UNSUPPORTED", http.StatusBadGateway)
			return
		}
		fragments, err := streaming.Extract(state.family, event.Data)
		if err != nil {
			if s.cfg.StreamingFailClosed || s.cfg.DeploymentProfile == ProfileProduction {
				state.terminalError("STREAM_MALFORMED", http.StatusBadGateway)
				return
			}
			state.forwardUninspected()
			_ = state.write(event.Raw)
			continue
		}
		if err := state.add(event, fragments); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			state.terminalError(streamErrorCode(err, "STREAM_BUFFER_EXHAUSTED"), http.StatusBadGateway)
			return
		}
		if err := state.flushReady(); err != nil {
			state.terminalError("STREAM_REWRITE_FAILED", http.StatusBadGateway)
			return
		}
	}
}

func streamDataHasAttachment(data []byte) bool {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch item := v.(type) {
		case map[string]any:
			for key, child := range item {
				switch strings.ToLower(key) {
				case "image_url", "input_image", "input_file", "file_data", "document", "attachment", "attachments":
					return true
				}
				if walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range item {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(value)
}

func (s *streamState) add(event streaming.Event, fragments []streaming.Fragment) error {
	q := streamQueuedEvent{event: event, fragments: fragments, replacements: map[int]string{}, assigned: map[int]bool{}}
	if len(fragments) == 0 {
		for i := range fragments {
			q.assigned[i] = true
		}
		s.queue = append(s.queue, q)
		return nil
	}
	qIndex := len(s.queue)
	s.queue = append(s.queue, q)
	for i, fragment := range fragments {
		if fragment.Text == "" {
			s.assign(qIndex, i, "")
			continue
		}
		s.pending += fragment.Text
		s.pendingParts = append(s.pendingParts, streamPendingPart{queueIndex: qIndex, fragment: i, text: fragment.Text})
		out, err := s.server.processStreamText(s.env, s.pending, fragment.Kind)
		if err != nil {
			return err
		}
		if out.Applied == core.ActionBlock || out.Applied == core.ActionReview {
			s.terminalError(out.Code, http.StatusForbidden)
			return context.Canceled
		}
		if out.Applied == core.ActionRedact || out.Applied == core.ActionTokenize {
			s.assignPending(out.Text)
			continue
		}
		s.releaseSafe()
	}
	if int64(len(s.pending)) > s.server.cfg.MaxBufferedStreamBytes {
		return fmt.Errorf("stream inspection buffer exhausted")
	}
	if s.bufferedBytes() > s.server.cfg.MaxBufferedStreamBytes {
		return fmt.Errorf("stream inspection buffer exhausted")
	}
	return nil
}

func (s *streamState) bufferedBytes() int64 {
	total := int64(len(s.pending))
	for _, item := range s.queue {
		total += int64(len(item.event.Raw))
	}
	return total
}

func (s *streamState) releaseSafe() {
	window := s.server.cfg.StreamInspectionWindow
	for len(s.pending) > window && len(s.pendingParts) > 0 {
		part := s.pendingParts[0]
		// Do not split one SSE delta. It remains queued until the next event or
		// finalization, which preserves event meaning and keeps the holdback safe.
		if len(part.text) > len(s.pending)-window {
			return
		}
		s.assign(part.queueIndex, part.fragment, part.text)
		s.pending = s.pending[len(part.text):]
		s.pendingParts = s.pendingParts[1:]
	}
}

func (s *streamState) assignPending(text string) {
	for _, part := range s.pendingParts {
		s.assign(part.queueIndex, part.fragment, "")
	}
	if len(s.pendingParts) > 0 {
		last := s.pendingParts[len(s.pendingParts)-1]
		s.assign(last.queueIndex, last.fragment, text)
	}
	s.pending = ""
	s.pendingParts = nil
}

func (s *streamState) assign(queueIndex, fragment int, value string) {
	if queueIndex < 0 || queueIndex >= len(s.queue) {
		return
	}
	s.queue[queueIndex].replacements[fragment] = value
	s.queue[queueIndex].assigned[fragment] = true
}

func (s *streamState) finish() error {
	if len(s.pending) > 0 {
		kind := "text"
		if len(s.pendingParts) > 0 {
			kind = s.queue[s.pendingParts[len(s.pendingParts)-1].queueIndex].fragments[s.pendingParts[len(s.pendingParts)-1].fragment].Kind
		}
		out, err := s.server.processStreamText(s.env, s.pending, kind)
		if err != nil {
			return err
		}
		if out.Applied == core.ActionBlock || out.Applied == core.ActionReview {
			s.terminalError(out.Code, http.StatusForbidden)
			return context.Canceled
		}
		if out.Applied == core.ActionRedact || out.Applied == core.ActionTokenize {
			s.assignPending(out.Text)
		} else {
			for _, part := range s.pendingParts {
				s.assign(part.queueIndex, part.fragment, part.text)
			}
			s.pending = ""
			s.pendingParts = nil
		}
	}
	return s.flushReady()
}

func (s *streamState) flushReady() error {
	for len(s.queue) > 0 {
		item := s.queue[0]
		if len(item.fragments) > 0 && len(item.assigned) != len(item.fragments) {
			return nil
		}
		data := item.event.Data
		if len(item.fragments) > 0 {
			var err error
			data, err = streaming.Rewrite(s.family, data, item.fragments, item.replacements)
			if err != nil {
				return err
			}
		}
		if err := s.write(item.event.Encode(data)); err != nil {
			return err
		}
		s.queue = s.queue[1:]
	}
	return nil
}

func (s *streamState) write(data []byte) error {
	if !s.committed {
		copyResponseHeaders(s.w, s.resp.Header)
		s.w.WriteHeader(s.resp.StatusCode)
		s.committed = true
	}
	if _, err := s.w.Write(data); err != nil {
		return err
	}
	if f, ok := s.w.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

func (s *streamState) forwardUninspected() {
	for _, item := range s.queue {
		_ = s.write(item.event.Raw)
	}
	s.queue = nil
	s.pending = ""
	s.pendingParts = nil
}

func (s *streamState) terminalError(code string, status int) {
	if code == "" {
		code = "SECURITY_POLICY_BLOCKED"
	}
	if !s.committed {
		writeOpenAIError(s.w, status, "security_policy_violation", code, "Response blocked by security policy.", s.env.RequestID)
		return
	}
	data := `{"error":{"type":"security_policy_violation","code":"` + safeStreamCode(code) + `","message":"Response blocked by security policy."}}`
	prefix := "data: "
	if s.family == "anthropic" {
		data = `{"type":"error","error":{"type":"security_policy_violation","message":"Response blocked by security policy."}}`
		prefix = "event: error\ndata: "
	}
	_ = s.write([]byte(prefix + data + "\n\n"))
}

func safeStreamCode(code string) string {
	var b strings.Builder
	for _, r := range code {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func errOrResponseTooLarge(err error, tooLarge bool) error {
	if err != nil {
		return err
	}
	if tooLarge {
		return errors.New("response too large")
	}
	return errors.New("upstream response failed")
}

func streamErrorCode(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	if strings.Contains(err.Error(), "buffer") {
		return "STREAM_BUFFER_EXHAUSTED"
	}
	return "STREAM_PIPELINE_FAILED"
}

func (s *Server) processStreamText(env *core.InspectionEnvelope, text, kind string) (StreamTextOutcome, error) {
	if contextual, ok := s.pipeline.(interface {
		ProcessStreamText(*core.InspectionEnvelope, string, string) (StreamTextOutcome, error)
	}); ok {
		return contextual.ProcessStreamText(env, text, kind)
	}
	return StreamTextOutcome{Predicted: core.ActionAllow, Applied: core.ActionAllow, Text: text}, nil
}
