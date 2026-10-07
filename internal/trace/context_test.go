package trace

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseTraceparent(t *testing.T) {
	valid := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	if _, ok := Parse(valid); !ok {
		t.Fatal("valid traceparent rejected")
	}
	for _, value := range []string{"", "garbage", "00-00000000000000000000000000000000-00f067aa0ba902b7-01", "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"} {
		if _, ok := Parse(value); ok {
			t.Fatalf("invalid traceparent accepted: %q", value)
		}
	}
}

func TestInboundTraceGeneratesSafeChildAndPropagation(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	r.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	r.Header.Set("baggage", "secret=do-not-forward")
	r.Header.Set("Authorization", "Bearer secret")
	ctx, current := FromRequest(r)
	child := Child(current)
	out, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.invalid", nil)
	Inject(out, child)
	if out.Header.Get("baggage") != "" || out.Header.Get("Authorization") != "" {
		t.Fatal("sensitive headers propagated")
	}
	if !strings.HasPrefix(out.Header.Get("traceparent"), "00-4bf92f3577b34da6a3ce929d0e0e4736-") {
		t.Fatalf("trace not preserved: %q", out.Header.Get("traceparent"))
	}
	if current.TraceID == "" || current.SpanID == "" {
		t.Fatalf("missing current context: %+v", current)
	}
}
