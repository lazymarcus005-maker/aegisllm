// Package trace implements the small W3C Trace Context contract needed by
// the gateway. It deliberately ignores baggage and identity/auth headers.
package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
)

type Context struct{ TraceID, ParentID, SpanID, Flags string }
type key struct{}

var traceparentPattern = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

func Parse(value string) (Context, bool) {
	value = strings.TrimSpace(value)
	if !traceparentPattern.MatchString(value) || strings.EqualFold(value[3:35], strings.Repeat("0", 32)) || strings.EqualFold(value[36:52], strings.Repeat("0", 16)) {
		return Context{}, false
	}
	if strings.EqualFold(value[0:2], "ff") {
		return Context{}, false
	}
	return Context{TraceID: value[3:35], ParentID: value[36:52], Flags: value[53:55]}, true
}

func New(inbound string) Context {
	if got, ok := Parse(inbound); ok {
		got.SpanID = got.ParentID
		return got
	}
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Context{TraceID: strings.Repeat("0", 32), SpanID: strings.Repeat("0", 16), Flags: "01"}
	}
	return Context{TraceID: hex.EncodeToString(b[:16]), SpanID: hex.EncodeToString(b[16:]), Flags: "01"}
}
func Child(parent Context) Context {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		b = [8]byte{}
	}
	return Context{TraceID: parent.TraceID, ParentID: parent.SpanID, SpanID: hex.EncodeToString(b[:]), Flags: parent.Flags}
}
func (c Context) Traceparent() string {
	if len(c.TraceID) != 32 || len(c.SpanID) != 16 {
		return ""
	}
	return "00-" + c.TraceID + "-" + c.SpanID + "-" + c.Flags
}
func With(ctx context.Context, c Context) context.Context { return context.WithValue(ctx, key{}, c) }
func From(ctx context.Context) (Context, bool)            { c, ok := ctx.Value(key{}).(Context); return c, ok }
func FromRequest(r *http.Request) (context.Context, Context) {
	c := New(r.Header.Get("traceparent"))
	c = Child(c)
	ctx := With(r.Context(), c)
	return ctx, c
}
func Inject(req *http.Request, c Context) {
	if value := c.Traceparent(); value != "" {
		req.Header.Set("traceparent", value)
	}
	req.Header.Del("baggage")
	req.Header.Del("authorization")
	req.Header.Del("proxy-authorization")
}
