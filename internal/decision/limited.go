package decision

import "context"

// LimitedProvider bounds in-flight Evaluate calls. Waiting is context-aware,
// and every acquired slot is released on success, error, or cancellation.
type LimitedProvider struct {
	inner  DecisionProvider
	slots  chan struct{}
	active func(int)
}

func NewLimitedProvider(inner DecisionProvider, maxConcurrent int, active func(int)) *LimitedProvider {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	return &LimitedProvider{inner: inner, slots: make(chan struct{}, maxConcurrent), active: active}
}

func (p *LimitedProvider) Name() string { return "limited-" + p.inner.Name() }

func (p *LimitedProvider) Evaluate(ctx context.Context, req DecisionRequest, ids []string) (DecisionEvidence, error) {
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		return DecisionEvidence{}, ctx.Err()
	}
	if p.active != nil {
		p.active(len(p.slots))
	}
	defer func() {
		<-p.slots
		if p.active != nil {
			p.active(len(p.slots))
		}
	}()
	return p.inner.Evaluate(ctx, req, ids)
}
