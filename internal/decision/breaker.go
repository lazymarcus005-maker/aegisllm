package decision

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned while the breaker is open: the provider is
// known-unhealthy and calls are shed. Callers must treat it as provider
// unavailability — never as "safe" (INV-008).
var ErrCircuitOpen = errors.New("semantic provider circuit open")

// CircuitBreaker sheds calls after repeated provider failures and retries
// after a cooldown.
type CircuitBreaker struct {
	mu        sync.Mutex
	failures  int
	threshold int
	cooldown  time.Duration
	openUntil time.Time
	now       func() time.Time
}

func NewCircuitBreaker(threshold int, cooldown time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 3
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &CircuitBreaker{threshold: threshold, cooldown: cooldown, now: time.Now}
}

// SetClock overrides time for tests.
func (b *CircuitBreaker) SetClock(now func() time.Time) {
	b.mu.Lock()
	b.now = now
	b.mu.Unlock()
}

// Allow reports whether a call may proceed.
func (b *CircuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures < b.threshold {
		return true
	}
	return b.now().After(b.openUntil)
}

// Record reports a call outcome; the threshold-th consecutive failure opens
// the breaker for the cooldown period.
func (b *CircuitBreaker) Record(success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if success {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.openUntil = b.now().Add(b.cooldown)
	}
}

// ResilientProvider wraps a DecisionProvider with the circuit breaker so that
// an unhealthy laya-serve sheds load instead of stalling every request
// (T-017). Errors (including ErrCircuitOpen) always surface as errors; the
// pipeline's policy-controlled fallback decides the action (NFR-AVAIL-002).
type ResilientProvider struct {
	inner   DecisionProvider
	breaker *CircuitBreaker
}

func NewResilientProvider(inner DecisionProvider, breaker *CircuitBreaker) *ResilientProvider {
	return &ResilientProvider{inner: inner, breaker: breaker}
}

func (r *ResilientProvider) Name() string { return "resilient-" + r.inner.Name() }

func (r *ResilientProvider) Evaluate(ctx context.Context, req DecisionRequest, ids []string) (DecisionEvidence, error) {
	if !r.breaker.Allow() {
		return DecisionEvidence{}, ErrCircuitOpen
	}
	ev, err := r.inner.Evaluate(ctx, req, ids)
	r.breaker.Record(err == nil)
	return ev, err
}
