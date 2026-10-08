// Package limiter provides a process-local, bounded token-bucket and
// concurrency limiter. It intentionally has no tenant-facing labels or
// logging. Multi-instance limits require an external/distributed limiter.
package limiter

import (
	"errors"
	"math"
	"sort"
	"sync"
	"time"
)

var (
	ErrRateLimited      = errors.New("rate limit exceeded")
	ErrConcurrencyLimit = errors.New("concurrency limit exceeded")
	ErrKeyCapacity      = errors.New("limiter key capacity reached")
)

type Config struct {
	RequestsPerSecond float64
	Burst             int
	MaxConcurrent     int
	MaxKeys           int
	KeyIdleTimeout    time.Duration
}

type Clock func() time.Time

type Result struct {
	RetryAfter time.Duration
	Reason     error
}

type entry struct {
	tokens     float64
	lastRefill time.Time
	lastUsed   time.Time
	active     int
}

// Limiter is safe for concurrent use. A key is retained while active and is
// removed after KeyIdleTimeout once it has no active requests. When the map
// reaches MaxKeys, the oldest inactive key is evicted before rejecting a new
// key, keeping attacker-controlled key cardinality bounded.
type Limiter struct {
	mu          sync.Mutex
	cfg         Config
	now         Clock
	items       map[string]*entry
	nextCleanup time.Time
}

func New(cfg Config) *Limiter {
	return NewWithClock(cfg, time.Now)
}

func NewWithClock(cfg Config, now Clock) *Limiter {
	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 1
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 1
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 1
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = 1
	}
	if cfg.KeyIdleTimeout <= 0 {
		cfg.KeyIdleTimeout = 10 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{cfg: cfg, now: now, items: make(map[string]*entry), nextCleanup: now()}
}

// Allow consumes one request token and one concurrency slot. Release must be
// called exactly once when the request ends; it is safe to call the returned
// function more than once, which helps cancellation/defer paths.
func (l *Limiter) Allow(key string) (release func(), result Result) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupLocked(now)

	e, ok := l.items[key]
	if !ok {
		if len(l.items) >= l.cfg.MaxKeys && !l.evictOneLocked() {
			return nil, Result{RetryAfter: time.Second, Reason: ErrKeyCapacity}
		}
		e = &entry{tokens: float64(l.cfg.Burst), lastRefill: now, lastUsed: now}
		l.items[key] = e
	}
	l.refillLocked(e, now)
	e.lastUsed = now
	if e.tokens < 1 {
		return nil, Result{RetryAfter: l.retryAfter(e.tokens), Reason: ErrRateLimited}
	}
	if e.active >= l.cfg.MaxConcurrent {
		return nil, Result{RetryAfter: time.Second, Reason: ErrConcurrencyLimit}
	}
	e.tokens--
	e.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if current, exists := l.items[key]; exists && current == e {
				if current.active > 0 {
					current.active--
				}
				current.lastUsed = l.now()
			}
			l.mu.Unlock()
		})
	}, Result{}
}

func (l *Limiter) refillLocked(e *entry, now time.Time) {
	if now.Before(e.lastRefill) {
		e.lastRefill = now
		return
	}
	e.tokens = math.Min(float64(l.cfg.Burst), e.tokens+now.Sub(e.lastRefill).Seconds()*l.cfg.RequestsPerSecond)
	e.lastRefill = now
}

func (l *Limiter) retryAfter(tokens float64) time.Duration {
	seconds := (1 - tokens) / l.cfg.RequestsPerSecond
	if seconds <= 0 {
		return time.Second
	}
	return time.Duration(math.Ceil(seconds * float64(time.Second)))
}

func (l *Limiter) cleanupLocked(now time.Time) {
	if now.Before(l.nextCleanup) {
		return
	}
	cutoff := now.Add(-l.cfg.KeyIdleTimeout)
	for key, e := range l.items {
		if e.active == 0 && e.lastUsed.Before(cutoff) {
			delete(l.items, key)
		}
	}
	l.nextCleanup = now.Add(l.cfg.KeyIdleTimeout / 2)
}

func (l *Limiter) evictOneLocked() bool {
	type candidate struct {
		key  string
		when time.Time
	}
	var candidates []candidate
	for key, e := range l.items {
		if e.active == 0 {
			candidates = append(candidates, candidate{key, e.lastUsed})
		}
	}
	if len(candidates) == 0 {
		return false
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].when.Before(candidates[j].when) })
	delete(l.items, candidates[0].key)
	return true
}

// Size returns the current number of tracked keys for bounded-lifecycle tests
// and diagnostics. It does not expose key material.
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items)
}
