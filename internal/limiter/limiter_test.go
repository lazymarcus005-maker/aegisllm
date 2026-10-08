package limiter

import (
	"errors"
	"testing"
	"time"
)

func TestTokenBucketUsesInjectedClock(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewWithClock(Config{RequestsPerSecond: 2, Burst: 2, MaxConcurrent: 2, MaxKeys: 10, KeyIdleTimeout: time.Minute}, func() time.Time { return now })
	release, result := l.Allow("tenant-a/app-a")
	if result.Reason != nil {
		t.Fatalf("first request rejected: %v", result.Reason)
	}
	release()
	release, result = l.Allow("tenant-a/app-a")
	if result.Reason != nil {
		t.Fatalf("second request rejected: %v", result.Reason)
	}
	release()
	if _, result = l.Allow("tenant-a/app-a"); !errors.Is(result.Reason, ErrRateLimited) {
		t.Fatalf("third request reason = %v", result.Reason)
	}
	now = now.Add(500 * time.Millisecond)
	release, result = l.Allow("tenant-a/app-a")
	if result.Reason != nil {
		t.Fatalf("refilled request rejected: %v", result.Reason)
	}
	release()
}

func TestKeysAreIsolatedAndConcurrencyIsReleased(t *testing.T) {
	l := NewWithClock(Config{RequestsPerSecond: 100, Burst: 10, MaxConcurrent: 1, MaxKeys: 10, KeyIdleTimeout: time.Minute}, time.Now)
	release, result := l.Allow("tenant-a/app-a")
	if result.Reason != nil {
		t.Fatal(result.Reason)
	}
	if _, result = l.Allow("tenant-a/app-a"); !errors.Is(result.Reason, ErrConcurrencyLimit) {
		t.Fatalf("same key reason = %v", result.Reason)
	}
	other, result := l.Allow("tenant-b/app-a")
	if result.Reason != nil {
		t.Fatalf("different key rejected: %v", result.Reason)
	}
	other()
	release()
	if release, result = l.Allow("tenant-a/app-a"); result.Reason != nil {
		t.Fatalf("released slot rejected: %v", result.Reason)
	} else {
		release()
	}
}

func TestCleanupAndCapacityBoundKeys(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewWithClock(Config{RequestsPerSecond: 10, Burst: 1, MaxConcurrent: 1, MaxKeys: 2, KeyIdleTimeout: time.Second}, func() time.Time { return now })
	for _, key := range []string{"a", "b"} {
		release, result := l.Allow(key)
		if result.Reason != nil {
			t.Fatal(result.Reason)
		}
		release()
	}
	if got := l.Size(); got != 2 {
		t.Fatalf("size before cleanup = %d", got)
	}
	now = now.Add(2 * time.Second)
	release, result := l.Allow("c")
	if result.Reason != nil {
		t.Fatalf("new key rejected after cleanup: %v", result.Reason)
	}
	release()
	if got := l.Size(); got != 1 {
		t.Fatalf("size after cleanup = %d, want 1", got)
	}
}

func BenchmarkAllow(b *testing.B) {
	l := New(Config{RequestsPerSecond: 1e9, Burst: b.N + 1, MaxConcurrent: 1, MaxKeys: 10, KeyIdleTimeout: time.Hour})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		release, result := l.Allow("tenant/application")
		if result.Reason != nil {
			b.Fatal(result.Reason)
		}
		release()
	}
}
