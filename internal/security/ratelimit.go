package security

import (
	"context"
	"time"

	"auth-service/internal/kv"
)

// RateLimiter: fixed window counter. Maksimal `max` percobaan per key dalam
// satu `window`. Disimpan di kv.Store sehingga dengan Redis batasnya berlaku
// untuk semua instance service.
type RateLimiter struct {
	store  kv.Store
	max    int
	window time.Duration
}

func NewRateLimiter(store kv.Store, max int, window time.Duration) *RateLimiter {
	return &RateLimiter{store: store, max: max, window: window}
}

func (l *RateLimiter) Window() time.Duration { return l.window }

// Allow mencatat satu percobaan dan mengembalikan false jika batas terlampaui.
func (l *RateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	n, err := l.store.Incr(ctx, "rl:"+key, l.window)
	if err != nil {
		return false, err
	}
	return n <= int64(l.max), nil
}

// Reset menghapus counter (dipanggil setelah login berhasil).
func (l *RateLimiter) Reset(ctx context.Context, key string) error {
	return l.store.Delete(ctx, "rl:"+key)
}
