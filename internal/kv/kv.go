// Package kv adalah key-value store sederhana dengan TTL. Dipakai untuk
// cache permission, blacklist token, dan counter rate limit.
//
// Ada dua implementasi dengan interface yang sama:
//   - Redis: state dibagi antar instance (untuk deployment > 1 replika).
//   - Memory: fallback jika Redis tidak dikonfigurasi/tidak tersedia
//     (cukup untuk satu instance; state hilang saat restart).
package kv

import (
	"context"
	"time"
)

type Store interface {
	// Get mengembalikan (value, true) jika key ada dan belum kedaluwarsa.
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Delete(ctx context.Context, keys ...string) error
	// Incr menaikkan counter. TTL hanya dipasang saat key pertama kali dibuat
	// (fixed window), sehingga counter otomatis reset setelah TTL habis.
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	Close() error
}
