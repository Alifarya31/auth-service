package kv

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type Redis struct {
	c *redis.Client
}

// NewRedis membuka koneksi dan langsung mengetes dengan PING.
func NewRedis(ctx context.Context, url string) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	c := redis.NewClient(opt)
	if err := c.Ping(ctx).Err(); err != nil {
		c.Close()
		return nil, err
	}
	return &Redis{c: c}, nil
}

func (r *Redis) Get(ctx context.Context, key string) (string, bool, error) {
	v, err := r.c.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (r *Redis) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return r.c.Set(ctx, key, value, ttl).Err()
}

func (r *Redis) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return r.c.Del(ctx, keys...).Err()
}

// Incr: INCR + EXPIRE NX dalam satu transaksi (MULTI/EXEC). EXPIRE NX hanya
// memasang TTL jika key belum punya TTL, yaitu saat window baru dimulai.
func (r *Redis) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	var incr *redis.IntCmd
	_, err := r.c.TxPipelined(ctx, func(p redis.Pipeliner) error {
		incr = p.Incr(ctx, key)
		p.ExpireNX(ctx, key, ttl)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

func (r *Redis) Close() error { return r.c.Close() }
