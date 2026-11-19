package security

import (
	"context"
	"time"

	"auth-service/internal/kv"
)

// Blacklist menyimpan jti access token yang sudah dicabut (logout).
// Entri hanya perlu hidup sampai token itu kedaluwarsa, jadi TTL = sisa umur
// token: blacklist tidak tumbuh tanpa batas.
type Blacklist struct {
	store kv.Store
}

func NewBlacklist(store kv.Store) *Blacklist {
	return &Blacklist{store: store}
}

func (b *Blacklist) Revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil // sudah kedaluwarsa, tidak perlu dicatat
	}
	return b.store.Set(ctx, "bl:"+jti, "1", ttl)
}

func (b *Blacklist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	_, ok, err := b.store.Get(ctx, "bl:"+jti)
	return ok, err
}
