// Package rbac menghitung akses (role + permission) user per tenant dengan
// pola cache-aside: cek cache dulu, jika tidak ada baca dari database lalu
// simpan ke cache. Cache dihapus (invalidate) saat permission berubah.
package rbac

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/kv"
	"auth-service/internal/store"
)

// Loader adalah sumber data akses (di produksi: *store.Store).
// Interface kecil ini membuat Service mudah dites tanpa database.
type Loader interface {
	GetUserAccess(ctx context.Context, userID, tenantID uuid.UUID) (store.Access, error)
}

type Service struct {
	loader Loader
	cache  kv.Store
	ttl    time.Duration
}

func NewService(loader Loader, cache kv.Store, ttl time.Duration) *Service {
	return &Service{loader: loader, cache: cache, ttl: ttl}
}

func cacheKey(tenantID, userID uuid.UUID) string {
	return "perm:" + tenantID.String() + ":" + userID.String()
}

// Access mengembalikan role dan permission user di tenant. Jika cache error
// (mis. Redis mati) service tetap jalan dengan membaca database.
func (s *Service) Access(ctx context.Context, userID, tenantID uuid.UUID) (store.Access, error) {
	key := cacheKey(tenantID, userID)
	if raw, ok, err := s.cache.Get(ctx, key); err != nil {
		slog.Warn("cache permission gagal dibaca", "err", err)
	} else if ok {
		var a store.Access
		if json.Unmarshal([]byte(raw), &a) == nil {
			return a, nil
		}
	}

	a, err := s.loader.GetUserAccess(ctx, userID, tenantID)
	if err != nil {
		return store.Access{}, err
	}
	if b, err := json.Marshal(a); err == nil {
		if err := s.cache.Set(ctx, key, string(b), s.ttl); err != nil {
			slog.Warn("cache permission gagal ditulis", "err", err)
		}
	}
	return a, nil
}

// HasPermission adalah pemeriksaan dinamis: permission dibaca saat request
// (bukan dari isi JWT), jadi perubahan role berlaku tanpa user login ulang.
func (s *Service) HasPermission(ctx context.Context, userID, tenantID uuid.UUID, perm string) (bool, error) {
	a, err := s.Access(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	return slices.Contains(a.Permissions, perm), nil
}

// Invalidate menghapus cache akses user-user tertentu di tenant.
func (s *Service) Invalidate(ctx context.Context, tenantID uuid.UUID, userIDs ...uuid.UUID) {
	keys := make([]string, len(userIDs))
	for i, u := range userIDs {
		keys[i] = cacheKey(tenantID, u)
	}
	if err := s.cache.Delete(ctx, keys...); err != nil {
		// Paling buruk perubahan baru berlaku setelah TTL cache habis.
		slog.Error("gagal invalidate cache permission", "err", err)
	}
}
