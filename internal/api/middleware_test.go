package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"auth-service/internal/kv"
	"auth-service/internal/rbac"
	"auth-service/internal/security"
	"auth-service/internal/store"
)

// Unit test middleware tanpa database: akses user disediakan oleh fake loader.

type fakeAccess map[uuid.UUID]store.Access // key: tenantID

func (f fakeAccess) GetUserAccess(_ context.Context, _, tenantID uuid.UUID) (store.Access, error) {
	return f[tenantID], nil
}

func newUnitServer(t *testing.T, access fakeAccess) *Server {
	t.Helper()
	cfg := testConfig()
	cache := kv.NewMemory()
	t.Cleanup(func() { cache.Close() })
	return &Server{
		Config: cfg,
		Tokens: security.NewTokenManager(cfg.JWTSecret, cfg.AccessTokenTTL),
		RBAC:   rbac.NewService(access, cache, cfg.PermissionCacheTTL),
		KV:     cache,
	}
}

func serve(h http.Handler, token string, headers ...string) int {
	req := httptest.NewRequest("GET", "/x", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

func TestGuardPermission(t *testing.T) {
	tenantA, tenantB := uuid.New(), uuid.New()
	s := newUnitServer(t, fakeAccess{
		tenantA: {Permissions: []string{"users:read"}},
		tenantB: {Permissions: []string{"users:read", "audit:read"}},
	})
	user := uuid.New()
	tokA, _, _ := s.Tokens.Issue(user, tenantA)

	h := s.guard("users:read", okHandler)
	if got := serve(h, ""); got != http.StatusUnauthorized {
		t.Errorf("tanpa token: %d", got)
	}
	if got := serve(h, "not-a-jwt"); got != http.StatusUnauthorized {
		t.Errorf("token rusak: %d", got)
	}
	if got := serve(h, tokA); got != http.StatusOK {
		t.Errorf("punya permission: %d", got)
	}
	// Di tenant B user punya audit:read, tapi token-nya untuk tenant A:
	// permission tenant lain tidak boleh bocor.
	if got := serve(s.guard("audit:read", okHandler), tokA); got != http.StatusForbidden {
		t.Errorf("permission tenant lain: %d", got)
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.1.1:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	if ip := clientIP(r, false); ip != "10.1.1.1" {
		t.Errorf("tanpa trust proxy harus RemoteAddr, dapat %s", ip)
	}
	if ip := clientIP(r, true); ip != "203.0.113.9" {
		t.Errorf("dengan trust proxy harus entri XFF terakhir, dapat %s", ip)
	}
}
