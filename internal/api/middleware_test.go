package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"auth-service/internal/config"
	"auth-service/internal/kv"
	"auth-service/internal/rbac"
	"auth-service/internal/store"
)

// Unit test middleware tanpa database: akses user disediakan oleh fake loader.

type fakeAccess map[uuid.UUID]store.Access // key: tenantID

func (f fakeAccess) GetUserAccess(_ context.Context, _, tenantID uuid.UUID) (store.Access, error) {
	return f[tenantID], nil
}

func newUnitServer(t *testing.T, access fakeAccess, mutate ...func(*config.Config)) *Server {
	t.Helper()
	cfg := testConfig()
	for _, m := range mutate {
		m(&cfg)
	}
	cache := kv.NewMemory()
	t.Cleanup(func() { cache.Close() })
	s, err := New(cfg, nil, nil, cache) // tanpa database & audit
	if err != nil {
		t.Fatal(err)
	}
	s.RBAC = rbac.NewService(access, cache, cfg.PermissionCacheTTL)
	return s
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

func TestBlacklistedTokenRejected(t *testing.T) {
	tenant := uuid.New()
	s := newUnitServer(t, fakeAccess{tenant: {Permissions: []string{"users:read"}}})
	tok, claims, _ := s.Tokens.Issue(uuid.New(), tenant)
	h := s.guard("users:read", okHandler)

	if got := serve(h, tok); got != http.StatusOK {
		t.Fatalf("sebelum dicabut: %d", got)
	}
	_ = s.Blacklist.Revoke(context.Background(), claims.ID, claims.ExpiresAt.Time)
	if got := serve(h, tok); got != http.StatusUnauthorized {
		t.Fatalf("token di blacklist harus ditolak: %d", got)
	}
}

func TestRequire2FA(t *testing.T) {
	tenant := uuid.New()
	s := newUnitServer(t, fakeAccess{tenant: {Permissions: []string{"users:create"}}})
	tok, _, _ := s.Tokens.Issue(uuid.New(), tenant)
	h := s.guardSensitive("users:create", okHandler)

	if got := serve(h, tok); got != http.StatusForbidden {
		t.Errorf("tanpa header 2FA: %d", got)
	}
	if got := serve(h, tok, "X-2FA-Code", "000000"); got != http.StatusForbidden {
		t.Errorf("kode 2FA salah: %d", got)
	}
	if got := serve(h, tok, "X-2FA-Code", testTwoFA); got != http.StatusOK {
		t.Errorf("kode 2FA benar: %d", got)
	}
}

func TestIPWhitelist(t *testing.T) {
	s := newUnitServer(t, fakeAccess{}, func(c *config.Config) {
		c.IPWhitelist = []string{"10.0.0.0/8"}
	})
	h := s.Handler()
	call := func(path, ip string) int {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = ip + ":1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call("/auth/me", "192.168.1.1"); got != http.StatusForbidden {
		t.Errorf("IP di luar whitelist: %d", got)
	}
	if got := call("/auth/me", "10.1.2.3"); got != http.StatusUnauthorized {
		t.Errorf("IP di whitelist harus lolos ke authenticate (401 tanpa token): %d", got)
	}
	if got := call("/healthz", "192.168.1.1"); got != http.StatusOK {
		t.Errorf("/healthz dikecualikan: %d", got)
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
