package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/audit"
	"auth-service/internal/config"
	"auth-service/internal/kv"
	"auth-service/internal/rbac"
	"auth-service/internal/security"
	"auth-service/internal/store"
	"auth-service/internal/testdb"
)

const (
	testSecret = "0123456789abcdef0123456789abcdef"
	testTwoFA  = "424242"
	testPass   = "s3cret-password"
)

func testConfig() config.Config {
	return config.Config{
		JWTSecret:          testSecret,
		AccessTokenTTL:     time.Minute,
		RefreshTokenTTL:    time.Hour,
		LoginMaxAttempts:   5,
		LoginWindow:        time.Minute,
		TwoFACode:          testTwoFA,
		PermissionCacheTTL: time.Minute,
	}
}

// newIntegrationServer membuat Server dengan database sungguhan
// (skip jika TEST_DATABASE_URL kosong).
func newIntegrationServer(t *testing.T) *testClient {
	t.Helper()
	pool := testdb.Pool(t)
	cfg := testConfig()
	cache := kv.NewMemory()
	t.Cleanup(func() { cache.Close() })
	st := store.New(pool)
	s := &Server{
		Config: cfg,
		Store:  st,
		Audit:  audit.NewLogger(pool),
		Tokens: security.NewTokenManager(cfg.JWTSecret, cfg.AccessTokenTTL),
		RBAC:   rbac.NewService(st, cache, cfg.PermissionCacheTTL),
		KV:     cache,
	}
	return &testClient{t: t, h: s.Handler(), srv: s}
}

type testClient struct {
	t   *testing.T
	h   http.Handler
	srv *Server
}

type resp struct {
	Status int
	Body   map[string]any
	Raw    string
}

func (c *testClient) do(method, path, token string, body any, headers ...string) resp {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	out := resp{Status: rec.Code, Raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.Body)
	return out
}

func (c *testClient) expect(r resp, status int) resp {
	c.t.Helper()
	if r.Status != status {
		c.t.Fatalf("status %d, harapan %d: %s", r.Status, status, r.Raw)
	}
	return r
}

// tenantFixture: tenant baru dengan owner (admin) yang sudah login.
type tenantFixture struct {
	Slug     string
	TenantID string
	Email    string
	UserID   string
	Access   string
	Refresh  string
}

func (c *testClient) newTenant() tenantFixture {
	c.t.Helper()
	id := uuid.NewString()[:8]
	f := tenantFixture{Slug: "t-" + id, Email: fmt.Sprintf("owner-%s@example.com", id)}
	r := c.expect(c.do("POST", "/auth/register", "", map[string]any{
		"email": f.Email, "password": testPass, "full_name": "Owner " + id,
		"tenant_name": "Tenant " + id, "tenant_slug": f.Slug,
	}), http.StatusCreated)
	f.TenantID = r.Body["tenant"].(map[string]any)["id"].(string)
	f.UserID = r.Body["user"].(map[string]any)["id"].(string)
	f.Access, f.Refresh = c.login(f.Email, testPass, f.Slug)
	return f
}

func (c *testClient) login(email, password, slug string) (access, refresh string) {
	c.t.Helper()
	r := c.expect(c.do("POST", "/auth/login", "", map[string]any{
		"email": email, "password": password, "tenant_slug": slug,
	}), http.StatusOK)
	return r.Body["access_token"].(string), r.Body["refresh_token"].(string)
}
