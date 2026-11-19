package api

import (
	"net/http"
	"testing"
)

func TestRegisterLoginMe(t *testing.T) {
	c := newIntegrationServer(t)
	f := c.newTenant()

	me := c.expect(c.do("GET", "/auth/me", f.Access, nil), http.StatusOK)
	if me.Body["user"].(map[string]any)["email"] != f.Email {
		t.Fatalf("email salah: %s", me.Raw)
	}
	if _, ok := me.Body["user"].(map[string]any)["password_hash"]; ok {
		t.Fatal("password_hash tidak boleh dikirim ke client")
	}
	roles := me.Body["roles"].([]any)
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("owner harus ber-role admin: %v", roles)
	}
	if len(me.Body["permissions"].([]any)) != 5 {
		t.Fatalf("admin harus punya semua permission: %v", me.Body["permissions"])
	}

	// Duplikat email dan slug ditolak.
	c.expect(c.do("POST", "/auth/register", "", map[string]any{
		"email": f.Email, "password": testPass, "full_name": "X", "tenant_name": "X", "tenant_slug": "other-" + f.Slug,
	}), http.StatusConflict)
	c.expect(c.do("POST", "/auth/register", "", map[string]any{
		"email": "new-" + f.Email, "password": testPass, "full_name": "X", "tenant_name": "X", "tenant_slug": f.Slug,
	}), http.StatusConflict)
}

func TestLoginFailuresAreGeneric(t *testing.T) {
	c := newIntegrationServer(t)
	f := c.newTenant()
	other := c.newTenant()

	cases := map[string]map[string]any{
		"password salah":   {"email": f.Email, "password": "wrong-password", "tenant_slug": f.Slug},
		"email tidak ada":  {"email": "nobody@example.com", "password": testPass, "tenant_slug": f.Slug},
		"bukan anggota":    {"email": f.Email, "password": testPass, "tenant_slug": other.Slug},
		"tenant tidak ada": {"email": f.Email, "password": testPass, "tenant_slug": "no-such-tenant"},
	}
	for name, body := range cases {
		r := c.do("POST", "/auth/login", "", body)
		if r.Status != http.StatusUnauthorized || r.Body["error"] != "invalid_credentials" {
			t.Errorf("%s: dapat %d %s", name, r.Status, r.Raw)
		}
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	c := newIntegrationServer(t)
	f := c.newTenant()

	// Rotasi: refresh token lama diganti yang baru.
	r1 := c.expect(c.do("POST", "/auth/refresh", "", map[string]any{"refresh_token": f.Refresh}), http.StatusOK)
	newRefresh := r1.Body["refresh_token"].(string)
	if newRefresh == f.Refresh {
		t.Fatal("refresh token harus berganti")
	}
	c.expect(c.do("GET", "/auth/me", r1.Body["access_token"].(string), nil), http.StatusOK)

	// Reuse token lama -> terdeteksi, seluruh family dicabut.
	reuse := c.expect(c.do("POST", "/auth/refresh", "", map[string]any{"refresh_token": f.Refresh}), http.StatusUnauthorized)
	if reuse.Body["error"] != "token_reused" {
		t.Fatalf("harus terdeteksi reuse: %s", reuse.Raw)
	}
	// Token terbaru di family yang sama ikut tidak berlaku.
	c.expect(c.do("POST", "/auth/refresh", "", map[string]any{"refresh_token": newRefresh}), http.StatusUnauthorized)

	c.expect(c.do("POST", "/auth/refresh", "", map[string]any{"refresh_token": "garbage"}), http.StatusUnauthorized)
}

func TestLogoutRevokesTokens(t *testing.T) {
	c := newIntegrationServer(t)
	f := c.newTenant()

	c.expect(c.do("POST", "/auth/logout", "", nil), http.StatusUnauthorized)
	c.expect(c.do("POST", "/auth/logout", f.Access, map[string]any{"refresh_token": f.Refresh}), http.StatusNoContent)
	// Access token masuk blacklist, refresh token dicabut.
	c.expect(c.do("GET", "/auth/me", f.Access, nil), http.StatusUnauthorized)
	c.expect(c.do("POST", "/auth/refresh", "", map[string]any{"refresh_token": f.Refresh}), http.StatusUnauthorized)
}

func TestLoginRateLimit(t *testing.T) {
	c := newIntegrationServer(t)
	f := c.newTenant() // login sukses di sini me-reset counter

	bad := map[string]any{"email": f.Email, "password": "wrong-password", "tenant_slug": f.Slug}
	for range c.srv.Config.LoginMaxAttempts {
		c.expect(c.do("POST", "/auth/login", "", bad), http.StatusUnauthorized)
	}
	r := c.expect(c.do("POST", "/auth/login", "", bad), http.StatusTooManyRequests)
	if r.Body["error"] != "too_many_attempts" {
		t.Fatalf("harus too_many_attempts: %s", r.Raw)
	}
	// Password benar pun ditolak selama window masih berjalan.
	c.expect(c.do("POST", "/auth/login", "", map[string]any{
		"email": f.Email, "password": testPass, "tenant_slug": f.Slug,
	}), http.StatusTooManyRequests)
}
