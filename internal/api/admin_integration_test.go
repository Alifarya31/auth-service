package api

import (
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"
)

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestAdminAPIFlow(t *testing.T) {
	c := newIntegrationServer(t)
	a := c.newTenant()
	twoFA := []string{"X-2FA-Code", testTwoFA}

	// Endpoint sensitif tanpa 2FA ditolak.
	c.expect(c.do("POST", "/api/roles", a.Access, map[string]any{"name": "auditor"}), http.StatusForbidden)

	// Buat role + beri permission.
	role := c.expect(c.do("POST", "/api/roles", a.Access, map[string]any{"name": "auditor", "description": "Baca audit"}, twoFA...), http.StatusCreated)
	roleID := role.Body["id"].(string)
	c.expect(c.do("POST", "/api/roles", a.Access, map[string]any{"name": "auditor"}, twoFA...), http.StatusConflict)

	rp := c.expect(c.do("POST", "/api/roles/"+roleID+"/permissions", a.Access,
		map[string]any{"permissions": []string{"audit:read", "users:read", "audit:read"}}, twoFA...), http.StatusOK)
	if got := strs(rp.Body["permissions"]); !slices.Equal(got, []string{"audit:read", "users:read"}) {
		t.Fatalf("permission role: %v", got)
	}
	c.expect(c.do("POST", "/api/roles/"+roleID+"/permissions", a.Access,
		map[string]any{"permissions": []string{"does:not_exist"}}, twoFA...), http.StatusBadRequest)

	// Buat user biasa (role member).
	bobEmail := "bob-" + uuid.NewString()[:8] + "@example.com"
	bob := c.expect(c.do("POST", "/api/users", a.Access, map[string]any{
		"email": bobEmail, "password": testPass, "full_name": "Bob", "roles": []string{"member"},
	}, twoFA...), http.StatusCreated)
	bobID := bob.Body["id"].(string)
	c.expect(c.do("POST", "/api/users", a.Access, map[string]any{
		"email": "x-" + bobEmail, "password": testPass, "full_name": "X", "roles": []string{"nope"},
	}, twoFA...), http.StatusBadRequest)

	perm := c.expect(c.do("GET", "/api/users/"+bobID+"/permissions", a.Access, nil), http.StatusOK)
	if got := strs(perm.Body["permissions"]); !slices.Equal(got, []string{"users:read"}) {
		t.Fatalf("permission bob: %v", got)
	}

	// Bob (member) tidak boleh endpoint admin.
	bobAccess, _ := c.login(bobEmail, testPass, a.Slug)
	c.expect(c.do("POST", "/api/users", bobAccess, map[string]any{
		"email": "evil@example.com", "password": testPass, "full_name": "Evil",
	}, twoFA...), http.StatusForbidden)
	c.expect(c.do("GET", "/api/audit/log", bobAccess, nil), http.StatusForbidden)

	// Pemeriksaan dinamis: role member diberi audit:read -> cache bob
	// di-invalidate -> bob langsung bisa akses tanpa login ulang.
	members := c.expect(c.do("GET", "/api/tenants/"+a.TenantID+"/users", a.Access, nil), http.StatusOK)
	if n := len(members.Body["users"].([]any)); n != 2 {
		t.Fatalf("tenant harus punya 2 user, dapat %d", n)
	}
	memberRoleID := findRoleID(t, c, a)
	c.expect(c.do("POST", "/api/roles/"+memberRoleID+"/permissions", a.Access,
		map[string]any{"permissions": []string{"audit:read"}}, twoFA...), http.StatusOK)
	c.expect(c.do("GET", "/api/audit/log", bobAccess, nil), http.StatusOK)

	// Audit log + filter.
	logs := c.expect(c.do("GET", "/api/audit/log?action=permission.change", a.Access, nil), http.StatusOK)
	if n := len(logs.Body["events"].([]any)); n != 2 {
		t.Fatalf("harus ada 2 permission.change, dapat %d", n)
	}
	byUser := c.expect(c.do("GET", "/api/audit/log?user_id="+bobID+"&action=auth.login", a.Access, nil), http.StatusOK)
	if n := len(byUser.Body["events"].([]any)); n != 1 {
		t.Fatalf("bob harus punya 1 login, dapat %d", n)
	}
	ev := byUser.Body["events"].([]any)[0].(map[string]any)
	if ev["ip"] == "" || ev["user_agent"] == nil {
		t.Fatalf("audit harus mencatat IP dan user agent: %v", ev)
	}
	future := c.expect(c.do("GET", "/api/audit/log?from=2999-01-01", a.Access, nil), http.StatusOK)
	if n := len(future.Body["events"].([]any)); n != 0 {
		t.Fatalf("filter tanggal: %d", n)
	}
	c.expect(c.do("GET", "/api/audit/log?from=kemarin", a.Access, nil), http.StatusBadRequest)
}

// findRoleID mengambil ID role "member" tenant langsung dari database,
// karena tidak ada endpoint list role di spesifikasi.
func findRoleID(t *testing.T, c *testClient, f tenantFixture) string {
	t.Helper()
	var id string
	err := c.pool.QueryRow(t.Context(),
		`SELECT id::text FROM roles WHERE tenant_id = $1 AND name = 'member'`, f.TenantID).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestTenantIsolation(t *testing.T) {
	c := newIntegrationServer(t)
	a := c.newTenant()
	b := c.newTenant()
	twoFA := []string{"X-2FA-Code", testTwoFA}

	// Admin B mencoba data tenant A (IDOR).
	c.expect(c.do("GET", "/api/tenants/"+a.TenantID+"/users", b.Access, nil), http.StatusForbidden)
	c.expect(c.do("GET", "/api/users/"+a.UserID+"/permissions", b.Access, nil), http.StatusNotFound)

	roleA := findRoleID(t, c, a)
	c.expect(c.do("POST", "/api/roles/"+roleA+"/permissions", b.Access,
		map[string]any{"permissions": []string{"audit:read"}}, twoFA...), http.StatusNotFound)

	// Role "auditor" milik A tidak bisa dipakai di B.
	c.expect(c.do("POST", "/api/roles", a.Access, map[string]any{"name": "auditor"}, twoFA...), http.StatusCreated)
	c.expect(c.do("POST", "/api/users", b.Access, map[string]any{
		"email": "c-" + uuid.NewString()[:8] + "@example.com", "password": testPass, "full_name": "C", "roles": []string{"auditor"},
	}, twoFA...), http.StatusBadRequest)

	// Audit log B tidak memuat event A.
	logs := c.expect(c.do("GET", "/api/audit/log?limit=200", b.Access, nil), http.StatusOK)
	for _, e := range logs.Body["events"].([]any) {
		if tid := e.(map[string]any)["tenant_id"]; tid != b.TenantID {
			t.Fatalf("audit log bocor dari tenant lain: %v", tid)
		}
	}

	c.expect(c.do("GET", "/api/tenants/bukan-uuid/users", b.Access, nil), http.StatusBadRequest)
}
