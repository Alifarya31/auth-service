package api

import (
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/audit"
	"auth-service/internal/security"
	"auth-service/internal/store"
)

var roleNamePattern = regexp.MustCompile(`^[a-z0-9_-]{2,50}$`)

// pathUUID membaca {name} dari path sebagai UUID; menulis 400 jika tidak valid.
func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", name+" harus berupa UUID")
		return uuid.Nil, false
	}
	return id, true
}

// dedup membuang duplikat dan string kosong, sambil menjaga urutan.
func dedup(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// POST /api/users (users:create + 2FA) — admin membuat user di tenant-nya.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var req struct {
		Email    string   `json:"email"`
		Password string   `json:"password"`
		FullName string   `json:"full_name"`
		Roles    []string `json:"roles"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = normalizeEmail(req.Email)
	req.Roles = dedup(req.Roles)
	if len(req.Roles) == 0 {
		req.Roles = []string{store.RoleMember}
	}
	switch {
	case !emailPattern.MatchString(req.Email):
		writeError(w, http.StatusBadRequest, "validation_error", "email tidak valid")
		return
	case strings.TrimSpace(req.FullName) == "":
		writeError(w, http.StatusBadRequest, "validation_error", "full_name wajib diisi")
		return
	}
	hash, err := security.HashPassword(req.Password)
	if errors.Is(err, security.ErrWeakPassword) {
		writeError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	} else if err != nil {
		internalError(w, err)
		return
	}

	user, err := s.Store.CreateUserInTenant(r.Context(), p.TenantID, req.Email, strings.TrimSpace(req.FullName), hash, req.Roles)
	switch {
	case errors.Is(err, store.ErrEmailTaken):
		writeError(w, http.StatusConflict, "conflict", err.Error())
		return
	case errors.Is(err, store.ErrUnknownRole):
		writeError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	case err != nil:
		internalError(w, err)
		return
	}
	s.logAudit(r, audit.ActionUserCreate, &p.UserID, &p.TenantID,
		map[string]any{"target_user_id": user.ID, "email": user.Email, "roles": req.Roles})
	writeJSON(w, http.StatusCreated, store.TenantUser{User: user, Roles: req.Roles})
}

// GET /api/users/{id}/permissions (users:read) — hanya user di tenant pemanggil.
func (s *Server) handleUserPermissions(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	userID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	member, err := s.Store.IsMember(r.Context(), userID, p.TenantID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !member {
		// 404 (bukan 403): tidak membocorkan bahwa user ada di tenant lain.
		writeError(w, http.StatusNotFound, "not_found", "user tidak ditemukan di tenant ini")
		return
	}
	access, err := s.RBAC.Access(r.Context(), userID, p.TenantID)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":     userID,
		"tenant_id":   p.TenantID,
		"roles":       access.Roles,
		"permissions": access.Permissions,
	})
}

// POST /api/roles (roles:create + 2FA)
func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.ToLower(strings.TrimSpace(req.Name))
	if !roleNamePattern.MatchString(req.Name) {
		writeError(w, http.StatusBadRequest, "validation_error", "name hanya huruf kecil, angka, '_' atau '-' (2-50 karakter)")
		return
	}
	role, err := s.Store.CreateRole(r.Context(), p.TenantID, req.Name, strings.TrimSpace(req.Description))
	if errors.Is(err, store.ErrRoleExists) {
		writeError(w, http.StatusConflict, "conflict", err.Error())
		return
	} else if err != nil {
		internalError(w, err)
		return
	}
	s.logAudit(r, audit.ActionRoleCreate, &p.UserID, &p.TenantID,
		map[string]any{"role_id": role.ID, "name": role.Name})
	writeJSON(w, http.StatusCreated, role)
}

// POST /api/roles/{id}/permissions (roles:assign_permissions + 2FA)
func (s *Server) handleAddRolePermissions(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	roleID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Permissions []string `json:"permissions"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Permissions = dedup(req.Permissions)
	if len(req.Permissions) == 0 {
		writeError(w, http.StatusBadRequest, "validation_error", "permissions wajib diisi")
		return
	}

	perms, affected, err := s.Store.AddRolePermissions(r.Context(), p.TenantID, roleID, req.Permissions)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "role tidak ditemukan di tenant ini")
		return
	case errors.Is(err, store.ErrUnknownPermission):
		writeError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	case err != nil:
		internalError(w, err)
		return
	}

	// Permission berubah -> hapus cache semua pemegang role ini.
	s.RBAC.Invalidate(r.Context(), p.TenantID, affected...)
	s.logAudit(r, audit.ActionPermissionChange, &p.UserID, &p.TenantID, map[string]any{
		"role_id": roleID, "added": req.Permissions, "affected_users": len(affected),
	})
	writeJSON(w, http.StatusOK, map[string]any{"role_id": roleID, "permissions": perms})
}

// GET /api/tenants/{id}/users (users:read) — hanya untuk tenant di token.
func (s *Server) handleTenantUsers(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	tenantID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if !sameTenant(p, tenantID) {
		s.logAudit(r, audit.ActionAccessDenied, &p.UserID, &p.TenantID,
			map[string]any{"reason": "cross_tenant", "target_tenant_id": tenantID, "path": r.URL.Path})
		writeError(w, http.StatusForbidden, "forbidden", "tidak boleh mengakses tenant lain")
		return
	}
	users, err := s.Store.ListTenantUsers(r.Context(), tenantID)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tenantID, "users": users})
}

// GET /api/audit/log?action=&user_id=&from=&to=&limit=&offset= (audit:read)
// Selalu dibatasi ke tenant pemanggil.
func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	q := r.URL.Query()
	f := audit.Filter{TenantID: p.TenantID, Action: q.Get("action"), Limit: 50}

	bad := func(msg string) { writeError(w, http.StatusBadRequest, "validation_error", msg) }

	if v := q.Get("user_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			bad("user_id harus UUID")
			return
		}
		f.UserID = &id
	}
	if v := q.Get("from"); v != "" {
		t, _, err := parseDate(v)
		if err != nil {
			bad("from harus RFC3339 atau YYYY-MM-DD")
			return
		}
		f.From = &t
	}
	if v := q.Get("to"); v != "" {
		t, dateOnly, err := parseDate(v)
		if err != nil {
			bad("to harus RFC3339 atau YYYY-MM-DD")
			return
		}
		if dateOnly {
			t = t.AddDate(0, 0, 1) // to=2026-11-19 mencakup seluruh hari itu
		}
		f.To = &t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			bad("limit harus 1-200")
			return
		}
		f.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			bad("offset harus >= 0")
			return
		}
		f.Offset = n
	}

	events, err := s.Audit.List(r.Context(), f)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "limit": f.Limit, "offset": f.Offset})
}

// parseDate menerima RFC3339 atau tanggal saja (YYYY-MM-DD, UTC).
func parseDate(v string) (t time.Time, dateOnly bool, err error) {
	if t, err = time.Parse(time.RFC3339, v); err == nil {
		return t, false, nil
	}
	t, err = time.Parse(time.DateOnly, v)
	return t, true, err
}
