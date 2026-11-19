package api

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/audit"
	"auth-service/internal/security"
	"auth-service/internal/store"
)

var (
	slugPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$`)
	emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // detik
}

// issueTokens membuat access token + refresh token baru (family baru).
func (s *Server) issueTokens(r *http.Request, userID, tenantID uuid.UUID) (tokenResponse, error) {
	access, _, err := s.Tokens.Issue(userID, tenantID)
	if err != nil {
		return tokenResponse{}, err
	}
	raw, hash, err := security.NewRefreshToken()
	if err != nil {
		return tokenResponse{}, err
	}
	err = s.Store.CreateRefreshToken(r.Context(), store.RefreshToken{
		UserID: userID, TenantID: tenantID, FamilyID: uuid.New(),
		Hash: hash, ExpiresAt: time.Now().Add(s.Config.RefreshTokenTTL),
	})
	if err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{access, raw, "Bearer", int(s.Tokens.TTL().Seconds())}, nil
}

// POST /auth/register: membuat tenant baru + user pemilik (role admin).
// User berikutnya di tenant itu dibuat admin lewat POST /api/users.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		FullName   string `json:"full_name"`
		TenantName string `json:"tenant_name"`
		TenantSlug string `json:"tenant_slug"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = normalizeEmail(req.Email)
	req.TenantSlug = strings.ToLower(strings.TrimSpace(req.TenantSlug))
	switch {
	case !emailPattern.MatchString(req.Email):
		writeError(w, http.StatusBadRequest, "validation_error", "email tidak valid")
		return
	case strings.TrimSpace(req.FullName) == "" || strings.TrimSpace(req.TenantName) == "":
		writeError(w, http.StatusBadRequest, "validation_error", "full_name dan tenant_name wajib diisi")
		return
	case !slugPattern.MatchString(req.TenantSlug):
		writeError(w, http.StatusBadRequest, "validation_error", "tenant_slug hanya huruf kecil, angka, dan '-' (3-50 karakter)")
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

	user, tenant, err := s.Store.RegisterTenantOwner(r.Context(), strings.TrimSpace(req.TenantName),
		req.TenantSlug, req.Email, strings.TrimSpace(req.FullName), hash)
	switch {
	case errors.Is(err, store.ErrEmailTaken), errors.Is(err, store.ErrSlugTaken):
		writeError(w, http.StatusConflict, "conflict", err.Error())
		return
	case err != nil:
		internalError(w, err)
		return
	}

	s.logAudit(r, audit.ActionRegister, &user.ID, &tenant.ID, map[string]any{"tenant_slug": tenant.Slug})
	writeJSON(w, http.StatusCreated, map[string]any{"user": user, "tenant": tenant})
}

// POST /auth/login: email + password + tenant_slug -> access & refresh token.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		TenantSlug string `json:"tenant_slug"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = normalizeEmail(req.Email)
	ctx := r.Context()

	// Rate limit per (IP + email): membatasi brute force password satu akun
	// tanpa membuat penyerang bisa mengunci akun korban dari IP lain.
	limitKey := "login:" + requestInfoFrom(ctx).IP + ":" + req.Email
	allowed, err := s.LoginLimiter.Allow(ctx, limitKey)
	if err != nil {
		internalError(w, err)
		return
	}
	if !allowed {
		s.logAudit(r, audit.ActionLoginRateLimited, nil, nil, map[string]any{"email": req.Email})
		w.Header().Set("Retry-After", strconv.Itoa(int(s.LoginLimiter.Window().Seconds())))
		writeError(w, http.StatusTooManyRequests, "too_many_attempts", "terlalu banyak percobaan login, coba lagi nanti")
		return
	}

	// Semua kegagalan memberi pesan yang sama agar penyerang tidak bisa
	// membedakan "email tidak ada", "password salah", atau "bukan anggota tenant".
	fail := func(reason string, userID, tenantID *uuid.UUID) {
		s.logAudit(r, audit.ActionLoginFailed, userID, tenantID,
			map[string]any{"email": req.Email, "tenant_slug": req.TenantSlug, "reason": reason})
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "email, password, atau tenant salah")
	}

	user, err := s.Store.GetUserByEmail(ctx, req.Email)
	if errors.Is(err, store.ErrNotFound) {
		security.CheckPasswordDummy(req.Password) // samakan waktu respons
		fail("unknown_email", nil, nil)
		return
	} else if err != nil {
		internalError(w, err)
		return
	}
	if !security.CheckPassword(user.PasswordHash, req.Password) {
		fail("wrong_password", &user.ID, nil)
		return
	}
	if !user.IsActive {
		fail("inactive_user", &user.ID, nil)
		return
	}
	tenant, err := s.Store.GetTenantBySlug(ctx, req.TenantSlug)
	if errors.Is(err, store.ErrNotFound) {
		fail("unknown_tenant", &user.ID, nil)
		return
	} else if err != nil {
		internalError(w, err)
		return
	}
	member, err := s.Store.IsActiveMember(ctx, user.ID, tenant.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !member {
		fail("not_a_member", &user.ID, &tenant.ID)
		return
	}

	resp, err := s.issueTokens(r, user.ID, tenant.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	_ = s.LoginLimiter.Reset(ctx, limitKey)
	s.logAudit(r, audit.ActionLogin, &user.ID, &tenant.ID, nil)
	writeJSON(w, http.StatusOK, resp)
}

// POST /auth/refresh: rotasi refresh token. Token lama langsung tidak berlaku.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()

	newRaw, newHash, err := security.NewRefreshToken()
	if err != nil {
		internalError(w, err)
		return
	}
	old, err := s.Store.RotateRefreshToken(ctx, security.HashToken(req.RefreshToken), newHash,
		time.Now().Add(s.Config.RefreshTokenTTL))
	switch {
	case errors.Is(err, store.ErrTokenReused):
		s.logAudit(r, audit.ActionRefreshReuse, &old.UserID, &old.TenantID,
			map[string]any{"family_id": old.FamilyID})
		writeError(w, http.StatusUnauthorized, "token_reused", "refresh token sudah pernah dipakai; semua sesi terkait dicabut")
		return
	case errors.Is(err, store.ErrTokenInvalid):
		writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	case err != nil:
		internalError(w, err)
		return
	}

	// User bisa saja sudah dinonaktifkan/dikeluarkan sejak login.
	member, err := s.Store.IsActiveMember(ctx, old.UserID, old.TenantID)
	if err != nil {
		internalError(w, err)
		return
	}
	if !member {
		_ = s.Store.RevokeFamily(ctx, newHash, old.UserID)
		writeError(w, http.StatusUnauthorized, "invalid_token", "user tidak lagi aktif di tenant ini")
		return
	}

	access, _, err := s.Tokens.Issue(old.UserID, old.TenantID)
	if err != nil {
		internalError(w, err)
		return
	}
	s.logAudit(r, audit.ActionRefresh, &old.UserID, &old.TenantID, map[string]any{"family_id": old.FamilyID})
	writeJSON(w, http.StatusOK, tokenResponse{access, newRaw, "Bearer", int(s.Tokens.TTL().Seconds())})
}

// POST /auth/logout: access token saat ini masuk blacklist (sampai
// kedaluwarsa) dan refresh token (seluruh family-nya) dicabut.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &req) {
		return
	}
	if err := s.Blacklist.Revoke(r.Context(), p.TokenID, p.ExpiresAt); err != nil {
		internalError(w, err)
		return
	}
	if req.RefreshToken != "" {
		if err := s.Store.RevokeFamily(r.Context(), security.HashToken(req.RefreshToken), p.UserID); err != nil {
			internalError(w, err)
			return
		}
	}
	s.logAudit(r, audit.ActionLogout, &p.UserID, &p.TenantID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// GET /auth/me: profil user + tenant aktif + role + permission.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	ctx := r.Context()
	user, err := s.Store.GetUserByID(ctx, p.UserID)
	if err != nil {
		internalError(w, err)
		return
	}
	tenant, err := s.Store.GetTenantByID(ctx, p.TenantID)
	if err != nil {
		internalError(w, err)
		return
	}
	access, err := s.RBAC.Access(ctx, p.UserID, p.TenantID)
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":        user,
		"tenant":      tenant,
		"roles":       access.Roles,
		"permissions": access.Permissions,
	})
}
