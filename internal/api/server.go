// Package api berisi HTTP handler, middleware, dan routing.
package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"auth-service/internal/audit"
	"auth-service/internal/config"
	"auth-service/internal/kv"
	"auth-service/internal/rbac"
	"auth-service/internal/security"
	"auth-service/internal/store"
)

type Server struct {
	Config       config.Config
	Store        *store.Store
	Audit        *audit.Logger
	Tokens       *security.TokenManager
	RBAC         *rbac.Service
	Blacklist    *security.Blacklist
	LoginLimiter *security.RateLimiter
	IPAllow      *security.IPAllowlist
}

// New merakit Server dari konfigurasi. cache dipakai bersama untuk cache
// permission, blacklist token, dan counter rate limit.
func New(cfg config.Config, st *store.Store, auditLog *audit.Logger, cache kv.Store) (*Server, error) {
	allow, err := security.ParseIPAllowlist(cfg.IPWhitelist)
	if err != nil {
		return nil, err
	}
	return &Server{
		Config:       cfg,
		Store:        st,
		Audit:        auditLog,
		Tokens:       security.NewTokenManager(cfg.JWTSecret, cfg.AccessTokenTTL),
		RBAC:         rbac.NewService(st, cache, cfg.PermissionCacheTTL),
		Blacklist:    security.NewBlacklist(cache),
		LoginLimiter: security.NewRateLimiter(cache, cfg.LoginMaxAttempts, cfg.LoginWindow),
		IPAllow:      allow,
	}, nil
}

// Handler menyusun semua route. Memakai router bawaan Go (net/http,
// pola "METHOD /path/{id}") sehingga tidak butuh dependency router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// 2.2 Auth flow
	mux.HandleFunc("POST /auth/register", s.handleRegister)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/refresh", s.handleRefresh)
	mux.Handle("POST /auth/logout", s.authenticate(http.HandlerFunc(s.handleLogout)))
	mux.Handle("GET /auth/me", s.authenticate(http.HandlerFunc(s.handleMe)))

	// Urutan luar -> dalam: catat IP klien, lalu cek IP whitelist.
	return s.withRequestInfo(s.ipWhitelist(mux))
}

// guard menyusun rantai middleware untuk endpoint terproteksi:
// authenticate (siapa?) -> requirePermission (boleh?) -> handler.
func (s *Server) guard(perm string, h http.HandlerFunc) http.Handler {
	return s.authenticate(s.requirePermission(perm, h))
}

// guardSensitive sama dengan guard, ditambah verifikasi 2FA.
func (s *Server) guardSensitive(perm string, h http.HandlerFunc) http.Handler {
	return s.authenticate(s.requirePermission(perm, s.require2FA(h)))
}

// logAudit mencatat event audit dengan IP dan user agent dari request.
// context.WithoutCancel: audit tetap ditulis walau client memutus koneksi.
func (s *Server) logAudit(r *http.Request, action string, userID, tenantID *uuid.UUID, meta map[string]any) {
	info := requestInfoFrom(r.Context())
	s.Audit.Log(context.WithoutCancel(r.Context()), audit.Event{
		UserID:    userID,
		TenantID:  tenantID,
		Action:    action,
		IP:        info.IP,
		UserAgent: info.UserAgent,
		Metadata:  meta,
	})
}
