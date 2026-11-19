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
	Config config.Config
	Store  *store.Store
	Audit  *audit.Logger
	Tokens *security.TokenManager
	RBAC   *rbac.Service
	KV     kv.Store
}

// guard menyusun rantai middleware untuk endpoint terproteksi:
// authenticate (siapa?) -> requirePermission (boleh?) -> handler.
func (s *Server) guard(perm string, h http.HandlerFunc) http.Handler {
	return s.authenticate(s.requirePermission(perm, h))
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
	return s.withRequestInfo(mux)
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
