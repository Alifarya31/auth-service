package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/audit"
)

type ctxKey int

const (
	ctxRequestInfo ctxKey = iota
	ctxPrincipal
)

// requestInfo menyimpan IP dan user agent klien untuk audit dan rate limit.
type requestInfo struct {
	IP        string
	UserAgent string
}

// Principal adalah identitas pemanggil hasil verifikasi access token.
type Principal struct {
	UserID    uuid.UUID
	TenantID  uuid.UUID
	TokenID   string // jti, dipakai untuk blacklist saat logout
	ExpiresAt time.Time
}

func requestInfoFrom(ctx context.Context) requestInfo {
	info, _ := ctx.Value(ctxRequestInfo).(requestInfo)
	return info
}

func principalFrom(ctx context.Context) Principal {
	p, _ := ctx.Value(ctxPrincipal).(Principal)
	return p
}

func (s *Server) withRequestInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := requestInfo{IP: clientIP(r, s.Config.TrustProxy), UserAgent: r.UserAgent()}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestInfo, info)))
	})
}

// clientIP mengambil IP klien. X-Forwarded-For hanya dipercaya jika
// TRUST_PROXY=true; yang diambil adalah entri paling kanan (ditambahkan oleh
// proxy kita), karena entri paling kiri bisa dipalsukan oleh klien.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authenticate memverifikasi "Authorization: Bearer <jwt>" lalu menaruh
// Principal di context.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "access token wajib dikirim")
			return
		}
		claims, err := s.Tokens.Parse(raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token", "access token tidak valid atau kedaluwarsa")
			return
		}
		userID, _ := claims.UserID()
		p := Principal{
			UserID:    userID,
			TenantID:  claims.TenantID,
			TokenID:   claims.ID,
			ExpiresAt: claims.ExpiresAt.Time,
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxPrincipal, p)))
	})
}

// requirePermission memeriksa permission secara dinamis per endpoint.
// Permission dibaca dari RBAC service (cache -> database) untuk tenant di
// token, sehingga user tidak pernah bisa memakai permission dari tenant lain.
func (s *Server) requirePermission(perm string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principalFrom(r.Context())
		ok, err := s.RBAC.HasPermission(r.Context(), p.UserID, p.TenantID, perm)
		if err != nil {
			internalError(w, err)
			return
		}
		if !ok {
			s.logAudit(r, audit.ActionAccessDenied, &p.UserID, &p.TenantID,
				map[string]any{"permission": perm, "path": r.URL.Path, "method": r.Method})
			writeError(w, http.StatusForbidden, "forbidden", "tidak punya permission "+perm)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameTenant mencegah IDOR lintas tenant: ID tenant di URL harus sama
// dengan tenant di token.
func sameTenant(p Principal, tenantID uuid.UUID) bool {
	return p.TenantID == tenantID
}
