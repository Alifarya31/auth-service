package api

import (
	"context"
	"crypto/subtle"
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
		// Token yang sudah di-logout ada di blacklist (berdasarkan jti).
		revoked, err := s.Blacklist.IsRevoked(r.Context(), claims.ID)
		if err != nil {
			internalError(w, err) // fail closed: jangan terima token jika status tidak bisa dicek
			return
		}
		if revoked {
			writeError(w, http.StatusUnauthorized, "token_revoked", "access token sudah dicabut")
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

// ipWhitelist menolak request dari IP di luar IP_WHITELIST. /healthz
// dikecualikan agar health check container tetap jalan.
func (s *Server) ipWhitelist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && !s.IPAllow.Allowed(requestInfoFrom(r.Context()).IP) {
			writeError(w, http.StatusForbidden, "ip_not_allowed", "IP tidak diizinkan")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// require2FA mensimulasikan 2FA untuk endpoint sensitif: header X-2FA-Code
// harus sama dengan TWO_FA_CODE. Di produksi ini diganti verifikasi TOTP
// per user. Perbandingan constant-time mencegah timing attack.
func (s *Server) require2FA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.Header.Get("X-2FA-Code")
		if code == "" || subtle.ConstantTimeCompare([]byte(code), []byte(s.Config.TwoFACode)) != 1 {
			p := principalFrom(r.Context())
			s.logAudit(r, audit.ActionAccessDenied, &p.UserID, &p.TenantID,
				map[string]any{"reason": "2fa_failed", "path": r.URL.Path, "method": r.Method})
			writeError(w, http.StatusForbidden, "2fa_required", "endpoint ini butuh header X-2FA-Code yang valid")
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
