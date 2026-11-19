// Package audit mencatat dan membaca audit trail (tabel auditable_events).
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Daftar action yang dicatat.
const (
	ActionRegister         = "auth.register"
	ActionLogin            = "auth.login"
	ActionLoginFailed      = "auth.login_failed"
	ActionLoginRateLimited = "auth.login_rate_limited"
	ActionRefresh          = "auth.refresh"
	ActionRefreshReuse     = "auth.refresh_reuse_detected"
	ActionLogout           = "auth.logout"
	ActionUserCreate       = "user.create"
	ActionRoleCreate       = "role.create"
	ActionPermissionChange = "permission.change"
	ActionAccessDenied     = "access.denied"
)

// Event adalah satu kejadian yang akan dicatat. UserID/TenantID boleh nil
// (mis. login gagal untuk email yang tidak terdaftar).
type Event struct {
	UserID    *uuid.UUID
	TenantID  *uuid.UUID
	Action    string
	IP        string
	UserAgent string
	Metadata  map[string]any
}

// Record adalah baris audit yang dibaca kembali.
type Record struct {
	ID        int64          `json:"id"`
	UserID    *uuid.UUID     `json:"user_id"`
	TenantID  *uuid.UUID     `json:"tenant_id"`
	Action    string         `json:"action"`
	IP        string         `json:"ip"`
	UserAgent string         `json:"user_agent"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt time.Time      `json:"created_at"`
}

// Filter untuk membaca log. TenantID wajib: log selalu dibatasi per tenant.
type Filter struct {
	TenantID uuid.UUID
	Action   string
	UserID   *uuid.UUID
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
}

type Logger struct {
	db *pgxpool.Pool
}

func NewLogger(db *pgxpool.Pool) *Logger {
	return &Logger{db: db}
}

// Log menulis event secara sinkron. Kegagalan menulis audit hanya di-log
// (tidak menggagalkan request) agar outage audit tidak mematikan login.
func (l *Logger) Log(ctx context.Context, e Event) {
	if l == nil { // Logger nil = audit dimatikan (dipakai di unit test tanpa DB)
		return
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		meta = []byte("{}")
	}
	_, err = l.db.Exec(ctx,
		`INSERT INTO auditable_events (user_id, tenant_id, action, ip, user_agent, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		e.UserID, e.TenantID, e.Action, e.IP, truncate(e.UserAgent, 512), meta)
	if err != nil {
		slog.Error("gagal menulis audit log", "action", e.Action, "err", err)
	}
}

// List membaca audit log sesuai filter, terbaru lebih dulu.
// Query disusun dari kondisi tetap + placeholder ($n), bukan dari input user,
// sehingga aman dari SQL injection.
func (l *Logger) List(ctx context.Context, f Filter) ([]Record, error) {
	conds := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, strings.Replace(cond, "?", "$"+strconv.Itoa(len(args)), 1))
	}
	if f.Action != "" {
		add("action = ?", f.Action)
	}
	if f.UserID != nil {
		add("user_id = ?", *f.UserID)
	}
	if f.From != nil {
		add("created_at >= ?", *f.From)
	}
	if f.To != nil {
		add("created_at < ?", *f.To)
	}
	args = append(args, f.Limit, f.Offset)

	sql := `SELECT id, user_id, tenant_id, action, ip, user_agent, metadata, created_at
	        FROM auditable_events WHERE ` + strings.Join(conds, " AND ") +
		` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(len(args)-1) +
		` OFFSET $` + strconv.Itoa(len(args))

	rows, err := l.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Record{}
	for rows.Next() {
		var r Record
		var userID, tenantID uuid.NullUUID
		if err := rows.Scan(&r.ID, &userID, &tenantID, &r.Action, &r.IP, &r.UserAgent, &r.Metadata, &r.CreatedAt); err != nil {
			return nil, err
		}
		if userID.Valid {
			r.UserID = &userID.UUID
		}
		if tenantID.Valid {
			r.TenantID = &tenantID.UUID
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
