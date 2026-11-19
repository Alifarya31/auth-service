package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// RegisterTenantOwner membuat tenant baru beserta user pemiliknya dalam satu
// transaksi: tenant, user, keanggotaan, role "admin" (semua permission) dan
// role "member" (users:read), lalu user diberi role admin.
func (s *Store) RegisterTenantOwner(ctx context.Context, tenantName, slug, email, fullName, passwordHash string) (User, Tenant, error) {
	t := Tenant{ID: uuid.New(), Name: tenantName, Slug: slug}
	u := User{ID: uuid.New(), Email: email, FullName: fullName, IsActive: true, PasswordHash: passwordHash}
	adminRole, memberRole := uuid.New(), uuid.New()

	err := s.withTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) RETURNING created_at`,
			t.ID, t.Name, t.Slug).Scan(&t.CreatedAt); err != nil {
			if _, ok := uniqueViolation(err); ok {
				return ErrSlugTaken
			}
			return err
		}
		if err := insertUser(ctx, tx, &u); err != nil {
			return err
		}
		batch := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO user_tenants (user_id, tenant_id) VALUES ($1, $2)`, []any{u.ID, t.ID}},
			{`INSERT INTO roles (id, tenant_id, name, description) VALUES ($1, $2, $3, 'Akses penuh tenant'), ($4, $2, $5, 'Akses baca')`,
				[]any{adminRole, t.ID, RoleAdmin, memberRole, RoleMember}},
			{`INSERT INTO role_permissions (role_id, permission_id) SELECT $1, id FROM permissions`, []any{adminRole}},
			{`INSERT INTO role_permissions (role_id, permission_id) SELECT $1, id FROM permissions WHERE code = 'users:read'`, []any{memberRole}},
			{`INSERT INTO user_roles (user_id, role_id, tenant_id) VALUES ($1, $2, $3)`, []any{u.ID, adminRole, t.ID}},
		}
		for _, q := range batch {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	return u, t, err
}

func insertUser(ctx context.Context, tx pgx.Tx, u *User) error {
	err := tx.QueryRow(ctx,
		`INSERT INTO users (id, email, password_hash, full_name) VALUES ($1, $2, $3, $4) RETURNING created_at`,
		u.ID, u.Email, u.PasswordHash, u.FullName).Scan(&u.CreatedAt)
	if _, ok := uniqueViolation(err); ok {
		return ErrEmailTaken
	}
	return err
}

const userColumns = `id, email, full_name, is_active, created_at, password_hash`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.FullName, &u.IsActive, &u.CreatedAt, &u.PasswordHash)
	return u, notFound(err)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email))
}

func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

func (s *Store) GetTenantBySlug(ctx context.Context, slug string) (Tenant, error) {
	var t Tenant
	err := s.db.QueryRow(ctx, `SELECT id, name, slug, created_at FROM tenants WHERE slug = $1`, slug).
		Scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt)
	return t, notFound(err)
}

func (s *Store) GetTenantByID(ctx context.Context, id uuid.UUID) (Tenant, error) {
	var t Tenant
	err := s.db.QueryRow(ctx, `SELECT id, name, slug, created_at FROM tenants WHERE id = $1`, id).
		Scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt)
	return t, notFound(err)
}

// IsActiveMember memastikan user aktif dan masih anggota tenant.
func (s *Store) IsActiveMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM user_tenants ut JOIN users u ON u.id = ut.user_id
		   WHERE ut.user_id = $1 AND ut.tenant_id = $2 AND u.is_active)`,
		userID, tenantID).Scan(&ok)
	return ok, err
}
