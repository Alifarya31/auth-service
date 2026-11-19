package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrUnknownRole       = errors.New("ada role yang tidak ada di tenant ini")
	ErrUnknownPermission = errors.New("ada permission yang tidak dikenal")
)

type Role struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type TenantUser struct {
	User
	Roles []string `json:"roles"`
}

// CreateUserInTenant membuat user baru sebagai anggota tenant dengan role
// yang disebutkan. Role dicari HANYA di tenant tersebut, sehingga admin
// tenant A tidak bisa memberi role milik tenant B.
func (s *Store) CreateUserInTenant(ctx context.Context, tenantID uuid.UUID, email, fullName, passwordHash string, roleNames []string) (User, error) {
	u := User{ID: uuid.New(), Email: email, FullName: fullName, IsActive: true, PasswordHash: passwordHash}
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		roleIDs, err := roleIDsByName(ctx, tx, tenantID, roleNames)
		if err != nil {
			return err
		}
		if err := insertUser(ctx, tx, &u); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO user_tenants (user_id, tenant_id) VALUES ($1, $2)`, u.ID, tenantID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id, tenant_id) SELECT $1, unnest($2::uuid[]), $3`,
			u.ID, roleIDs, tenantID)
		return err
	})
	return u, err
}

func roleIDsByName(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, names []string) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM roles WHERE tenant_id = $1 AND name = ANY($2)`, tenantID, names)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	if len(ids) != len(names) { // names sudah unik (dedup di handler)
		return nil, ErrUnknownRole
	}
	return ids, nil
}

func (s *Store) CreateRole(ctx context.Context, tenantID uuid.UUID, name, description string) (Role, error) {
	r := Role{ID: uuid.New(), TenantID: tenantID, Name: name, Description: description}
	err := s.db.QueryRow(ctx,
		`INSERT INTO roles (id, tenant_id, name, description) VALUES ($1, $2, $3, $4) RETURNING created_at`,
		r.ID, r.TenantID, r.Name, r.Description).Scan(&r.CreatedAt)
	if _, ok := uniqueViolation(err); ok {
		return r, ErrRoleExists
	}
	return r, err
}

// AddRolePermissions menambahkan permission ke role milik tenant.
// Mengembalikan seluruh permission role setelah perubahan dan daftar user
// pemegang role tersebut (untuk invalidasi cache).
// Role milik tenant lain diperlakukan sebagai ErrNotFound (tidak bocor
// informasi bahwa role itu ada).
func (s *Store) AddRolePermissions(ctx context.Context, tenantID, roleID uuid.UUID, codes []string) (perms []string, affected []uuid.UUID, err error) {
	err = s.withTx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM roles WHERE id = $1 AND tenant_id = $2)`, roleID, tenantID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}

		rows, err := tx.Query(ctx, `SELECT id FROM permissions WHERE code = ANY($1)`, codes)
		if err != nil {
			return err
		}
		permIDs, err := pgx.CollectRows(rows, pgx.RowTo[int32])
		if err != nil {
			return err
		}
		if len(permIDs) != len(codes) {
			return ErrUnknownPermission
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO role_permissions (role_id, permission_id) SELECT $1, unnest($2::int[])
			 ON CONFLICT DO NOTHING`, roleID, permIDs); err != nil {
			return err
		}

		rows, err = tx.Query(ctx,
			`SELECT p.code FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
			 WHERE rp.role_id = $1 ORDER BY p.code`, roleID)
		if err != nil {
			return err
		}
		if perms, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}

		rows, err = tx.Query(ctx, `SELECT user_id FROM user_roles WHERE role_id = $1`, roleID)
		if err != nil {
			return err
		}
		affected, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	return perms, affected, err
}

// IsMember: apakah user anggota tenant (aktif maupun tidak).
func (s *Store) IsMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM user_tenants WHERE user_id = $1 AND tenant_id = $2)`,
		userID, tenantID).Scan(&ok)
	return ok, err
}

// ListTenantUsers: semua anggota tenant beserta role-nya dalam satu query
// (role diagregasi dengan array_agg, bukan query per user).
func (s *Store) ListTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]TenantUser, error) {
	rows, err := s.db.Query(ctx, `
		SELECT u.id, u.email, u.full_name, u.is_active, u.created_at,
		       COALESCE(array_agg(r.name ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL), '{}')
		FROM user_tenants ut
		JOIN users u ON u.id = ut.user_id
		LEFT JOIN user_roles ur ON ur.user_id = ut.user_id AND ur.tenant_id = ut.tenant_id
		LEFT JOIN roles r ON r.id = ur.role_id
		WHERE ut.tenant_id = $1
		GROUP BY u.id
		ORDER BY u.created_at, u.email`, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (TenantUser, error) {
		var tu TenantUser
		err := row.Scan(&tu.ID, &tu.Email, &tu.FullName, &tu.IsActive, &tu.CreatedAt, &tu.Roles)
		return tu, err
	})
}
