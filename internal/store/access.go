package store

import (
	"context"

	"github.com/google/uuid"
)

// Access adalah role dan permission efektif seorang user di satu tenant.
type Access struct {
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// GetUserAccess mengambil role dan permission user di tenant tertentu dalam
// satu query (tanpa N+1). Join ke user_tenants + users memastikan user yang
// dinonaktifkan atau dikeluarkan dari tenant tidak punya akses apa pun.
func (s *Store) GetUserAccess(ctx context.Context, userID, tenantID uuid.UUID) (Access, error) {
	a := Access{Roles: []string{}, Permissions: []string{}}
	err := s.db.QueryRow(ctx, `
		SELECT
		  COALESCE(array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '{}'),
		  COALESCE(array_agg(DISTINCT p.code) FILTER (WHERE p.code IS NOT NULL), '{}')
		FROM user_roles ur
		JOIN user_tenants ut ON ut.user_id = ur.user_id AND ut.tenant_id = ur.tenant_id
		JOIN users u         ON u.id = ur.user_id AND u.is_active
		JOIN roles r         ON r.id = ur.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p       ON p.id = rp.permission_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2`,
		userID, tenantID).Scan(&a.Roles, &a.Permissions)
	return a, err
}
