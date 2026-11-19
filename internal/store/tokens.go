package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrTokenInvalid = errors.New("refresh token tidak valid atau kedaluwarsa")
	// ErrTokenReused: token yang sudah pernah dirotasi dipakai lagi.
	// Ini indikasi token dicuri, sehingga seluruh family dicabut.
	ErrTokenReused = errors.New("refresh token sudah pernah dipakai")
)

type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TenantID  uuid.UUID
	FamilyID  uuid.UUID
	Hash      string
	ExpiresAt time.Time
}

func (s *Store) CreateRefreshToken(ctx context.Context, t RefreshToken) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO refresh_tokens (id, user_id, tenant_id, family_id, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.New(), t.UserID, t.TenantID, t.FamilyID, t.Hash, t.ExpiresAt)
	return err
}

// RotateRefreshToken menukar token lama dengan token baru secara atomik.
// SELECT ... FOR UPDATE mengunci baris token sehingga dua request refresh
// bersamaan dengan token yang sama tidak bisa sama-sama berhasil.
//
// Hasil:
//   - sukses: token lama dicabut, token baru (family sama) disimpan.
//   - token sudah dicabut sebelumnya: seluruh family dicabut, ErrTokenReused.
//   - tidak ada / kedaluwarsa: ErrTokenInvalid.
//
// Data token lama dikembalikan (juga saat ErrTokenReused) untuk audit.
func (s *Store) RotateRefreshToken(ctx context.Context, oldHash, newHash string, newExpiresAt time.Time) (RefreshToken, error) {
	var old RefreshToken
	var revokedAt *time.Time
	reused := false

	err := s.withTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT id, user_id, tenant_id, family_id, expires_at, revoked_at
			 FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, oldHash).
			Scan(&old.ID, &old.UserID, &old.TenantID, &old.FamilyID, &old.ExpiresAt, &revokedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return err
		}

		if revokedAt != nil {
			reused = true
			// Commit pencabutan family (bukan rollback), lalu laporkan reuse.
			_, err := tx.Exec(ctx,
				`UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`,
				old.FamilyID)
			return err
		}
		if time.Now().After(old.ExpiresAt) {
			return ErrTokenInvalid
		}

		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1`, old.ID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO refresh_tokens (id, user_id, tenant_id, family_id, token_hash, expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			uuid.New(), old.UserID, old.TenantID, old.FamilyID, newHash, newExpiresAt)
		return err
	})
	if err == nil && reused {
		err = ErrTokenReused
	}
	return old, err
}

// RevokeFamily mencabut semua refresh token dalam satu family (dipakai saat
// logout). Hanya token milik userID yang bisa dicabut.
func (s *Store) RevokeFamily(ctx context.Context, tokenHash string, userID uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now()
		 WHERE revoked_at IS NULL AND family_id = (
		   SELECT family_id FROM refresh_tokens WHERE token_hash = $1 AND user_id = $2)`,
		tokenHash, userID)
	return err
}
