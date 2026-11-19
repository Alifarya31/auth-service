// Package store berisi semua query SQL (pgx). Setiap query yang menyentuh
// data tenant selalu menerima tenantID sebagai parameter: isolasi tenant
// dijaga di layer data, bukan hanya di handler.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound   = errors.New("data tidak ditemukan")
	ErrEmailTaken = errors.New("email sudah terdaftar")
	ErrSlugTaken  = errors.New("slug tenant sudah dipakai")
	ErrRoleExists = errors.New("nama role sudah ada di tenant ini")
)

type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	FullName     string    `json:"full_name"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	PasswordHash string    `json:"-"`
}

type Tenant struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// uniqueViolation mengembalikan nama constraint jika err adalah pelanggaran UNIQUE.
func uniqueViolation(err error) (string, bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return pgErr.ConstraintName, true
	}
	return "", false
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// withTx menjalankan fn dalam transaksi; rollback otomatis jika fn gagal.
func (s *Store) withTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op setelah commit
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
