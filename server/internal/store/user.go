package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
	PasswordHash string    `json:"-"`
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO app_user (username, password_hash, role) VALUES ($1,$2,$3) RETURNING id`,
		username, passwordHash, role).Scan(&id)
	return id, err
}

func (s *Store) UserByName(ctx context.Context, username string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role, disabled, created_at
		 FROM app_user WHERE username = $1`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Disabled, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM app_user`).Scan(&n)
	return n, err
}

func (s *Store) SetPassword(ctx context.Context, userID int64, hash string) error {
	ct, err := s.pool.Exec(ctx, `UPDATE app_user SET password_hash=$2 WHERE id=$1`, userID, hash)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Audit 记录一次敏感操作。绝不记录凭据本身，只记录谁在什么时候做了什么。
func (s *Store) Audit(ctx context.Context, actor, action, target string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	_, _ = s.pool.Exec(ctx,
		`INSERT INTO audit_log (actor, action, target, detail) VALUES ($1,$2,$3,$4)`,
		actor, action, target, detail)
}
