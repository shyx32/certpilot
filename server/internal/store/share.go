package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ShareLink 是一个只读看板的分享链接。
type ShareLink struct {
	ID         int64      `json:"id"`
	Token      string     `json:"token"`
	Name       string     `json:"name"`
	Enabled    bool       `json:"enabled"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedBy  *string    `json:"created_by,omitempty"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// CreateShareLink 生成一个不可猜测的分享 token。
func (s *Store) CreateShareLink(ctx context.Context, name, createdBy string, ttl time.Duration) (*ShareLink, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}

	var l ShareLink
	err := s.pool.QueryRow(ctx, `
		INSERT INTO share_link (token, name, expires_at, created_by)
		VALUES ($1,$2,$3,$4)
		RETURNING id, token, name, enabled, expires_at, created_by, last_seen_at, created_at`,
		token, name, expires, createdBy).
		Scan(&l.ID, &l.Token, &l.Name, &l.Enabled, &l.ExpiresAt,
			&l.CreatedBy, &l.LastSeenAt, &l.CreatedAt)
	return &l, err
}

func (s *Store) ListShareLinks(ctx context.Context) ([]*ShareLink, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, token, name, enabled, expires_at, created_by, last_seen_at, created_at
		FROM share_link ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ShareLink{}
	for rows.Next() {
		var l ShareLink
		if err := rows.Scan(&l.ID, &l.Token, &l.Name, &l.Enabled, &l.ExpiresAt,
			&l.CreatedBy, &l.LastSeenAt, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, rows.Err()
}

func (s *Store) DeleteShareLink(ctx context.Context, id int64) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM share_link WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ResolveShareToken 校验 token 并顺手记录访问时间。
//
// 过期或停用的链接一律当作不存在——不区分「不存在」与「已过期」，
// 避免把 token 是否曾经有效这个信息泄露出去。
func (s *Store) ResolveShareToken(ctx context.Context, token string) (*ShareLink, error) {
	if token == "" {
		return nil, ErrNotFound
	}
	var l ShareLink
	err := s.pool.QueryRow(ctx, `
		UPDATE share_link SET last_seen_at = now()
		WHERE token = $1 AND enabled
		  AND (expires_at IS NULL OR expires_at > now())
		RETURNING id, token, name, enabled, expires_at, created_by, last_seen_at, created_at`,
		token).Scan(&l.ID, &l.Token, &l.Name, &l.Enabled, &l.ExpiresAt,
		&l.CreatedBy, &l.LastSeenAt, &l.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &l, err
}

// PublicHealthRow 是只读看板上的一行。
//
// 刻意只有域名、状态与剩余天数：这个页面不需要登录，
// 因此不能暴露证书路径、颁发者细节、任务日志等内部信息。
type PublicHealthRow struct {
	Domain    string `json:"domain"`
	Severity  string `json:"severity"`
	DaysLeft  *int   `json:"days_left,omitempty"`
	Reachable bool   `json:"reachable"`
}

// PublicHealth 返回只读看板的数据。
func (s *Store) PublicHealth(ctx context.Context) ([]PublicHealthRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT domain, severity, days_left, probe_error IS NULL FROM (
			SELECT DISTINCT ON (domain, port) domain, severity, days_left, probe_error, checked_at
			FROM health_check ORDER BY domain, port, checked_at DESC
		) t
		ORDER BY
			CASE severity WHEN 'danger' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END,
			days_left NULLS FIRST, domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PublicHealthRow{}
	for rows.Next() {
		var r PublicHealthRow
		if err := rows.Scan(&r.Domain, &r.Severity, &r.DaysLeft, &r.Reachable); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
