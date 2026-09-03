// Package store 封装数据访问。直接写 SQL，不引入 ORM——
// 这个系统的查询都很简单，ORM 带来的抽象成本大于收益。
package store

import (
	"context"

	"github.com/certpilot/server/internal/secretbox"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
	box  *secretbox.Box
}

func New(pool *pgxpool.Pool, box *secretbox.Box) *Store {
	return &Store{pool: pool, box: box}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }
