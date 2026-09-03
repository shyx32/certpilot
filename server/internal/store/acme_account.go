package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/certpilot/server/internal/secretbox"
	"github.com/jackc/pgx/v5"
)

type ACMEAccount struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	DirectoryURL string    `json:"directory_url"`
	Email        string    `json:"email"`
	KID          *string   `json:"kid,omitempty"`
	IsStaging    bool      `json:"is_staging"`
	CreatedAt    time.Time `json:"created_at"`
}

func acmeAccountAAD(id int64) []byte { return []byte(fmt.Sprintf("acme_account:%d", id)) }

// CreateACMEAccount 保存 CA 账号。私钥注册后无法再生成，丢失等于账号作废。
func (s *Store) CreateACMEAccount(ctx context.Context, a *ACMEAccount, privateKeyPEM []byte) (int64, error) {
	var id int64
	if err := s.pool.QueryRow(ctx, `SELECT nextval('acme_account_id_seq')`).Scan(&id); err != nil {
		return 0, err
	}
	sealed, err := s.box.Seal(privateKeyPEM, acmeAccountAAD(id))
	if err != nil {
		return 0, err
	}
	blob, err := json.Marshal(sealed)
	if err != nil {
		return 0, err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO acme_account (id, name, directory_url, email, private_key_enc, kid, is_staging)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, a.Name, a.DirectoryURL, a.Email, blob, a.KID, a.IsStaging)
	return id, err
}

// ACMEAccountKey 返回账号私钥明文。
func (s *Store) ACMEAccountKey(ctx context.Context, id int64) (*ACMEAccount, []byte, error) {
	var a ACMEAccount
	var blob []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, directory_url, email, private_key_enc, kid, is_staging, created_at
		FROM acme_account WHERE id=$1`, id).
		Scan(&a.ID, &a.Name, &a.DirectoryURL, &a.Email, &blob, &a.KID, &a.IsStaging, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	var sealed secretbox.Sealed
	if err := json.Unmarshal(blob, &sealed); err != nil {
		return nil, nil, err
	}
	key, err := s.box.Open(&sealed, acmeAccountAAD(a.ID))
	return &a, key, err
}

// SetACMEAccountKID 在首次注册成功后记录 CA 返回的账号 URL。
func (s *Store) SetACMEAccountKID(ctx context.Context, id int64, kid string) error {
	_, err := s.pool.Exec(ctx, `UPDATE acme_account SET kid=$2 WHERE id=$1`, id, kid)
	return err
}

func (s *Store) ListACMEAccounts(ctx context.Context) ([]*ACMEAccount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, directory_url, email, kid, is_staging, created_at
		FROM acme_account ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ACMEAccount{}
	for rows.Next() {
		var a ACMEAccount
		if err := rows.Scan(&a.ID, &a.Name, &a.DirectoryURL, &a.Email,
			&a.KID, &a.IsStaging, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}
