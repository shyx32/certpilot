package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/certpilot/server/internal/dnsx"
	"github.com/certpilot/server/internal/secretbox"
	"github.com/jackc/pgx/v5"
)

var ErrNotFound = errors.New("store: 记录不存在")

// Credential 是一条凭据。Secret 永远不出现在 API 响应里。
type Credential struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	Kind          string     `json:"kind"`
	Origin        string     `json:"origin"`
	RAMUserName   *string    `json:"ram_user_name,omitempty"`
	RAMPolicyName *string    `json:"ram_policy_name,omitempty"`
	Region        *string    `json:"region,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	LastCheckOK   *bool      `json:"last_check_ok,omitempty"`
	LastCheckErr  *string    `json:"last_check_err,omitempty"`
	ZoneCount     int        `json:"zone_count"`
	CreatedAt     time.Time  `json:"created_at"`
}

// credentialAAD 把密文绑定到具体记录上，防止密文被搬到另一条记录复用。
func credentialAAD(id int64) []byte {
	return []byte(fmt.Sprintf("credential:%d", id))
}

// CreateCredential 加密并写入一条凭据。
func (s *Store) CreateCredential(ctx context.Context, c *Credential, secret []byte) (int64, error) {
	var id int64
	// 先取 id，才能用它作为加密的附加认证数据。
	if err := s.pool.QueryRow(ctx, `SELECT nextval('credential_id_seq')`).Scan(&id); err != nil {
		return 0, err
	}
	sealed, err := s.box.Seal(secret, credentialAAD(id))
	if err != nil {
		return 0, err
	}
	blob, err := json.Marshal(sealed)
	if err != nil {
		return 0, err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO credential (id, name, kind, secret_enc, origin, ram_user_name, ram_policy_name, region)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, c.Name, c.Kind, blob, c.Origin, c.RAMUserName, c.RAMPolicyName, c.Region)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// Secret 解密并返回凭据明文。调用方用完即弃，不要缓存。
func (s *Store) Secret(ctx context.Context, id int64) ([]byte, error) {
	var blob []byte
	err := s.pool.QueryRow(ctx,
		`SELECT secret_enc FROM credential WHERE id=$1 AND deleted_at IS NULL`, id).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var sealed secretbox.Sealed
	if err := json.Unmarshal(blob, &sealed); err != nil {
		return nil, err
	}
	return s.box.Open(&sealed, credentialAAD(id))
}

const credentialCols = `c.id, c.name, c.kind, c.origin, c.ram_user_name, c.ram_policy_name,
	c.region, c.last_checked_at, c.last_check_ok, c.last_check_err, c.created_at,
	(SELECT count(*) FROM credential_zone z WHERE z.credential_id = c.id)`

func scanCredential(row pgx.Row) (*Credential, error) {
	var c Credential
	err := row.Scan(&c.ID, &c.Name, &c.Kind, &c.Origin, &c.RAMUserName, &c.RAMPolicyName,
		&c.Region, &c.LastCheckedAt, &c.LastCheckOK, &c.LastCheckErr, &c.CreatedAt, &c.ZoneCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}

func (s *Store) ListCredentials(ctx context.Context) ([]*Credential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+credentialCols+` FROM credential c WHERE c.deleted_at IS NULL ORDER BY c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Credential{}
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetCredential(ctx context.Context, id int64) (*Credential, error) {
	return scanCredential(s.pool.QueryRow(ctx,
		`SELECT `+credentialCols+` FROM credential c WHERE c.id=$1 AND c.deleted_at IS NULL`, id))
}

func (s *Store) DeleteCredential(ctx context.Context, id int64) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE credential SET deleted_at=now() WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkCredentialChecked 记录一次健康检查结果。
// 每天刷新一次，AK 失效当天就能暴露，而不是等到续期时才发现。
func (s *Store) MarkCredentialChecked(ctx context.Context, id int64, ok bool, errMsg string) error {
	var e *string
	if !ok && errMsg != "" {
		e = &errMsg
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE credential SET last_checked_at=now(), last_check_ok=$2, last_check_err=$3 WHERE id=$1`,
		id, ok, e)
	return err
}

// ReplaceZones 用一次扫描的结果整体替换该凭据的 zone 清单。
// 整体替换而非增量合并：云端删掉的域名必须同步消失，否则自动匹配会指向不存在的 zone。
func (s *Store) ReplaceZones(ctx context.Context, credentialID int64, zones []dnsx.Zone) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM credential_zone WHERE credential_id=$1`, credentialID); err != nil {
		return err
	}
	for _, z := range zones {
		if _, err := tx.Exec(ctx, `
			INSERT INTO credential_zone (credential_id, zone, provider_zone_id)
			VALUES ($1,$2,$3) ON CONFLICT (credential_id, zone) DO NOTHING`,
			credentialID, z.Name, z.ProviderZoneID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// AllZones 返回全部凭据的 zone，供域名自动匹配使用。
func (s *Store) AllZones(ctx context.Context) ([]dnsx.Zone, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT z.zone, z.credential_id, coalesce(z.provider_zone_id,'')
		FROM credential_zone z
		JOIN credential c ON c.id = z.credential_id AND c.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []dnsx.Zone{}
	for rows.Next() {
		var z dnsx.Zone
		if err := rows.Scan(&z.Name, &z.CredentialID, &z.ProviderZoneID); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// ZonesOf 返回单个凭据的 zone 清单。
func (s *Store) ZonesOf(ctx context.Context, credentialID int64) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT zone FROM credential_zone WHERE credential_id=$1 ORDER BY zone`, credentialID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var z string
		if err := rows.Scan(&z); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}
