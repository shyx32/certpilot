package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type DeployTarget struct {
	ID              int64           `json:"id"`
	Name            string          `json:"name"`
	Kind            string          `json:"kind"`
	CredentialID    *int64          `json:"credential_id,omitempty"`
	ServerServiceID *int64          `json:"server_service_id,omitempty"`
	Params          json.RawMessage `json:"params"`
	Enabled         bool            `json:"enabled"`
	CreatedAt       time.Time       `json:"created_at"`
}

func (s *Store) CreateDeployTarget(ctx context.Context, t *DeployTarget) (int64, error) {
	if t.Params == nil {
		t.Params = json.RawMessage(`{}`)
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO deploy_target (name, kind, credential_id, server_service_id, params, enabled)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		t.Name, t.Kind, t.CredentialID, t.ServerServiceID, t.Params, t.Enabled).Scan(&id)
	return id, err
}

const deployTargetCols = `id, name, kind, credential_id, server_service_id, params, enabled, created_at`

func scanDeployTarget(row pgx.Row) (*DeployTarget, error) {
	var t DeployTarget
	err := row.Scan(&t.ID, &t.Name, &t.Kind, &t.CredentialID, &t.ServerServiceID,
		&t.Params, &t.Enabled, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &t, err
}

func (s *Store) ListDeployTargets(ctx context.Context) ([]*DeployTarget, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+deployTargetCols+` FROM deploy_target ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DeployTarget{}
	for rows.Next() {
		t, err := scanDeployTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetDeployTarget(ctx context.Context, id int64) (*DeployTarget, error) {
	return scanDeployTarget(s.pool.QueryRow(ctx,
		`SELECT `+deployTargetCols+` FROM deploy_target WHERE id=$1`, id))
}

func (s *Store) DeleteDeployTarget(ctx context.Context, id int64) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM deploy_target WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Binding 是证书与部署目标的绑定关系及其最近一次结果。
type Binding struct {
	ID                 int64      `json:"id"`
	CertConfigID       int64      `json:"cert_config_id"`
	DeployTargetID     int64      `json:"deploy_target_id"`
	TargetName         string     `json:"target_name"`
	TargetKind         string     `json:"target_kind"`
	LastDeployedCertID *int64     `json:"last_deployed_cert_id,omitempty"`
	LastStatus         string     `json:"last_status"`
	LastError          *string    `json:"last_error,omitempty"`
	LastDeployedAt     *time.Time `json:"last_deployed_at,omitempty"`
}

func (s *Store) BindTarget(ctx context.Context, certConfigID, targetID int64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cert_binding (cert_config_id, deploy_target_id) VALUES ($1,$2)
		ON CONFLICT (cert_config_id, deploy_target_id) DO NOTHING`, certConfigID, targetID)
	return err
}

func (s *Store) UnbindTarget(ctx context.Context, certConfigID, targetID int64) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM cert_binding WHERE cert_config_id=$1 AND deploy_target_id=$2`,
		certConfigID, targetID)
	return err
}

// BindingsOf 返回某证书的全部绑定目标（含目标名称，供界面直接展示）。
func (s *Store) BindingsOf(ctx context.Context, certConfigID int64) ([]*Binding, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT b.id, b.cert_config_id, b.deploy_target_id, t.name, t.kind,
		       b.last_deployed_cert_id, b.last_status, b.last_error, b.last_deployed_at
		FROM cert_binding b
		JOIN deploy_target t ON t.id = b.deploy_target_id
		WHERE b.cert_config_id = $1 AND t.enabled
		ORDER BY b.id`, certConfigID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Binding{}
	for rows.Next() {
		var b Binding
		if err := rows.Scan(&b.ID, &b.CertConfigID, &b.DeployTargetID, &b.TargetName,
			&b.TargetKind, &b.LastDeployedCertID, &b.LastStatus, &b.LastError,
			&b.LastDeployedAt); err != nil {
			return nil, err
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

// MarkBinding 记录一次部署结果。
//
// status 取 deployed（已下发）或 verified（已确认线上生效）或 failed。
// 区分前两者是有意的：下发成功不等于生效。
func (s *Store) MarkBinding(ctx context.Context, certConfigID, targetID, certID int64, status, errMsg string) error {
	var e *string
	if errMsg != "" {
		e = &errMsg
	}
	var cid *int64
	if certID > 0 {
		cid = &certID
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE cert_binding
		SET last_deployed_cert_id = COALESCE($3, last_deployed_cert_id),
		    last_status = $4, last_error = $5, last_deployed_at = now()
		WHERE cert_config_id = $1 AND deploy_target_id = $2`,
		certConfigID, targetID, cid, status, e)
	return err
}
