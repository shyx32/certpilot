package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/certpilot/server/internal/secretbox"
	"github.com/jackc/pgx/v5"
)

// CertConfig 是一张证书的申请单。
type CertConfig struct {
	ID              int64           `json:"id"`
	Name            string          `json:"name"`
	Domains         []string        `json:"domains"`
	KeyType         string          `json:"key_type"`
	ChallengeType   string          `json:"challenge_type"`
	ChallengeRef    json.RawMessage `json:"challenge_ref"`
	ACMEAccountID   int64           `json:"acme_account_id"`
	RenewBeforeDays int             `json:"renew_before_days"`
	Enabled         bool            `json:"enabled"`
	FailStreak      int             `json:"fail_streak"`
	CooldownUntil   *time.Time      `json:"cooldown_until,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`

	// 以下来自最新一版证书，列表页直接用，避免前端二次请求。
	NotAfter    *time.Time `json:"not_after,omitempty"`
	Fingerprint *string    `json:"fingerprint,omitempty"`
	DaysLeft    *int       `json:"days_left,omitempty"`
}

// scheduleOffset 由名称哈希得到，把续期请求打散在一天之内，
// 避免所有域名在同一分钟一起冲击 CA。
func scheduleOffset(name string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return int(h.Sum32() % 86400)
}

func (s *Store) CreateCertConfig(ctx context.Context, c *CertConfig) (int64, error) {
	if c.ChallengeRef == nil {
		c.ChallengeRef = json.RawMessage(`{}`)
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO cert_config
			(name, domains, key_type, challenge_type, challenge_ref,
			 acme_account_id, renew_before_days, enabled, schedule_offset)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		c.Name, c.Domains, c.KeyType, c.ChallengeType, c.ChallengeRef,
		c.ACMEAccountID, c.RenewBeforeDays, c.Enabled, scheduleOffset(c.Name)).Scan(&id)
	return id, err
}

const certConfigCols = `cc.id, cc.name, cc.domains, cc.key_type, cc.challenge_type,
	cc.challenge_ref, cc.acme_account_id, cc.renew_before_days, cc.enabled,
	cc.fail_streak, cc.cooldown_until, cc.created_at, latest.not_after, latest.fingerprint`

// certConfigFrom 把最新一版证书 join 进来。
const certConfigFrom = `
	FROM cert_config cc
	LEFT JOIN LATERAL (
		SELECT not_after, fingerprint FROM certificate
		WHERE cert_config_id = cc.id ORDER BY not_after DESC LIMIT 1
	) latest ON true`

func scanCertConfig(row pgx.Row) (*CertConfig, error) {
	var c CertConfig
	err := row.Scan(&c.ID, &c.Name, &c.Domains, &c.KeyType, &c.ChallengeType,
		&c.ChallengeRef, &c.ACMEAccountID, &c.RenewBeforeDays, &c.Enabled,
		&c.FailStreak, &c.CooldownUntil, &c.CreatedAt, &c.NotAfter, &c.Fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if c.NotAfter != nil {
		d := int(time.Until(*c.NotAfter).Hours() / 24)
		c.DaysLeft = &d
	}
	return &c, nil
}

func (s *Store) ListCertConfigs(ctx context.Context) ([]*CertConfig, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+certConfigCols+certConfigFrom+
			` WHERE cc.deleted_at IS NULL ORDER BY latest.not_after ASC NULLS FIRST, cc.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CertConfig{}
	for rows.Next() {
		c, err := scanCertConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetCertConfig(ctx context.Context, id int64) (*CertConfig, error) {
	return scanCertConfig(s.pool.QueryRow(ctx,
		`SELECT `+certConfigCols+certConfigFrom+` WHERE cc.id=$1 AND cc.deleted_at IS NULL`, id))
}

func (s *Store) DeleteCertConfig(ctx context.Context, id int64) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE cert_config SET deleted_at=now() WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DueForRenewal 返回需要续期的配置。
//
// 三个条件缺一不可：启用、不在失败冷却期、且（没有证书或即将到期）。
// 冷却期的存在是为了不把 CA 的失败配额浪费在一个注定失败的配置上。
func (s *Store) DueForRenewal(ctx context.Context) ([]*CertConfig, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+certConfigCols+certConfigFrom+`
		WHERE cc.deleted_at IS NULL
		  AND cc.enabled
		  AND (cc.cooldown_until IS NULL OR cc.cooldown_until < now())
		  AND (latest.not_after IS NULL
		       OR latest.not_after - make_interval(days => cc.renew_before_days) < now())
		  AND NOT EXISTS (
		      SELECT 1 FROM job j
		      WHERE j.kind IN ('issue','renew') AND j.ref_id = cc.id
		        AND j.state IN ('queued','running'))
		ORDER BY latest.not_after ASC NULLS FIRST`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CertConfig{}
	for rows.Next() {
		c, err := scanCertConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RecordFailure 累加失败次数，连续失败达到阈值后进入冷却并转人工。
func (s *Store) RecordFailure(ctx context.Context, configID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE cert_config
		SET fail_streak = fail_streak + 1,
		    cooldown_until = CASE WHEN fail_streak + 1 >= 3
		                          THEN now() + interval '6 hours' ELSE cooldown_until END
		WHERE id = $1`, configID)
	return err
}

func (s *Store) ResetFailure(ctx context.Context, configID int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE cert_config SET fail_streak=0, cooldown_until=NULL WHERE id=$1`, configID)
	return err
}

// ---------- 证书版本 ----------

type Certificate struct {
	ID           int64     `json:"id"`
	CertConfigID int64     `json:"cert_config_id"`
	Serial       string    `json:"serial"`
	Fingerprint  string    `json:"fingerprint"`
	CertPEM      string    `json:"-"`
	ChainPEM     string    `json:"-"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Issuer       string    `json:"issuer"`
	CreatedAt    time.Time `json:"created_at"`
}

func certificateAAD(id int64) []byte { return []byte(fmt.Sprintf("certificate:%d", id)) }

// SaveCertificate 写入一个新的证书版本。私钥加密存放。
func (s *Store) SaveCertificate(ctx context.Context, c *Certificate, keyPEM []byte, orderURL string) (int64, error) {
	var id int64
	if err := s.pool.QueryRow(ctx, `SELECT nextval('certificate_id_seq')`).Scan(&id); err != nil {
		return 0, err
	}
	sealed, err := s.box.Seal(keyPEM, certificateAAD(id))
	if err != nil {
		return 0, err
	}
	blob, err := json.Marshal(sealed)
	if err != nil {
		return 0, err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO certificate
			(id, cert_config_id, serial, fingerprint, cert_pem, chain_pem, key_enc,
			 not_before, not_after, issuer, acme_order_url)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (cert_config_id, fingerprint) DO NOTHING`,
		id, c.CertConfigID, c.Serial, c.Fingerprint, c.CertPEM, c.ChainPEM, blob,
		c.NotBefore, c.NotAfter, c.Issuer, orderURL)
	return id, err
}

// LatestCertificate 返回某配置最新一版证书及其私钥明文。
func (s *Store) LatestCertificate(ctx context.Context, configID int64) (*Certificate, []byte, error) {
	var c Certificate
	var blob []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, cert_config_id, serial, fingerprint, cert_pem, chain_pem, key_enc,
		       not_before, not_after, issuer, created_at
		FROM certificate WHERE cert_config_id=$1 ORDER BY not_after DESC LIMIT 1`, configID).
		Scan(&c.ID, &c.CertConfigID, &c.Serial, &c.Fingerprint, &c.CertPEM, &c.ChainPEM,
			&blob, &c.NotBefore, &c.NotAfter, &c.Issuer, &c.CreatedAt)
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
	key, err := s.box.Open(&sealed, certificateAAD(c.ID))
	if err != nil {
		return nil, nil, err
	}
	return &c, key, nil
}

// ListCertificates 返回某配置的历史版本，用于回滚与追溯。
func (s *Store) ListCertificates(ctx context.Context, configID int64) ([]*Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, cert_config_id, serial, fingerprint, not_before, not_after, issuer, created_at
		FROM certificate WHERE cert_config_id=$1 ORDER BY not_after DESC`, configID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Certificate{}
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.CertConfigID, &c.Serial, &c.Fingerprint,
			&c.NotBefore, &c.NotAfter, &c.Issuer, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// PruneCertificates 按保留策略清理历史版本，防止数据库无限增长。
func (s *Store) PruneCertificates(ctx context.Context, configID int64, keep int) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM certificate WHERE cert_config_id = $1 AND id NOT IN (
			SELECT id FROM certificate WHERE cert_config_id = $1
			ORDER BY not_after DESC LIMIT $2)`, configID, keep)
	return err
}
