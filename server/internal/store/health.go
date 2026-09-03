package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/certpilot/server/internal/health"
	"github.com/jackc/pgx/v5"
)

// MonitorDomain 是一个「仅监控不管理」的域名。
type MonitorDomain struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`
	Port      int       `json:"port"`
	SNI       *string   `json:"sni,omitempty"`
	Note      *string   `json:"note,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) CreateMonitorDomain(ctx context.Context, m *MonitorDomain) (int64, error) {
	if m.Port == 0 {
		m.Port = 443
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO monitor_domain (domain, port, sni, note) VALUES ($1,$2,$3,$4)
		ON CONFLICT (domain, port) DO UPDATE SET enabled = true, note = EXCLUDED.note
		RETURNING id`, m.Domain, m.Port, m.SNI, m.Note).Scan(&id)
	return id, err
}

func (s *Store) ListMonitorDomains(ctx context.Context) ([]*MonitorDomain, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, domain, port, sni, note, enabled, created_at
		FROM monitor_domain ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*MonitorDomain{}
	for rows.Next() {
		var m MonitorDomain
		if err := rows.Scan(&m.ID, &m.Domain, &m.Port, &m.SNI, &m.Note,
			&m.Enabled, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

func (s *Store) DeleteMonitorDomain(ctx context.Context, id int64) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM monitor_domain WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ProbeTarget 是一个待巡检的目标，来自证书配置或独立监控项。
type ProbeTarget struct {
	Domain       string
	Port         int
	SNI          string
	CertConfigID *int64
	// ExpectedFP 是本地最新一版的指纹，用于发现「续了但没生效」。
	ExpectedFP string
}

// ProbeTargets 汇总所有需要巡检的目标。
//
// 通配符域名本身不能解析，跳过；它们的具体子域如果需要监控，
// 由用户单独添加为监控项。
func (s *Store) ProbeTargets(ctx context.Context) ([]ProbeTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT d.domain, 443 AS port, NULL::text AS sni, cc.id, coalesce(latest.fingerprint, '')
		FROM cert_config cc
		CROSS JOIN LATERAL unnest(cc.domains) AS d(domain)
		LEFT JOIN LATERAL (
			SELECT fingerprint FROM certificate
			WHERE cert_config_id = cc.id ORDER BY not_after DESC LIMIT 1
		) latest ON true
		WHERE cc.deleted_at IS NULL AND cc.enabled AND d.domain NOT LIKE '*.%'

		UNION ALL

		SELECT m.domain, m.port, m.sni, NULL, ''
		FROM monitor_domain m WHERE m.enabled`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 去重键是「域名 + 端口」：同一个域名的不同端口是不同的目标。
	// 同一目标既在证书里又被单独监控时，保留带指纹的那条——
	// 没有指纹就没法发现「续了但没生效」。
	seen := map[string]int{}
	out := []ProbeTarget{}
	for rows.Next() {
		var t ProbeTarget
		var cfgID *int64
		var sni *string
		if err := rows.Scan(&t.Domain, &t.Port, &sni, &cfgID, &t.ExpectedFP); err != nil {
			return nil, err
		}
		t.CertConfigID = cfgID
		if sni != nil {
			t.SNI = *sni
		}
		key := fmt.Sprintf("%s:%d", t.Domain, t.Port)
		if i, ok := seen[key]; ok {
			if out[i].ExpectedFP == "" && t.ExpectedFP != "" {
				out[i] = t
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, t)
	}
	return out, rows.Err()
}

// HealthCheck 是一次巡检的结果记录。
type HealthCheck struct {
	ID           int64           `json:"id"`
	CertConfigID *int64          `json:"cert_config_id,omitempty"`
	Domain       string          `json:"domain"`
	Port         int             `json:"port"`
	ObservedFP   *string         `json:"observed_fp,omitempty"`
	Subject      *string         `json:"subject,omitempty"`
	Issuer       *string         `json:"issuer,omitempty"`
	NotAfter     *time.Time      `json:"not_after,omitempty"`
	DaysLeft     *int            `json:"days_left,omitempty"`
	ChainOK      *bool           `json:"chain_ok,omitempty"`
	ChainLen     *int            `json:"chain_len,omitempty"`
	NameMatch    *bool           `json:"name_match,omitempty"`
	FPMatch      *bool           `json:"fp_match,omitempty"`
	TLSVersion   *string         `json:"tls_version,omitempty"`
	Severity     string          `json:"severity"`
	Findings     json.RawMessage `json:"findings"`
	ProbeError   *string         `json:"probe_error,omitempty"`
	CheckedAt    time.Time       `json:"checked_at"`
}

// SaveHealthCheck 记录一次巡检结果。a 为 nil 表示连接失败。
func (s *Store) SaveHealthCheck(ctx context.Context, t ProbeTarget, a *health.Analysis, probeErr error) error {
	rec := HealthCheck{
		CertConfigID: t.CertConfigID,
		Domain:       t.Domain,
		Port:         t.Port,
		Findings:     json.RawMessage(`[]`),
	}
	if probeErr != nil {
		msg := probeErr.Error()
		rec.ProbeError = &msg
		// 连不上本身就是需要人处理的状态，不能记成「正常」。
		rec.Severity = health.SevDanger
		rec.Findings, _ = json.Marshal([]health.Issue{{
			Code: "unreachable", Severity: health.SevDanger, Text: msg,
		}})
	} else if a != nil {
		rec.ObservedFP = &a.Fingerprint
		rec.Subject = &a.Subject
		rec.Issuer = &a.Issuer
		na := a.NotAfter
		rec.NotAfter = &na
		dl := a.DaysLeft
		rec.DaysLeft = &dl
		co := a.ChainOK
		rec.ChainOK = &co
		cl := a.ChainLen
		rec.ChainLen = &cl
		nm := a.NameMatch
		rec.NameMatch = &nm
		tv := a.TLSVersion
		rec.TLSVersion = &tv
		rec.Severity = a.Worst()
		if t.ExpectedFP != "" {
			m := equalFold(t.ExpectedFP, a.Fingerprint)
			rec.FPMatch = &m
		}
		rec.Findings, _ = json.Marshal(a.Issues)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO health_check
			(cert_config_id, domain, port, sni, observed_fp, subject, issuer, not_after,
			 days_left, chain_ok, chain_len, name_match, fp_match, tls_version,
			 severity, findings, probe_error, issues)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'{}')`,
		rec.CertConfigID, rec.Domain, rec.Port, nullable(t.SNI), rec.ObservedFP,
		rec.Subject, rec.Issuer, rec.NotAfter, rec.DaysLeft, rec.ChainOK, rec.ChainLen,
		rec.NameMatch, rec.FPMatch, rec.TLSVersion, rec.Severity, rec.Findings, rec.ProbeError)
	return err
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

const healthCols = `id, cert_config_id, domain, port, observed_fp, subject, issuer, not_after,
	days_left, chain_ok, chain_len, name_match, fp_match, tls_version, severity,
	findings, probe_error, checked_at`

func scanHealth(row pgx.Row) (*HealthCheck, error) {
	var h HealthCheck
	err := row.Scan(&h.ID, &h.CertConfigID, &h.Domain, &h.Port, &h.ObservedFP,
		&h.Subject, &h.Issuer, &h.NotAfter, &h.DaysLeft, &h.ChainOK, &h.ChainLen,
		&h.NameMatch, &h.FPMatch, &h.TLSVersion, &h.Severity, &h.Findings,
		&h.ProbeError, &h.CheckedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &h, err
}

// LatestHealth 返回每个域名最近一次的巡检结果。
func (s *Store) LatestHealth(ctx context.Context) ([]*HealthCheck, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+healthCols+` FROM (
			SELECT DISTINCT ON (domain, port) * FROM health_check
			ORDER BY domain, port, checked_at DESC
		) h
		ORDER BY
			CASE severity WHEN 'danger' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END,
			days_left NULLS FIRST, domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*HealthCheck{}
	for rows.Next() {
		h, err := scanHealth(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// PruneHealthChecks 按保留天数清理历史巡检记录。
//
// 每天每个域名一条，1000 域名保留 90 天约 9 万行——
// 有保留策略才不会无限增长。
func (s *Store) PruneHealthChecks(ctx context.Context, keepDays int) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM health_check WHERE checked_at < now() - make_interval(days => $1)`, keepDays)
	return err
}

// MetricRow 是导出给 Prometheus 的一行数据。
type MetricRow struct {
	Name     string
	Domains  []string
	NotAfter *time.Time
	Enabled  bool
	Severity string
}

// MetricsSnapshot 汇总指标所需的数据，一次查询取全。
func (s *Store) MetricsSnapshot(ctx context.Context) (certs []MetricRow,
	jobs map[string]int, health map[string]int, err error) {

	rows, err := s.pool.Query(ctx, `
		SELECT cc.name, cc.domains, cc.enabled, latest.not_after
		FROM cert_config cc
		LEFT JOIN LATERAL (
			SELECT not_after FROM certificate
			WHERE cert_config_id = cc.id ORDER BY not_after DESC LIMIT 1
		) latest ON true
		WHERE cc.deleted_at IS NULL`)
	if err != nil {
		return nil, nil, nil, err
	}
	for rows.Next() {
		var m MetricRow
		if err := rows.Scan(&m.Name, &m.Domains, &m.Enabled, &m.NotAfter); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		certs = append(certs, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}

	jobs = map[string]int{}
	jrows, err := s.pool.Query(ctx, `SELECT state, count(*) FROM job GROUP BY state`)
	if err != nil {
		return nil, nil, nil, err
	}
	for jrows.Next() {
		var state string
		var n int
		if err := jrows.Scan(&state, &n); err != nil {
			jrows.Close()
			return nil, nil, nil, err
		}
		jobs[state] = n
	}
	jrows.Close()

	health = map[string]int{}
	hrows, err := s.pool.Query(ctx, `
		SELECT coalesce(nullif(severity,''), 'ok'), count(*) FROM (
			SELECT DISTINCT ON (domain, port) severity FROM health_check
			ORDER BY domain, port, checked_at DESC
		) t GROUP BY 1`)
	if err != nil {
		return nil, nil, nil, err
	}
	for hrows.Next() {
		var sev string
		var n int
		if err := hrows.Scan(&sev, &n); err != nil {
			hrows.Close()
			return nil, nil, nil, err
		}
		health[sev] = n
	}
	hrows.Close()
	return certs, jobs, health, nil
}
