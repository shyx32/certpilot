package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/certpilot/server/internal/nginxsvc"
	"github.com/jackc/pgx/v5"
)

// SSHHost 是一台被纳管的服务器。
type SSHHost struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Host         string     `json:"host"`
	Port         int        `json:"port"`
	Username     string     `json:"username"`
	CredentialID int64      `json:"credential_id"`
	JumpHostID   *int64     `json:"jump_host_id,omitempty"`
	HostKeyFP    *string    `json:"host_key_fp,omitempty"`
	LastProbeAt  *time.Time `json:"last_probe_at,omitempty"`
	LastProbeOK  *bool      `json:"last_probe_ok,omitempty"`
	LastProbeErr *string    `json:"last_probe_err,omitempty"`
	ServiceCount int        `json:"service_count"`
	CreatedAt    time.Time  `json:"created_at"`
}

func (s *Store) CreateSSHHost(ctx context.Context, h *SSHHost) (int64, error) {
	if h.Port == 0 {
		h.Port = 22
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO ssh_host (name, host, port, username, credential_id, jump_host_id)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		h.Name, h.Host, h.Port, h.Username, h.CredentialID, h.JumpHostID).Scan(&id)
	return id, err
}

const sshHostCols = `h.id, h.name, h.host, h.port, h.username, h.credential_id, h.jump_host_id,
	h.host_key_fp, h.last_probe_at, h.last_probe_ok, h.last_probe_err, h.created_at,
	(SELECT count(*) FROM server_service s WHERE s.ssh_host_id = h.id)`

func scanSSHHost(row pgx.Row) (*SSHHost, error) {
	var h SSHHost
	err := row.Scan(&h.ID, &h.Name, &h.Host, &h.Port, &h.Username, &h.CredentialID,
		&h.JumpHostID, &h.HostKeyFP, &h.LastProbeAt, &h.LastProbeOK, &h.LastProbeErr,
		&h.CreatedAt, &h.ServiceCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &h, err
}

func (s *Store) ListSSHHosts(ctx context.Context) ([]*SSHHost, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+sshHostCols+` FROM ssh_host h ORDER BY h.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*SSHHost{}
	for rows.Next() {
		h, err := scanSSHHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) GetSSHHost(ctx context.Context, id int64) (*SSHHost, error) {
	return scanSSHHost(s.pool.QueryRow(ctx, `SELECT `+sshHostCols+` FROM ssh_host h WHERE h.id=$1`, id))
}

func (s *Store) DeleteSSHHost(ctx context.Context, id int64) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM ssh_host WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetHostKey 固化首次接入时看到的主机指纹。
//
// 之后每次连接都必须匹配，否则拒绝——这是防中间人的关键，
// 所以只在指纹为空时写入，不允许被后续连接悄悄改掉。
func (s *Store) SetHostKey(ctx context.Context, id int64, fp string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE ssh_host SET host_key_fp = $2 WHERE id = $1 AND host_key_fp IS NULL`, id, fp)
	return err
}

func (s *Store) MarkHostProbed(ctx context.Context, id int64, ok bool, errMsg string, detection any) error {
	var e *string
	if !ok && errMsg != "" {
		e = &errMsg
	}
	var blob []byte
	if detection != nil {
		blob, _ = json.Marshal(detection)
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE ssh_host SET last_probe_at=now(), last_probe_ok=$2, last_probe_err=$3,
		       last_detection = COALESCE($4::jsonb, last_detection)
		WHERE id=$1`, id, ok, e, blob)
	return err
}

// ServerService 是一台主机上的一个 nginx 实例。
type ServerService struct {
	ID             int64           `json:"id"`
	SSHHostID      int64           `json:"ssh_host_id"`
	HostName       string          `json:"host_name,omitempty"`
	Kind           string          `json:"kind"`
	ComposeProject *string         `json:"compose_project,omitempty"`
	ComposeService *string         `json:"compose_service,omitempty"`
	ContainerName  *string         `json:"container_name,omitempty"`
	ContainerImage *string         `json:"container_image,omitempty"`
	ContainerUser  *string         `json:"container_user,omitempty"`
	Mounts         json.RawMessage `json:"mounts"`
	WriteStrategy  string          `json:"write_strategy"`
	StrategyReason *string         `json:"strategy_reason,omitempty"`
	TestArgv       []string        `json:"test_argv"`
	ReloadArgv     []string        `json:"reload_argv"`
	// ReloadNeedsSudo 由探测判定：nginx 主进程是 root 而登录用户不是时为真。
	ReloadNeedsSudo bool            `json:"reload_needs_sudo"`
	UseSudo         bool            `json:"use_sudo"`
	IsCustom        bool            `json:"is_custom"`
	DiscoveredCerts json.RawMessage `json:"discovered_certs"`
	Notes           []string        `json:"notes"`
	Enabled         bool            `json:"enabled"`
	DetectedAt      *time.Time      `json:"detected_at,omitempty"`
}

// SaveDetectedServices 用一次探测的结果覆盖该主机的服务清单。
//
// 整体覆盖而非增量合并：容器被删掉后对应记录必须消失，
// 否则部署时会指向一个不存在的目标。用户自定义的服务用 is_custom 保护。
func (s *Store) SaveDetectedServices(ctx context.Context, hostID int64, services []nginxsvc.Service) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`DELETE FROM server_service WHERE ssh_host_id=$1 AND NOT is_custom`, hostID); err != nil {
		return err
	}

	for _, svc := range services {
		mounts, _ := json.Marshal(svc.Mounts)
		certs, _ := json.Marshal(svc.Certs)
		notes := svc.Notes
		if notes == nil {
			notes = []string{}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO server_service
				(ssh_host_id, kind, compose_project, compose_service, container_name,
				 container_image, container_user, mounts, write_strategy, strategy_reason,
				 test_argv, reload_argv, reload_needs_sudo, discovered_certs, notes, detected_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, now())`,
			hostID, string(svc.Kind), nullable(svc.ComposeProject), nullable(svc.ComposeService),
			nullable(svc.ContainerName), nullable(svc.Image), nullable(svc.ContainerUser),
			mounts, string(svc.WriteStrategy), nullable(svc.StrategyReason),
			toJSON(svc.TestArgv), toJSON(svc.ReloadArgv), svc.ReloadNeedsSudo,
			certs, notes); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func toJSON(v []string) []byte {
	b, _ := json.Marshal(v)
	return b
}

const serverServiceCols = `s.id, s.ssh_host_id, h.name, s.kind, s.compose_project, s.compose_service,
	s.container_name, s.container_image, s.container_user, s.mounts, s.write_strategy,
	s.strategy_reason, s.test_argv, s.reload_argv, s.reload_needs_sudo, s.use_sudo, s.is_custom,
	s.discovered_certs, s.notes, s.enabled, s.detected_at`

func scanServerService(row pgx.Row) (*ServerService, error) {
	var s ServerService
	var testArgv, reloadArgv []byte
	err := row.Scan(&s.ID, &s.SSHHostID, &s.HostName, &s.Kind, &s.ComposeProject, &s.ComposeService,
		&s.ContainerName, &s.ContainerImage, &s.ContainerUser, &s.Mounts, &s.WriteStrategy,
		&s.StrategyReason, &testArgv, &reloadArgv, &s.ReloadNeedsSudo, &s.UseSudo, &s.IsCustom,
		&s.DiscoveredCerts, &s.Notes, &s.Enabled, &s.DetectedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(testArgv, &s.TestArgv)
	_ = json.Unmarshal(reloadArgv, &s.ReloadArgv)
	return &s, nil
}

func (s *Store) ListServices(ctx context.Context, hostID int64) ([]*ServerService, error) {
	q := `SELECT ` + serverServiceCols + `
	      FROM server_service s JOIN ssh_host h ON h.id = s.ssh_host_id`
	args := []any{}
	if hostID > 0 {
		q += ` WHERE s.ssh_host_id = $1`
		args = append(args, hostID)
	}
	q += ` ORDER BY s.id`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ServerService{}
	for rows.Next() {
		svc, err := scanServerService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, svc)
	}
	return out, rows.Err()
}

func (s *Store) GetService(ctx context.Context, id int64) (*ServerService, error) {
	return scanServerService(s.pool.QueryRow(ctx, `SELECT `+serverServiceCols+`
		FROM server_service s JOIN ssh_host h ON h.id = s.ssh_host_id WHERE s.id=$1`, id))
}

// UpdateServiceCommands 保存管理员自定义的预检与重载命令。
func (s *Store) UpdateServiceCommands(ctx context.Context, id int64, test, reload []string, sudo bool) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE server_service
		SET test_argv=$2, reload_argv=$3, use_sudo=$4, is_custom=true
		WHERE id=$1`, id, toJSON(test), toJSON(reload), sudo)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ToService 把库中记录还原成探测模型，供部署使用。
func (r *ServerService) ToService() *nginxsvc.Service {
	svc := &nginxsvc.Service{
		Kind:            nginxsvc.Kind(r.Kind),
		ContainerName:   deref(r.ContainerName),
		ComposeProject:  deref(r.ComposeProject),
		ComposeService:  deref(r.ComposeService),
		Image:           deref(r.ContainerImage),
		ContainerUser:   deref(r.ContainerUser),
		TestArgv:        r.TestArgv,
		ReloadArgv:      r.ReloadArgv,
		ReloadNeedsSudo: r.ReloadNeedsSudo,
		WriteStrategy:   nginxsvc.WriteStrategy(r.WriteStrategy),
	}
	_ = json.Unmarshal(r.Mounts, &svc.Mounts)
	_ = json.Unmarshal(r.DiscoveredCerts, &svc.Certs)
	return svc
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
