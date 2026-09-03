// Package sshnginx 把证书下发到通过 SSH 管理的 nginx。
//
// 支持宿主机与容器两种形态、三种写入策略（直写 / sudo 直写 / 辅助容器），
// 流程统一为：落临时文件 → 预检 → 原子替换 → 重载 → 失败回滚。
package sshnginx

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/certpilot/server/internal/nginxsvc"
	"github.com/certpilot/server/internal/provider/deploy"
	"github.com/certpilot/server/internal/sshx"
)

func init() {
	deploy.Register("ssh_nginx", func(ctx context.Context, params, secret []byte) (deploy.Deployer, error) {
		return New(params, secret)
	})
}

// HostSpec 是连接目标所需的信息，由编排层从库中读出后注入。
type HostSpec struct {
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	User        string    `json:"user"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Jump        *HostSpec `json:"jump,omitempty"`
	// JumpSecret 是跳板机的凭据明文，同样由编排层注入。
	JumpSecret json.RawMessage `json:"jump_secret,omitempty"`
}

// Params 是该部署目标的配置。
type Params struct {
	// Host 与 Service 由编排层注入，不由用户填写。
	Host    HostSpec          `json:"host"`
	Service *nginxsvc.Service `json:"service"`

	// CertPath / KeyPath 是服务视角的证书路径。容器形态即容器内路径。
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
	// VerifyDomains 是部署后要拨测的域名；为空时跳过校验并在日志中说明。
	VerifyDomains []string `json:"verify_domains"`
	// VerifyPort 默认 443。
	VerifyPort int `json:"verify_port,omitempty"`
}

// sshSecret 是 SSH 凭据的明文结构。
type sshSecret struct {
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	Passphrase    string `json:"passphrase,omitempty"`
	Password      string `json:"password,omitempty"`
}

type Deployer struct {
	params Params
	auth   sshx.Auth
}

func New(paramsJSON, secret []byte) (*Deployer, error) {
	var p Params
	if err := json.Unmarshal(paramsJSON, &p); err != nil {
		return nil, fmt.Errorf("ssh_nginx: 配置无法解析: %w", err)
	}
	if p.Service == nil {
		return nil, errors.New("ssh_nginx: 缺少服务信息，请先对该主机执行一次探测")
	}
	if p.CertPath == "" || p.KeyPath == "" {
		return nil, errors.New("ssh_nginx: 必须指定证书与私钥的存放路径")
	}
	auth, err := parseAuth(secret)
	if err != nil {
		return nil, err
	}
	return &Deployer{params: p, auth: auth}, nil
}

func parseAuth(secret []byte) (sshx.Auth, error) {
	var s sshSecret
	if err := json.Unmarshal(secret, &s); err != nil {
		return sshx.Auth{}, fmt.Errorf("ssh_nginx: SSH 凭据无法解析: %w", err)
	}
	if s.PrivateKeyPEM == "" && s.Password == "" {
		return sshx.Auth{}, errors.New("ssh_nginx: SSH 凭据里既没有私钥也没有密码")
	}
	return sshx.Auth{
		PrivateKeyPEM: []byte(s.PrivateKeyPEM),
		Passphrase:    s.Passphrase,
		Password:      s.Password,
	}, nil
}

func (d *Deployer) target() *sshx.Target {
	t := &sshx.Target{
		Host: d.params.Host.Host, Port: d.params.Host.Port,
		User: d.params.Host.User, Auth: d.auth,
		HostKeyFingerprint: d.params.Host.Fingerprint,
	}
	if j := d.params.Host.Jump; j != nil {
		jt := &sshx.Target{
			Host: j.Host, Port: j.Port, User: j.User,
			HostKeyFingerprint: j.Fingerprint,
		}
		if len(d.params.Host.JumpSecret) > 0 {
			if a, err := parseAuth(d.params.Host.JumpSecret); err == nil {
				jt.Auth = a
			}
		}
		t.Jump = jt
	}
	return t
}

// Validate 只验证能否连上并跑通预检命令，不碰任何证书文件。
//
// 这就是界面上「试运行」按钮背后的动作：绝大多数配置错误
// 在这里就会暴露，而不是等到某天凌晨三点自动续期时。
func (d *Deployer) Validate(ctx context.Context) error {
	c, err := sshx.Dial(ctx, d.target())
	if err != nil {
		return fmt.Errorf("ssh_nginx: %w", err)
	}
	defer c.Close()

	svc := d.params.Service
	if len(svc.TestArgv) == 0 {
		return nil
	}
	res, err := c.Run(ctx, resolveArgv(svc, svc.TestArgv))
	if err != nil {
		return fmt.Errorf("ssh_nginx: 执行预检命令失败: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("ssh_nginx: 预检命令返回 %d：%s", res.ExitCode, res.Combined())
	}
	return nil
}

func (d *Deployer) Deploy(ctx context.Context, b *deploy.Bundle) error {
	c, err := sshx.Dial(ctx, d.target())
	if err != nil {
		return fmt.Errorf("ssh_nginx: %w", err)
	}
	defer c.Close()

	svc := d.params.Service
	// 容器 ID 每次都变，执行前按 compose 标签重新解析。
	if err := d.resolveContainer(ctx, c, svc); err != nil {
		return err
	}

	_, err = nginxsvc.Deploy(ctx, c, svc, &nginxsvc.Material{
		CertPath:     d.params.CertPath,
		KeyPath:      d.params.KeyPath,
		FullChainPEM: b.FullChainPEM(),
		KeyPEM:       b.KeyPEM,
	}, time.Now().UTC().Format("20060102150405"))
	if err != nil {
		return fmt.Errorf("ssh_nginx: %w", err)
	}
	return nil
}

// resolveContainer 把 compose 标签解析成当前容器 ID。
//
// 解析不到就报错而不是静默跳过——容器没起来这件事本身就需要人知道。
func (d *Deployer) resolveContainer(ctx context.Context, c *sshx.Client, svc *nginxsvc.Service) error {
	if svc.Kind != nginxsvc.KindDocker {
		return nil
	}
	loc := svc.Locator()
	if loc == nil {
		return errors.New("ssh_nginx: 容器服务缺少定位信息（compose 标签或容器名）")
	}
	res, err := c.Run(ctx, loc)
	if err != nil {
		return fmt.Errorf("ssh_nginx: 定位容器失败: %w", err)
	}
	id := strings.Fields(res.Stdout)
	if len(id) == 0 {
		return fmt.Errorf("ssh_nginx: 没有找到运行中的容器（%s），请确认它已启动",
			svc.DisplayName())
	}
	svc.ContainerID = id[0]
	// 命令模板里的容器占位符要用新 ID 重新展开。
	svc.TestArgv, svc.ReloadArgv = nginxsvc.BuildCommands(nginxsvc.KindDocker, svc.ContainerID)
	return nil
}

func resolveArgv(svc *nginxsvc.Service, argv []string) []string {
	return sshx.ExpandArgv(argv, map[string]string{
		"container": svc.ContainerID,
	})
}

// Verify 与每个域名握手，比对线上证书指纹。
//
// nginx reload 是即时的，但配置里可能有多个 server 块用了不同证书，
// 拨测才能确认改对了地方。
func (d *Deployer) Verify(ctx context.Context, b *deploy.Bundle) error {
	if len(d.params.VerifyDomains) == 0 {
		// 没有可拨测的域名时不能假装成功，但也不该卡住流程——
		// 例如内网服务没有公网解析。明确返回 nil 并由日志说明。
		return nil
	}
	port := d.params.VerifyPort
	if port == 0 {
		port = 443
	}

	var pending []string
	for _, domain := range d.params.VerifyDomains {
		fp, err := probeFingerprint(ctx, domain, port)
		if err != nil {
			pending = append(pending, fmt.Sprintf("%s: %v", domain, err))
			continue
		}
		if !strings.EqualFold(fp, b.Fingerprint) {
			pending = append(pending, fmt.Sprintf("%s: 线上指纹与新证书不一致", domain))
		}
	}
	if len(pending) > 0 {
		return fmt.Errorf("ssh_nginx: 尚未确认生效: %s", strings.Join(pending, "; "))
	}
	return nil
}

// RetryWindow：nginx reload 是即时的，窗口比 CDN 短得多。
func (d *Deployer) RetryWindow() deploy.RetryWindow { return deploy.DefaultWindow }

func probeFingerprint(ctx context.Context, host string, port int) (string, error) {
	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// 只取指纹，链是否可信由巡检单独检查。
		InsecureSkipVerify: true,
	}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("对端没有返回证书")
	}
	return deploy.Fingerprint(state.PeerCertificates[0]), nil
}
