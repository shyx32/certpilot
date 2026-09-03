package sshx

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Auth 是一台主机的认证方式。密钥优先于密码。
type Auth struct {
	// PrivateKeyPEM 是登录私钥。
	PrivateKeyPEM []byte
	// Passphrase 是私钥口令，可为空。
	Passphrase string
	// Password 仅在没有私钥时使用。
	Password string
}

// Target 描述一台待连接的主机。
type Target struct {
	Host string
	Port int
	User string
	Auth Auth
	// HostKeyFingerprint 是首次接入时固化的指纹（SHA256:... 形式）。
	//
	// 为空表示首次连接：此时接受对端公钥并把指纹返回给调用方入库，
	// 之后每次连接都必须匹配，否则拒绝——这是防中间人的关键。
	HostKeyFingerprint string
	// Jump 是跳板机，可以多级。
	Jump *Target
}

func (t *Target) addr() string {
	port := t.Port
	if port == 0 {
		port = 22
	}
	return fmt.Sprintf("%s:%d", t.Host, port)
}

// ErrHostKeyMismatch 表示对端公钥与固化的指纹不符。
var ErrHostKeyMismatch = errors.New("sshx: 主机密钥与首次接入时记录的不一致，可能存在中间人攻击")

// Client 是一条已建立的 SSH 连接。
type Client struct {
	conn *ssh.Client
	// 跳板链上的连接，关闭时需要一并释放。
	parents []*ssh.Client
	// SeenFingerprint 是本次连接实际看到的对端指纹。
	SeenFingerprint string
}

// Fingerprint 返回公钥的 SHA256 指纹，格式与 ssh-keygen -lf 一致。
func Fingerprint(key ssh.PublicKey) string {
	sum := ssh.FingerprintSHA256(key)
	return sum
}

func authMethods(a Auth) ([]ssh.AuthMethod, error) {
	var out []ssh.AuthMethod
	if len(a.PrivateKeyPEM) > 0 {
		var signer ssh.Signer
		var err error
		if a.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(a.PrivateKeyPEM, []byte(a.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(a.PrivateKeyPEM)
		}
		if err != nil {
			return nil, fmt.Errorf("私钥无法解析: %w", err)
		}
		out = append(out, ssh.PublicKeys(signer))
	}
	if a.Password != "" {
		out = append(out, ssh.Password(a.Password))
	}
	if len(out) == 0 {
		return nil, errors.New("sshx: 未提供任何认证方式")
	}
	return out, nil
}

// Dial 建立连接，必要时先连跳板机。
func Dial(ctx context.Context, t *Target) (*Client, error) {
	return dial(ctx, t, 0)
}

const maxJumpDepth = 5

func dial(ctx context.Context, t *Target, depth int) (*Client, error) {
	if depth > maxJumpDepth {
		return nil, errors.New("sshx: 跳板机层级过深")
	}

	methods, err := authMethods(t.Auth)
	if err != nil {
		return nil, err
	}

	var seen string
	cfg := &ssh.ClientConfig{
		User:    t.User,
		Auth:    methods,
		Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = Fingerprint(key)
			if t.HostKeyFingerprint == "" {
				// 首次接入：记录并放行，由调用方入库固化。
				return nil
			}
			if seen != t.HostKeyFingerprint {
				return fmt.Errorf("%w（期望 %s，实际 %s）",
					ErrHostKeyMismatch, t.HostKeyFingerprint, seen)
			}
			return nil
		},
	}

	// 无跳板：直连。
	if t.Jump == nil {
		conn, err := dialContext(ctx, t.addr(), cfg)
		if err != nil {
			return nil, err
		}
		return &Client{conn: conn, SeenFingerprint: seen}, nil
	}

	// 有跳板：先连跳板机，再从它拨到目标。
	jump, err := dial(ctx, t.Jump, depth+1)
	if err != nil {
		return nil, fmt.Errorf("连接跳板机 %s 失败: %w", t.Jump.addr(), err)
	}
	raw, err := jump.conn.DialContext(ctx, "tcp", t.addr())
	if err != nil {
		jump.Close()
		return nil, fmt.Errorf("经跳板机拨号到 %s 失败: %w", t.addr(), err)
	}
	c, chans, reqs, err := ssh.NewClientConn(raw, t.addr(), cfg)
	if err != nil {
		jump.Close()
		return nil, err
	}
	parents := append([]*ssh.Client{jump.conn}, jump.parents...)
	return &Client{conn: ssh.NewClient(c, chans, reqs), parents: parents, SeenFingerprint: seen}, nil
}

func dialContext(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: cfg.Timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func (c *Client) Close() error {
	err := c.conn.Close()
	for _, p := range c.parents {
		_ = p.Close()
	}
	return err
}

// Result 是一次命令执行的结果。
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Combined 返回合并后的输出，便于直接回显给用户。
func (r *Result) Combined() string {
	if r.Stderr == "" {
		return r.Stdout
	}
	if r.Stdout == "" {
		return r.Stderr
	}
	return r.Stdout + "\n" + r.Stderr
}

// Run 执行一条命令。argv 会被逐个转义，用户填的内容只能是参数。
//
// 返回的 error 只表示「没能执行」；命令本身返回非零退出码时
// error 为 nil，由调用方检查 ExitCode——因为很多探测命令
// 失败退出是正常结果（例如 which 找不到程序）。
func (c *Client) Run(ctx context.Context, argv []string) (*Result, error) {
	cmd, err := BuildCommand(argv)
	if err != nil {
		return nil, err
	}
	return c.RunRaw(ctx, cmd)
}

// RunRaw 执行一条已经拼好的命令行。
//
// 只用于系统内置的、文本固定的脚本（例如原子替换那段）；
// 绝不能把用户输入拼进来——那正是 Run 存在的原因。
func (c *Client) RunRaw(ctx context.Context, cmd string) (*Result, error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case <-ctx.Done():
		// 会话不会自己响应 context，主动关掉以释放连接。
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return nil, ctx.Err()
	case err := <-done:
		res := &Result{
			Stdout: strings.TrimRight(stdout.String(), "\n"),
			Stderr: strings.TrimRight(stderr.String(), "\n"),
		}
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		if err != nil {
			return nil, err
		}
		return res, nil
	}
}

// RunScript 把一段固定脚本经 stdin 交给 sh，参数作为位置参数传入。
//
// 原子替换要做备份、改名、改权限，绕不开 shell。安全边界在于：
// 脚本文本是代码里的常量，变量只通过 $1 $2 进入，全程不做字符串拼接，
// 因此用户填的内容永远只是参数，不会成为代码。
func (c *Client) RunScript(ctx context.Context, script string, args []string, sudo bool) (*Result, error) {
	argv := []string{"sh", "-s", "--"}
	if sudo {
		argv = WithSudo(argv)
	}
	argv = append(argv, args...)
	cmd, err := BuildCommand(argv)
	if err != nil {
		return nil, err
	}

	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	sess.Stdin = strings.NewReader(script)

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = sess.Close()
		return nil, ctx.Err()
	case err := <-done:
		res := &Result{
			Stdout: strings.TrimRight(stdout.String(), "\n"),
			Stderr: strings.TrimRight(stderr.String(), "\n"),
		}
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		if err != nil {
			return nil, err
		}
		return res, nil
	}
}

// PipeIn 把内容经 stdin 送给一条命令，用于向容器卷写文件。
func (c *Client) PipeIn(ctx context.Context, argv []string, content io.Reader) (*Result, error) {
	cmd, err := BuildCommand(argv)
	if err != nil {
		return nil, err
	}
	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	sess.Stdin = content

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = sess.Close()
		return nil, ctx.Err()
	case err := <-done:
		res := &Result{
			Stdout: strings.TrimRight(stdout.String(), "\n"),
			Stderr: strings.TrimRight(stderr.String(), "\n"),
		}
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		if err != nil {
			return nil, err
		}
		return res, nil
	}
}

// EncodeKey 是把二进制内容安全塞进命令行的辅助：base64 后由远端解码。
func EncodeKey(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
