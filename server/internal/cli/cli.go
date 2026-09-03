// Package cli 提供命令行客户端，供 CI 与脚本调用。
//
// 它走的是和界面完全相同的 HTTP 接口，不直接连数据库——
// 这样权限校验与审计日志对 CLI 同样生效。
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client 是 CLI 使用的 API 客户端。
type Client struct {
	BaseURL string
	http    *http.Client
	cookie  string
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

// Login 用用户名密码换取会话。
func (c *Client) Login(ctx context.Context, username, password string) error {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("连接 %s 失败：%w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("登录失败：用户名或密码不正确")
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == "cp_session" {
			c.cookie = ck.Value
			return nil
		}
	}
	return fmt.Errorf("登录成功但没有拿到会话")
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "cp_session", Value: c.cookie})
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%s", e.Error)
		}
		return nil, fmt.Errorf("请求失败（HTTP %d）", resp.StatusCode)
	}
	return raw, nil
}

// Run 分发 CLI 子命令。
func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	base := envOr("CP_URL", "http://localhost:8088")
	user := envOr("CP_USER", "admin")
	pass := os.Getenv("CP_PASSWORD")
	if pass == "" {
		return fmt.Errorf("请通过环境变量 CP_PASSWORD 提供密码")
	}

	c := New(base)
	if err := c.Login(ctx, user, pass); err != nil {
		return err
	}

	switch args[0] {
	case "list":
		return c.listCerts(ctx)
	case "issue":
		if len(args) < 2 {
			return fmt.Errorf("用法：certpilot cli issue <证书ID>")
		}
		return c.issue(ctx, args[1])
	case "status":
		return c.status(ctx)
	case "scan":
		return c.scan(ctx)
	default:
		printUsage()
		return fmt.Errorf("未知命令 %q", args[0])
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `certpilot cli — 通过 API 操作，适合在 CI 或脚本里调用

用法：
  certpilot cli list             列出全部证书及剩余天数
  certpilot cli status           输出巡检摘要；有严重问题时退出码为 1
  certpilot cli issue <证书ID>   触发一次签发或续期
  certpilot cli scan             触发一轮巡检

环境变量：
  CP_URL        服务地址，默认 http://localhost:8088
  CP_USER       用户名，默认 admin
  CP_PASSWORD   密码（必填）

status 的退出码可以直接用于流水线卡点：
  0 一切正常   1 存在严重问题
`)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (c *Client) listCerts(ctx context.Context) error {
	raw, err := c.do(ctx, http.MethodGet, "/api/v1/certificates", nil)
	if err != nil {
		return err
	}
	var certs []struct {
		ID       int64    `json:"id"`
		Name     string   `json:"name"`
		Domains  []string `json:"domains"`
		DaysLeft *int     `json:"days_left"`
	}
	if err := json.Unmarshal(raw, &certs); err != nil {
		return err
	}
	if len(certs) == 0 {
		fmt.Println("还没有证书。")
		return nil
	}
	fmt.Printf("%-5s %-24s %-10s %s\n", "ID", "名称", "剩余", "域名")
	for _, c := range certs {
		days := "未签发"
		if c.DaysLeft != nil {
			days = fmt.Sprintf("%d 天", *c.DaysLeft)
		}
		fmt.Printf("%-5d %-24s %-10s %s\n", c.ID, c.Name, days, strings.Join(c.Domains, ", "))
	}
	return nil
}

func (c *Client) issue(ctx context.Context, id string) error {
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/certificates/"+id+"/issue", nil)
	if err != nil {
		return err
	}
	var r struct {
		JobID int64 `json:"job_id"`
	}
	_ = json.Unmarshal(raw, &r)
	fmt.Printf("已提交，任务 #%d。用 certpilot cli status 或界面查看进度。\n", r.JobID)
	return nil
}

func (c *Client) scan(ctx context.Context) error {
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/health-checks/scan", nil)
	if err != nil {
		return err
	}
	var r struct {
		JobID int64 `json:"job_id"`
	}
	_ = json.Unmarshal(raw, &r)
	fmt.Printf("巡检已提交，任务 #%d。\n", r.JobID)
	return nil
}

// ErrUnhealthy 让 status 在有严重问题时以非零码退出，便于流水线卡点。
var ErrUnhealthy = fmt.Errorf("存在严重问题")

func (c *Client) status(ctx context.Context) error {
	raw, err := c.do(ctx, http.MethodGet, "/api/v1/health-checks", nil)
	if err != nil {
		return err
	}
	var rows []struct {
		Domain   string `json:"domain"`
		Severity string `json:"severity"`
		DaysLeft *int   `json:"days_left"`
		Findings []struct {
			Text string `json:"text"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("还没有巡检结果，先运行 certpilot cli scan。")
		return nil
	}

	var danger int
	for _, r := range rows {
		mark := "OK  "
		switch r.Severity {
		case "danger":
			mark = "危险"
			danger++
		case "warn":
			mark = "警告"
		}
		days := "—"
		if r.DaysLeft != nil {
			days = fmt.Sprintf("%d 天", *r.DaysLeft)
		}
		fmt.Printf("[%s] %-32s %s\n", mark, r.Domain, days)
		for _, f := range r.Findings {
			fmt.Printf("        %s\n", f.Text)
		}
	}
	if danger > 0 {
		return fmt.Errorf("%w：%d 个域名需要立即处理", ErrUnhealthy, danger)
	}
	return nil
}
