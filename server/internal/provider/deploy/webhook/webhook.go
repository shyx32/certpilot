// Package webhook 把证书 POST 到用户自己的端点。
//
// 它的存在让所有没有内置支持的场景都有出路：写个脚本接住证书就行，
// 不必等我们排期支持某家云。
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/certpilot/server/internal/provider/deploy"
)

func init() {
	deploy.Register("webhook", func(ctx context.Context, params, secret []byte) (deploy.Deployer, error) {
		return New(params, secret)
	})
}

// Params 是该目标的配置。
type Params struct {
	URL string `json:"url"`
	// Method 默认 POST。
	Method string `json:"method,omitempty"`
	// Headers 是附加请求头，可用于放 API token。
	Headers map[string]string `json:"headers,omitempty"`
	// IncludeKey 决定是否把私钥一并发出去。
	//
	// 默认为真——不发私钥的话对端多半没法用。但这意味着私钥会离开本系统，
	// 所以务必只指向可信端点，并使用 HTTPS。
	IncludeKey *bool `json:"include_key,omitempty"`
	// SigningSecret 非空时用 HMAC-SHA256 对请求体签名，
	// 放在 X-CertPilot-Signature 头里，供对端验证请求确实来自本系统。
	SigningSecret string `json:"signing_secret,omitempty"`
	// VerifyDomains 是部署后拨测的域名；为空则跳过校验。
	VerifyDomains []string `json:"verify_domains,omitempty"`
}

type Deployer struct {
	p Params
}

func New(paramsJSON, _ []byte) (*Deployer, error) {
	var p Params
	if err := json.Unmarshal(paramsJSON, &p); err != nil {
		return nil, fmt.Errorf("webhook: 配置无法解析: %w", err)
	}
	if p.URL == "" {
		return nil, errors.New("webhook: 必须指定接收端点")
	}
	if !strings.HasPrefix(p.URL, "http://") && !strings.HasPrefix(p.URL, "https://") {
		return nil, errors.New("webhook: 端点必须是 http 或 https 地址")
	}
	if p.Method == "" {
		p.Method = http.MethodPost
	}
	return &Deployer{p: p}, nil
}

func (d *Deployer) includeKey() bool {
	return d.p.IncludeKey == nil || *d.p.IncludeKey
}

// Validate 只检查端点可达，不发送任何证书内容。
func (d *Deployer) Validate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	body, _ := json.Marshal(map[string]any{
		"event": "ping",
		"note":  "CertPilot 连通性测试，本次不包含任何证书内容。",
	})
	resp, err := d.post(ctx, body)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	return resp
}

// payload 是发给对端的内容。字段名保持稳定，对端脚本依赖它们。
type payload struct {
	Event       string   `json:"event"`
	Domains     []string `json:"domains"`
	Fingerprint string   `json:"fingerprint"`
	NotAfter    string   `json:"not_after"`
	FullChain   string   `json:"fullchain_pem"`
	Cert        string   `json:"cert_pem"`
	Chain       string   `json:"chain_pem,omitempty"`
	Key         string   `json:"key_pem,omitempty"`
}

func (d *Deployer) Deploy(ctx context.Context, b *deploy.Bundle) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	pl := payload{
		Event:       "certificate",
		Domains:     b.Domains,
		Fingerprint: b.Fingerprint,
		NotAfter:    b.NotAfter.Format(time.RFC3339),
		FullChain:   string(b.FullChainPEM()),
		Cert:        string(b.CertPEM),
		Chain:       string(b.ChainPEM),
	}
	if d.includeKey() {
		pl.Key = string(b.KeyPEM)
	}

	body, err := json.Marshal(pl)
	if err != nil {
		return err
	}
	resp, err := d.post(ctx, body)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	return resp
}

// post 发送请求并把对端的响应正文带进错误里。
//
// 对端常常返回 200 但正文里写着失败原因；不带上它，用户只会看到
// 一个没有信息量的「部署失败」。
func (d *Deployer) post(ctx context.Context, body []byte) (error, error) {
	req, err := http.NewRequestWithContext(ctx, d.p.Method, d.p.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CertPilot")
	for k, v := range d.p.Headers {
		req.Header.Set(k, v)
	}
	if d.p.SigningSecret != "" {
		mac := hmac.New(sha256.New, []byte(d.p.SigningSecret))
		mac.Write(body)
		req.Header.Set("X-CertPilot-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败：%w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("对端返回 %d：%s", resp.StatusCode, truncate(string(respBody), 300)), nil
	}
	return nil, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Verify 拨测配置的域名。没有配置域名时跳过——
// 对端可能是内网服务或对象存储，没有可拨测的公网入口。
func (d *Deployer) Verify(ctx context.Context, b *deploy.Bundle) error {
	if len(d.p.VerifyDomains) == 0 {
		return nil
	}
	var pending []string
	for _, domain := range d.p.VerifyDomains {
		fp, err := deploy.ProbeFingerprint(ctx, domain, 443)
		if err != nil {
			pending = append(pending, fmt.Sprintf("%s: %v", domain, err))
			continue
		}
		if !strings.EqualFold(fp, b.Fingerprint) {
			pending = append(pending, fmt.Sprintf("%s: 线上指纹与新证书不一致", domain))
		}
	}
	if len(pending) > 0 {
		return fmt.Errorf("webhook: 尚未确认生效: %s", strings.Join(pending, "; "))
	}
	return nil
}
