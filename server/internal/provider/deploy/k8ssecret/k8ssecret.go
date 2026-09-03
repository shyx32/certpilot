// Package k8ssecret 把证书写进 Kubernetes 的 tls Secret。
//
// 直接调 API Server 的 REST 接口，不引入 client-go：
// 只需要 get/patch 一个 Secret，为此背上几十 MB 依赖不划算。
package k8ssecret

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	deploy.Register("k8s_secret", func(ctx context.Context, params, secret []byte) (deploy.Deployer, error) {
		return New(params, secret)
	})
}

// Params 是该目标的配置。
type Params struct {
	Namespace string `json:"namespace"`
	// SecretName 是要写入的 Secret 名字，类型固定为 kubernetes.io/tls。
	SecretName string `json:"secret_name"`
	// VerifyDomains 是部署后拨测的域名；为空则跳过。
	VerifyDomains []string `json:"verify_domains,omitempty"`
}

// Credential 是访问集群所需的凭据。
type Credential struct {
	// Server 是 API Server 地址，例如 https://10.0.0.1:6443
	Server string `json:"server"`
	// Token 是 ServiceAccount 令牌。推荐为它单独建一个只能读写
	// 指定命名空间下 Secret 的 Role，而不是给 cluster-admin。
	Token string `json:"token"`
	// CACert 是集群 CA 证书（PEM）。留空则跳过校验，仅建议在内网测试时使用。
	CACert string `json:"ca_cert,omitempty"`
	// InsecureSkipVerify 显式关闭校验，需要用户主动打开。
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

type Deployer struct {
	p      Params
	cred   Credential
	client *http.Client
}

func New(paramsJSON, secret []byte) (*Deployer, error) {
	var p Params
	if err := json.Unmarshal(paramsJSON, &p); err != nil {
		return nil, fmt.Errorf("k8s_secret: 配置无法解析: %w", err)
	}
	if p.Namespace == "" || p.SecretName == "" {
		return nil, errors.New("k8s_secret: 必须指定命名空间与 Secret 名称")
	}

	var c Credential
	if err := json.Unmarshal(secret, &c); err != nil {
		return nil, fmt.Errorf("k8s_secret: 凭据无法解析: %w", err)
	}
	if c.Server == "" || c.Token == "" {
		return nil, errors.New("k8s_secret: 缺少 API Server 地址或访问令牌")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case c.CACert != "":
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CACert)) {
			return nil, errors.New("k8s_secret: 集群 CA 证书不是合法 PEM")
		}
		tlsCfg.RootCAs = pool
	case c.InsecureSkipVerify:
		tlsCfg.InsecureSkipVerify = true
	default:
		return nil, errors.New(
			"k8s_secret: 请提供集群 CA 证书；确实要跳过校验时请显式打开 insecure_skip_verify")
	}

	return &Deployer{
		p: p, cred: c,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

func (d *Deployer) url() string {
	return fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s",
		strings.TrimSuffix(d.cred.Server, "/"), d.p.Namespace, d.p.SecretName)
}

func (d *Deployer) do(ctx context.Context, method, url string, body []byte, contentType string) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+d.cred.Token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("请求 API Server 失败：%w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, nil
}

// Validate 确认能连上集群并有权读取该 Secret。
func (d *Deployer) Validate(ctx context.Context) error {
	raw, code, err := d.do(ctx, http.MethodGet, d.url(), nil, "")
	if err != nil {
		return fmt.Errorf("k8s_secret: %w", err)
	}
	switch {
	case code == http.StatusOK || code == http.StatusNotFound:
		// 不存在也算通过：部署时会创建它。
		return nil
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return fmt.Errorf("k8s_secret: 令牌无权访问 %s/%s，请检查绑定的 Role",
			d.p.Namespace, d.p.SecretName)
	default:
		return fmt.Errorf("k8s_secret: API Server 返回 %d：%s", code, explain(raw))
	}
}

// secretBody 构造 kubernetes.io/tls 类型的 Secret。
func (d *Deployer) secretBody(b *deploy.Bundle) ([]byte, error) {
	return json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "kubernetes.io/tls",
		"metadata": map[string]any{
			"name":      d.p.SecretName,
			"namespace": d.p.Namespace,
			"annotations": map[string]string{
				"certpilot.io/fingerprint": b.Fingerprint,
				"certpilot.io/not-after":   b.NotAfter.Format(time.RFC3339),
			},
		},
		"data": map[string]string{
			// Ingress 读的是 fullchain：缺中间证书会让部分客户端握手失败。
			"tls.crt": base64.StdEncoding.EncodeToString(b.FullChainPEM()),
			"tls.key": base64.StdEncoding.EncodeToString(b.KeyPEM),
		},
	})
}

// Deploy 写入 Secret：存在则更新，不存在则创建。
func (d *Deployer) Deploy(ctx context.Context, b *deploy.Bundle) error {
	body, err := d.secretBody(b)
	if err != nil {
		return err
	}

	// 先尝试更新。用 PUT 而不是 PATCH：整体替换语义更明确，
	// 也避免旧的 tls.crt 残留。
	raw, code, err := d.do(ctx, http.MethodPut, d.url(), body, "application/json")
	if err != nil {
		return fmt.Errorf("k8s_secret: %w", err)
	}
	if code == http.StatusOK {
		return nil
	}
	if code != http.StatusNotFound {
		return fmt.Errorf("k8s_secret: 更新 Secret 失败（%d）：%s", code, explain(raw))
	}

	// 不存在则创建。
	createURL := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets",
		strings.TrimSuffix(d.cred.Server, "/"), d.p.Namespace)
	raw, code, err = d.do(ctx, http.MethodPost, createURL, body, "application/json")
	if err != nil {
		return fmt.Errorf("k8s_secret: %w", err)
	}
	if code != http.StatusCreated && code != http.StatusOK {
		return fmt.Errorf("k8s_secret: 创建 Secret 失败（%d）：%s", code, explain(raw))
	}
	return nil
}

// Verify 优先读回 Secret 比对指纹注解；配置了域名时再拨测。
//
// 读回注解能确认「写进去的确实是这一版」，而拨测能确认
// Ingress 是否真的加载了它——两者含义不同，都有价值。
func (d *Deployer) Verify(ctx context.Context, b *deploy.Bundle) error {
	raw, code, err := d.do(ctx, http.MethodGet, d.url(), nil, "")
	if err != nil {
		return fmt.Errorf("k8s_secret: %w", err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("k8s_secret: 读回 Secret 失败（%d）", code)
	}
	var got struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		return fmt.Errorf("k8s_secret: 无法解析 Secret：%w", err)
	}
	if fp := got.Metadata.Annotations["certpilot.io/fingerprint"]; !strings.EqualFold(fp, b.Fingerprint) {
		return errors.New("k8s_secret: Secret 里的指纹与新证书不一致")
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
		return fmt.Errorf("k8s_secret: Ingress 尚未加载新证书：%s", strings.Join(pending, "; "))
	}
	return nil
}

// explain 从 API Server 的错误响应里取出可读的原因。
func explain(raw []byte) string {
	var status struct {
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	if json.Unmarshal(raw, &status) == nil && status.Message != "" {
		return status.Message
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
