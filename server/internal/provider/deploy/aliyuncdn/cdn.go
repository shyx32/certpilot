// Package aliyuncdn 把证书下发到阿里云 CDN。
//
// 采用两段式：先上传到数字证书管理服务（CAS）拿 CertId，
// 再把该 CertId 绑定到各个 CDN 域名。这样一张证书只需上传一次即可绑定
// 多个域名，控制台里也能看到清晰的证书清单，出问题可以直接切回上一个 CertId。
package aliyuncdn

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	cas "github.com/aliyun/alibaba-cloud-sdk-go/services/cas"
	cdn "github.com/aliyun/alibaba-cloud-sdk-go/services/cdn"
	"github.com/certpilot/server/internal/aliyun"
	"github.com/certpilot/server/internal/provider/deploy"
)

func init() {
	deploy.Register("aliyun_cdn", func(ctx context.Context, params, secret []byte) (deploy.Deployer, error) {
		return New(params, secret)
	})
}

// Params 是该目标的配置。
type Params struct {
	// Domains 是要绑定的 CDN 加速域名。
	Domains []string `json:"domains"`
	// Region 是 CAS 所在地域，默认 cn-hangzhou。
	Region string `json:"region,omitempty"`
}

type Deployer struct {
	params Params
	cred   *aliyun.Credential
	cas    *cas.Client
	cdn    *cdn.Client
}

func New(paramsJSON, secret []byte) (*Deployer, error) {
	var p Params
	if err := json.Unmarshal(paramsJSON, &p); err != nil {
		return nil, err
	}
	cred, err := aliyun.ParseCredential(secret)
	if err != nil {
		return nil, err
	}
	if p.Region == "" {
		p.Region = cred.Region
	}
	casCli, err := cas.NewClientWithAccessKey(p.Region, cred.AccessKeyID, cred.AccessKeySecret)
	if err != nil {
		return nil, err
	}
	cdnCli, err := cdn.NewClientWithAccessKey(p.Region, cred.AccessKeyID, cred.AccessKeySecret)
	if err != nil {
		return nil, err
	}
	return &Deployer{params: p, cred: cred, cas: casCli, cdn: cdnCli}, nil
}

func (d *Deployer) Validate(ctx context.Context) error {
	if len(d.params.Domains) == 0 {
		return errors.New("aliyun_cdn: 至少要配置一个 CDN 域名")
	}
	req := cdn.CreateDescribeUserDomainsRequest()
	req.PageSize = requests.NewInteger(1)
	if err := aliyun.Prepare(ctx, req); err != nil {
		return err
	}
	if _, err := d.cdn.DescribeUserDomains(req); err != nil {
		return fmt.Errorf("aliyun_cdn: 凭据校验失败：%s", aliyun.Explain(err))
	}
	return nil
}

// Deploy 上传证书到 CAS，再逐个绑定到 CDN 域名。
//
// 单个域名绑定失败不会中断其余域名——10 个域名里 1 个出错，
// 其余 9 个照常完成，失败的单独重试与告警。
func (d *Deployer) Deploy(ctx context.Context, b *deploy.Bundle) error {
	certID, err := d.upload(ctx, b)
	if err != nil {
		return err
	}

	var failed []string
	for _, domain := range d.params.Domains {
		if err := d.bind(ctx, domain, certID, b); err != nil {
			slog.Error("绑定 CDN 域名失败", "domain", domain, "err", err)
			failed = append(failed, fmt.Sprintf("%s: %v", domain, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("aliyun_cdn: %d/%d 个域名绑定失败: %s",
			len(failed), len(d.params.Domains), strings.Join(failed, "; "))
	}
	return nil
}

// upload 把证书传到 CAS。名称带指纹前缀，便于在控制台辨认与回滚。
func (d *Deployer) upload(ctx context.Context, b *deploy.Bundle) (int64, error) {
	req := cas.CreateUploadUserCertificateRequest()
	req.Name = certName(b)
	req.Cert = string(b.FullChainPEM())
	req.Key = string(b.KeyPEM)
	if err := aliyun.Prepare(ctx, req); err != nil {
		return 0, err
	}
	resp, err := d.cas.UploadUserCertificate(req)
	if err != nil {
		return 0, fmt.Errorf("aliyun_cdn: 上传证书到 CAS 失败：%s", aliyun.Explain(err))
	}
	return resp.CertId, nil
}

// certName 需要在账号内唯一且可读。指纹前 8 位足以区分不同版本。
func certName(b *deploy.Bundle) string {
	base := "certpilot"
	if len(b.Domains) > 0 {
		base = strings.NewReplacer("*", "wildcard", ".", "-").Replace(b.Domains[0])
	}
	fp := b.Fingerprint
	if len(fp) > 8 {
		fp = fp[:8]
	}
	name := fmt.Sprintf("%s-%s", base, fp)
	// CAS 证书名有长度上限，超长会被拒绝。
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func (d *Deployer) bind(ctx context.Context, domain string, certID int64, b *deploy.Bundle) error {
	req := cdn.CreateSetCdnDomainSSLCertificateRequest()
	req.DomainName = domain
	req.CertType = "cas"
	req.CertId = requests.NewInteger64(certID)
	req.CertRegion = d.params.Region
	req.CertName = certName(b)
	req.SSLProtocol = "on"
	if err := aliyun.Prepare(ctx, req); err != nil {
		return err
	}
	if _, err := d.cdn.SetCdnDomainSSLCertificate(req); err != nil {
		return errors.New(aliyun.Explain(err))
	}
	return nil
}

// Verify 直接与每个 CDN 域名握手，比对线上证书指纹。
//
// 这是流水线能走到 verified 的唯一依据：调用 API 返回成功只说明请求被接受，
// 不代表边缘节点已经换证。
func (d *Deployer) Verify(ctx context.Context, b *deploy.Bundle) error {
	var pending []string
	for _, domain := range d.params.Domains {
		fp, err := probeFingerprint(ctx, domain)
		if err != nil {
			pending = append(pending, fmt.Sprintf("%s: %v", domain, err))
			continue
		}
		if !strings.EqualFold(fp, b.Fingerprint) {
			pending = append(pending, fmt.Sprintf("%s: 线上指纹 %s 与新证书不一致", domain, short(fp)))
		}
	}
	if len(pending) > 0 {
		return fmt.Errorf("aliyun_cdn: 尚未全部生效: %s", strings.Join(pending, "; "))
	}
	return nil
}

// RetryWindow 告诉调用方 CDN 是分钟级生效，Verify 需要更长的重试窗口。
func (d *Deployer) RetryWindow() deploy.RetryWindow { return deploy.CDNWindow }

func short(fp string) string {
	if len(fp) > 8 {
		return fp[:8]
	}
	return fp
}

// probeFingerprint 与目标建立 TLS 连接并取出叶证书指纹。
func probeFingerprint(ctx context.Context, host string) (string, error) {
	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// 只取指纹，不做信任校验——链是否可信由巡检单独检查。
		InsecureSkipVerify: true,
	}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", host+":443")
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
