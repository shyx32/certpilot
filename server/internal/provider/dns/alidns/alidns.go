// Package alidns 是阿里云 DNS 的 provider 实现。
package alidns

import (
	"context"
	"fmt"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	sdk "github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
	"github.com/certpilot/server/internal/aliyun"
	"github.com/certpilot/server/internal/dnsx"
	dnsprov "github.com/certpilot/server/internal/provider/dns"
)

func init() {
	dnsprov.Register("aliyun_ak", func(ctx context.Context, secret []byte) (dnsprov.Provider, error) {
		return New(secret)
	})
}

// Provider 实现 dns.Provider 与 dns.ZoneLister。
type Provider struct {
	client *sdk.Client
}

func New(secret []byte) (*Provider, error) {
	cred, err := aliyun.ParseCredential(secret)
	if err != nil {
		return nil, err
	}
	// DNS 是全局服务，地域参数不影响解析结果。
	c, err := sdk.NewClientWithAccessKey(cred.Region, cred.AccessKeyID, cred.AccessKeySecret)
	if err != nil {
		return nil, err
	}
	return &Provider{client: c}, nil
}

// Present 写入 TXT 记录。写入前先清理同名旧记录，
// 避免上一轮遗留的值让 CA 读到错误内容。
func (p *Provider) Present(ctx context.Context, m *dnsx.Match, value string) error {
	if err := p.CleanUp(ctx, m, ""); err != nil {
		return err
	}
	req := sdk.CreateAddDomainRecordRequest()
	req.DomainName = m.Zone.Name
	req.RR = m.RecordName
	req.Type = "TXT"
	req.Value = value
	req.TTL = requests.NewInteger(600)
	if err := aliyun.Prepare(ctx, req); err != nil {
		return err
	}

	if _, err := p.client.AddDomainRecord(req); err != nil {
		return fmt.Errorf("写入 TXT 记录 %s 失败：%s", m.FQDN, aliyun.Explain(err))
	}
	return nil
}

// CleanUp 删除该主机记录下的 TXT。
//
// value 为空时删除全部同名 TXT——验证失败路径也必须清理，
// 否则 DNS 里会堆积陈旧的 _acme-challenge 记录。
func (p *Provider) CleanUp(ctx context.Context, m *dnsx.Match, value string) error {
	req := sdk.CreateDescribeSubDomainRecordsRequest()
	req.DomainName = m.Zone.Name
	req.SubDomain = m.FQDN
	req.Type = "TXT"
	req.PageSize = requests.NewInteger(100)
	if err := aliyun.Prepare(ctx, req); err != nil {
		return err
	}

	resp, err := p.client.DescribeSubDomainRecords(req)
	if err != nil {
		// 记录本就不存在时阿里云也会报错，这不算清理失败。
		if isNotExist(err) {
			return nil
		}
		return fmt.Errorf("查询 TXT 记录 %s 失败：%s", m.FQDN, aliyun.Explain(err))
	}

	for _, r := range resp.DomainRecords.Record {
		if value != "" && r.Value != value {
			continue
		}
		del := sdk.CreateDeleteDomainRecordRequest()
		del.RecordId = r.RecordId
		if err := aliyun.Prepare(ctx, del); err != nil {
			return err
		}
		if _, err := p.client.DeleteDomainRecord(del); err != nil && !isNotExist(err) {
			return fmt.Errorf("删除 TXT 记录 %s 失败：%s", r.RecordId, aliyun.Explain(err))
		}
	}
	return nil
}

func isNotExist(err error) bool {
	s := err.Error()
	return strings.Contains(s, "DomainRecordNotBelongToUser") ||
		strings.Contains(s, "InvalidRR.NoneExist") ||
		strings.Contains(s, "RecordNotExist")
}

// ListZones 拉取该账号下全部托管域名。
// 这是「录入凭据即扫描」与域名自动匹配的数据来源。
func (p *Provider) ListZones(ctx context.Context) ([]dnsx.Zone, error) {
	out := []dnsx.Zone{}
	for page := 1; page <= 100; page++ {
		req := sdk.CreateDescribeDomainsRequest()
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(100)
		if err := aliyun.Prepare(ctx, req); err != nil {
			return nil, err
		}

		resp, err := p.client.DescribeDomains(req)
		if err != nil {
			return nil, fmt.Errorf("拉取域名列表失败：%s", aliyun.Explain(err))
		}
		for _, d := range resp.Domains.Domain {
			out = append(out, dnsx.Zone{Name: d.DomainName, ProviderZoneID: d.DomainId})
		}
		if len(resp.Domains.Domain) == 0 || int64(len(out)) >= resp.TotalCount {
			break
		}
	}
	return out, nil
}

// Check 用一次只读调用验证凭据是否有效。
func (p *Provider) Check(ctx context.Context) error {
	req := sdk.CreateDescribeDomainsRequest()
	req.PageSize = requests.NewInteger(1)
	if err := aliyun.Prepare(ctx, req); err != nil {
		return err
	}
	_, err := p.client.DescribeDomains(req)
	return err
}
