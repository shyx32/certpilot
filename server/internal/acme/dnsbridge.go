package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/certpilot/server/internal/dnsx"
	dnsprov "github.com/certpilot/server/internal/provider/dns"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

// dnsBridge 把我们的 dns.Provider 适配成 lego 的 challenge.Provider。
//
// 两者的差别在于 zone 归属：lego 只给出域名，由 provider 自行决定
// TXT 写在哪个 zone 上。这里用 zone 清单做最长后缀匹配，
// 因此同一张 SAN 证书里的域名可以分属不同账号。
type dnsBridge struct {
	ctx      context.Context
	zones    []dnsx.Zone
	resolve  func(credentialID int64) (dnsprov.Provider, error)
	onRecord func(m *dnsx.Match, value string)
}

func (b *dnsBridge) Present(domain, _, keyAuth string) error {
	m, p, value, err := b.prepare(domain, keyAuth)
	if err != nil {
		return err
	}
	if b.onRecord != nil {
		b.onRecord(m, value)
	}
	return p.Present(b.ctx, m, value)
}

func (b *dnsBridge) CleanUp(domain, _, keyAuth string) error {
	m, p, value, err := b.prepare(domain, keyAuth)
	if err != nil {
		return err
	}
	return p.CleanUp(b.ctx, m, value)
}

func (b *dnsBridge) prepare(domain, keyAuth string) (*dnsx.Match, dnsprov.Provider, string, error) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	m, err := dnsx.ResolveZone(domain, b.zones)
	if err != nil {
		return nil, nil, "", fmt.Errorf("域名 %s 无法归属到已托管的 zone: %w", domain, err)
	}
	p, err := b.resolve(m.Zone.CredentialID)
	if err != nil {
		return nil, nil, "", err
	}
	return m, p, info.Value, nil
}

// Timeout 放宽传播等待的窗口。
//
// lego 在通知 CA 之前会自行向该域的权威 NS 轮询确认记录已生效，
// 而不是查本地 resolver——记录刚写完就通知 CA 是 DNS-01 最常见的失败原因。
// 这里把窗口放宽到 5 分钟，覆盖阿里云 DNS 偶发的慢传播。
func (b *dnsBridge) Timeout() (time.Duration, time.Duration) {
	return 5 * time.Minute, 10 * time.Second
}
