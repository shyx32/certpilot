// Package dns 定义 DNS-01 验证所需的 provider 接口。
package dns

import (
	"context"

	"github.com/certpilot/server/internal/dnsx"
)

// Provider 是一家 DNS 服务商的适配器。
//
// Present/CleanUp/Timeout 与 lego 的 challenge.Provider 语义一致，
// 因此 lego 已有的几十个实现可以直接包装复用。
type Provider interface {
	// Present 写入 TXT 记录。
	Present(ctx context.Context, m *dnsx.Match, value string) error
	// CleanUp 删除该记录。无论验证成功与否都必须调用，
	// 否则 DNS 里会堆积陈旧的 _acme-challenge 记录。
	CleanUp(ctx context.Context, m *dnsx.Match, value string) error
}

// ZoneLister 是可选能力：列出该凭据下可管理的全部 zone。
//
// 实现了它的 provider 才能支持「录入凭据即扫描」与域名到账号的自动匹配；
// 未实现的退化为按 Public Suffix List 推算注册域，不影响签发。
type ZoneLister interface {
	ListZones(ctx context.Context) ([]dnsx.Zone, error)
}

// Verifier 是可选能力：直接向该域的权威 NS 查询，确认记录已传播。
//
// 必须查权威 NS 而不是本地 resolver——记录刚写完就通知 CA
// 是 DNS-01 最常见的失败原因。
type Verifier interface {
	VerifyPropagation(ctx context.Context, fqdn, value string) error
}

// Factory 按凭据构造 Provider。注册表在 init 中填充，新增厂商不改调用方。
type Factory func(ctx context.Context, secret []byte) (Provider, error)

var registry = map[string]Factory{}

// Register 注册一家厂商，kind 与 credential.kind 对应。
func Register(kind string, f Factory) { registry[kind] = f }

// Lookup 取出某厂商的构造器。
func Lookup(kind string) (Factory, bool) { f, ok := registry[kind]; return f, ok }

// Kinds 列出已注册的厂商，供界面渲染下拉框。
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}
