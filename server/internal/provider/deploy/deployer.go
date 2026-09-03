// Package deploy 定义证书下发目标的适配器接口。
package deploy

import (
	"context"
	"time"
)

// Bundle 是一次下发所需的全部材料。
type Bundle struct {
	Domains     []string
	CertPEM     []byte
	ChainPEM    []byte // 中间证书；缺失会让部分客户端握手失败
	KeyPEM      []byte
	Fingerprint string // sha256，部署后校验用
	NotAfter    time.Time
}

// FullChainPEM 返回 leaf ‖ intermediate，绝大多数目标都要这个形式。
func (b *Bundle) FullChainPEM() []byte {
	out := make([]byte, 0, len(b.CertPEM)+len(b.ChainPEM))
	out = append(out, b.CertPEM...)
	return append(out, b.ChainPEM...)
}

// Deployer 把证书送到一个具体目标。三个方法各自独立，编排层不关心厂商差异。
type Deployer interface {
	// Validate 在保存配置时检查参数与凭据，不产生副作用。
	Validate(ctx context.Context) error
	// Deploy 下发证书。必须幂等：同一份证书重复下发不应报错。
	Deploy(ctx context.Context, b *Bundle) error
	// Verify 确认线上确实换成了这张证书。
	//
	// 这是流水线能走到 verified 的唯一依据。CDN 有分钟级生效延迟，
	// 实现应当自带重试窗口，或由调用方按 RetryWindow 反复调用。
	Verify(ctx context.Context, b *Bundle) error
}

// RetryWindow 是目标的生效延迟特征，调用方据此安排 Verify 的重试节奏。
type RetryWindow struct {
	Initial time.Duration
	Max     time.Duration
}

// WindowHinter 是可选能力；未实现时使用默认窗口。
type WindowHinter interface {
	RetryWindow() RetryWindow
}

// DefaultWindow 适用于即时生效的目标（Nginx、K8s Secret）。
var DefaultWindow = RetryWindow{Initial: 5 * time.Second, Max: 1 * time.Minute}

// CDNWindow 适用于 CDN 这类分钟级生效的目标。
var CDNWindow = RetryWindow{Initial: 30 * time.Second, Max: 10 * time.Minute}

// Factory 按目标配置构造 Deployer。
type Factory func(ctx context.Context, params []byte, secret []byte) (Deployer, error)

var registry = map[string]Factory{}

// Register 注册一种目标类型，kind 与 deploy_target.kind 对应。
func Register(kind string, f Factory) { registry[kind] = f }

// Lookup 取出某类型的构造器。
func Lookup(kind string) (Factory, bool) { f, ok := registry[kind]; return f, ok }

// Kinds 列出已注册的目标类型。
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}
