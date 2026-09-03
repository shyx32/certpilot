package health

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// Target 是一次巡检的目标。
type Target struct {
	Domain string
	Port   int
	// SNI 留空时用 Domain。CDN 场景下有时需要指定不同的 SNI。
	SNI string
	// ExpectedFingerprint 非空时比对，用于发现「续了但没生效」。
	ExpectedFingerprint string
}

func (t Target) addr() string {
	p := t.Port
	if p == 0 {
		p = 443
	}
	return net.JoinHostPort(t.Domain, fmt.Sprint(p))
}

func (t Target) sni() string {
	if t.SNI != "" {
		return t.SNI
	}
	return t.Domain
}

// Prober 执行 TLS 拨测。
type Prober struct {
	// Timeout 是单次连接的上限。
	Timeout time.Duration
	// CheckRevocation 打开后额外查询 OCSP。
	//
	// 默认关闭：OCSP 查询要访问 CA 的服务，慢且不稳定，
	// 而每日巡检的主要价值在到期与指纹这两项。
	CheckRevocation bool
}

func NewProber() *Prober {
	return &Prober{Timeout: 10 * time.Second}
}

// Probe 连接目标并判读证书。
//
// 刻意不做信任校验：我们要看的是「服务端实际发了什么」，
// 而不是「Go 的根证书库认不认」。链是否完整由 Analyze 单独判断，
// 这样自签或链不全的情况才能被观测到而不是直接连不上。
func (p *Prober) Probe(ctx context.Context, t Target) (*Analysis, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName:         t.sni(),
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10, // 允许协商到低版本，以便把它报出来
	}}
	conn, err := dialer.DialContext(ctx, "tcp", t.addr())
	if err != nil {
		return nil, fmt.Errorf("无法建立 TLS 连接：%w", err)
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	a := Analyze(t.sni(), state.PeerCertificates, state.Version, t.ExpectedFingerprint, time.Now())

	if p.CheckRevocation && len(state.PeerCertificates) > 1 {
		if revoked, err := checkOCSP(ctx, state.PeerCertificates[0], state.PeerCertificates[1]); err == nil && revoked {
			a.add("revoked", SevDanger,
				"证书已被 CA 吊销，需要立即重新签发。")
		}
	}
	return a, nil
}
