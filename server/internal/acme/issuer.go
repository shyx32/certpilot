package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/certpilot/server/internal/dnsx"
	dnsprov "github.com/certpilot/server/internal/provider/dns"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// Account 是签发所需的 CA 账号信息。
type Account struct {
	ID           int64
	DirectoryURL string
	Email        string
	KID          string
	KeyPEM       []byte
}

// Request 是一次签发请求。
type Request struct {
	Domains []string
	KeyType string
	// ChallengeType 取 "dns-01" 或 "http-01"。
	ChallengeType string

	// ---- DNS-01 ----

	// Zones 是全部已托管的 DNS zone，用于把每个域名归属到对应账号。
	Zones []dnsx.Zone
	// ResolveProvider 按凭据 ID 构造 DNS provider。
	ResolveProvider func(credentialID int64) (dnsprov.Provider, error)
	// OnRecord 在每次写入 TXT 时回调，用于把进度推送到界面。
	OnRecord func(m *dnsx.Match, value string)

	// ---- HTTP-01 ----

	// HTTPChallenge 是集中验证的应答端。
	HTTPChallenge HTTPChallenge
	// OnToken 在每次登记 token 时回调。
	OnToken func(domain, token string)
}

// Result 是签发结果。
type Result struct {
	CertPEM    []byte
	ChainPEM   []byte
	KeyPEM     []byte
	OrderURL   string
	Leaf       *x509.Certificate
	AccountKID string
}

// Obtain 走完一次完整的 ACME 签发。
//
// 注意这里只负责「拿到证书」；部署与生效校验由流水线的后续阶段完成，
// 因为签发成功并不等于线上已经换证。
func Obtain(ctx context.Context, acct *Account, req *Request) (*Result, error) {
	key, err := ParseAccountKey(acct.KeyPEM)
	if err != nil {
		return nil, err
	}
	user := &User{Email: acct.Email, Key: key}
	if acct.KID != "" {
		// 已注册过：带上 URI 直接复用，避免重复注册。
		user.Registration = &registration.Resource{URI: acct.KID}
	}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = acct.DirectoryURL
	cfg.Certificate.KeyType = KeyType(req.KeyType)

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("构造 ACME 客户端失败：%s", Explain(err))
	}

	if acct.KID == "" {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, &Error{Action: "注册 CA 账号失败", Cause: err}
		}
		user.Registration = reg
	}

	if err := setupChallenge(ctx, client, req); err != nil {
		return nil, err
	}

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: req.Domains,
		// Bundle 让返回的 Certificate 里带上中间证书。
		// 缺中间证书时浏览器往往正常，部分 App 与 Java 客户端却会报错。
		Bundle: true,
	})
	if err != nil {
		// 包装成 Error 而不是丢掉原始错误：调用方要靠它判断能否重试。
		return nil, &Error{Action: "签发失败", Cause: err}
	}

	leafPEM, chainPEM, err := splitChain(res.Certificate)
	if err != nil {
		return nil, err
	}
	leaf, err := parseLeaf(leafPEM)
	if err != nil {
		return nil, err
	}

	kid := acct.KID
	if user.Registration != nil {
		kid = user.Registration.URI
	}
	return &Result{
		CertPEM:    leafPEM,
		ChainPEM:   chainPEM,
		KeyPEM:     res.PrivateKey,
		OrderURL:   res.CertStableURL,
		Leaf:       leaf,
		AccountKID: kid,
	}, nil
}

// setupChallenge 按配置装配验证方式。
func setupChallenge(ctx context.Context, client *lego.Client, req *Request) error {
	if req.ChallengeType == "http-01" {
		if req.HTTPChallenge == nil {
			return errors.New("acme: HTTP-01 需要提供验证应答端")
		}
		return client.Challenge.SetHTTP01Provider(&httpBridge{
			store:    req.HTTPChallenge,
			onRecord: req.OnToken,
		})
	}
	return client.Challenge.SetDNS01Provider(&dnsBridge{
		ctx:      ctx,
		zones:    req.Zones,
		resolve:  req.ResolveProvider,
		onRecord: req.OnRecord,
	})
}

// splitChain 把 fullchain 拆成叶证书与其余中间证书。
//
// 分开存放是为了让部署侧自行决定拼装方式：多数目标要 fullchain，
// 少数接口要求分别提供。
func splitChain(fullchain []byte) (leaf, chain []byte, err error) {
	rest := fullchain
	var blocks [][]byte
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		blocks = append(blocks, pem.EncodeToMemory(blk))
	}
	if len(blocks) == 0 {
		return nil, nil, errors.New("acme: 返回的证书链为空")
	}
	leaf = blocks[0]
	if len(blocks) > 1 {
		chain = []byte(strings.Join(toStrings(blocks[1:]), ""))
	}
	return leaf, chain, nil
}

func toStrings(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = string(b)
	}
	return out
}

func parseLeaf(leafPEM []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(leafPEM)
	if blk == nil {
		return nil, errors.New("acme: 叶证书不是合法 PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}
