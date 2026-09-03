// Package health 巡检线上证书：连上去看一眼，把结论和本地记录比对。
//
// 它回答的是签发系统自己回答不了的问题：线上跑的到底是哪一版证书。
package health

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Issue 是一条巡检发现，面向使用者描述问题与后果。
type Issue struct {
	Code string `json:"code"`
	Text string `json:"text"`
	// Severity 取 info / warn / danger。
	Severity string `json:"severity"`
}

const (
	SevInfo   = "info"
	SevWarn   = "warn"
	SevDanger = "danger"
)

// Analysis 是对一条 TLS 连接的完整判读。
type Analysis struct {
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	SANs        []string  `json:"sans"`
	ChainLen    int       `json:"chain_len"`
	ChainOK     bool      `json:"chain_ok"`
	NameMatch   bool      `json:"name_match"`
	TLSVersion  string    `json:"tls_version"`
	Issues      []Issue   `json:"issues"`
}

// Analyze 判读一条链。domain 是访问时用的名字，chain[0] 是叶证书。
//
// expectedFP 非空时额外比对指纹——「签了但没生效」只有这一项能发现。
func Analyze(domain string, chain []*x509.Certificate, tlsVersion uint16, expectedFP string, now time.Time) *Analysis {
	if len(chain) == 0 {
		return &Analysis{Issues: []Issue{{
			Code: "no_certificate", Severity: SevDanger,
			Text: "对端没有返回任何证书。",
		}}}
	}

	leaf := chain[0]
	a := &Analysis{
		Fingerprint: FingerprintOf(leaf),
		Subject:     leaf.Subject.CommonName,
		Issuer:      leaf.Issuer.CommonName,
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		DaysLeft:    int(leaf.NotAfter.Sub(now).Hours() / 24),
		SANs:        leaf.DNSNames,
		ChainLen:    len(chain),
		TLSVersion:  tlsVersionName(tlsVersion),
	}

	// ---- 有效期 ----
	switch {
	case now.After(leaf.NotAfter):
		a.add("expired", SevDanger,
			fmt.Sprintf("证书已于 %s 过期。", leaf.NotAfter.Format(time.DateOnly)))
	case a.DaysLeft < 7:
		a.add("expiring_critical", SevDanger,
			fmt.Sprintf("证书还有 %d 天到期，需要立即处理。", a.DaysLeft))
	case a.DaysLeft <= 30:
		a.add("expiring_soon", SevWarn,
			fmt.Sprintf("证书还有 %d 天到期。", a.DaysLeft))
	}
	if now.Before(leaf.NotBefore) {
		a.add("not_yet_valid", SevDanger,
			fmt.Sprintf("证书要到 %s 才生效，当前不被信任。", leaf.NotBefore.Format(time.DateOnly)))
	}

	// ---- 证书链 ----
	//
	// 只有叶证书时浏览器往往正常（它会自己补全），
	// 部分 App 与 Java 客户端却会直接失败——这是最容易漏检的一类故障。
	a.ChainOK = len(chain) > 1
	if !a.ChainOK && !isSelfSigned(leaf) {
		a.add("missing_intermediate", SevDanger,
			"服务端只发送了叶证书，没有中间证书。浏览器可能正常，但部分 App 与 Java 客户端会握手失败。")
	}

	// ---- 域名匹配 ----
	if domain != "" {
		a.NameMatch = leaf.VerifyHostname(domain) == nil
		if !a.NameMatch {
			a.add("name_mismatch", SevDanger,
				fmt.Sprintf("证书不包含 %s。已覆盖：%s", domain, strings.Join(certNames(leaf), ", ")))
		}
	} else {
		a.NameMatch = true
	}

	// ---- 指纹一致性 ----
	//
	// 这是巡检最核心的一项：续期成功但线上没换，只有它能发现。
	if expectedFP != "" && !strings.EqualFold(expectedFP, a.Fingerprint) {
		a.add("fingerprint_mismatch", SevDanger,
			"线上证书与本地最新一版不一致——续期可能已完成但没有生效。")
	}

	// ---- 协议 ----
	if tlsVersion != 0 && tlsVersion < 0x0303 { // < TLS 1.2
		a.add("weak_tls", SevWarn,
			fmt.Sprintf("协商到 %s，低于 TLS 1.2。", a.TLSVersion))
	}

	// 自签证书单独提示：多数情况下它意味着部署没生效或走错了后端。
	if isSelfSigned(leaf) {
		a.add("self_signed", SevWarn,
			"这是一张自签证书，公网客户端不会信任它。")
	}
	return a
}

func (a *Analysis) add(code, sev, text string) {
	a.Issues = append(a.Issues, Issue{Code: code, Severity: sev, Text: text})
}

// Worst 返回最高严重级别，空表示一切正常。
func (a *Analysis) Worst() string {
	worst := ""
	for _, i := range a.Issues {
		switch i.Severity {
		case SevDanger:
			return SevDanger
		case SevWarn:
			worst = SevWarn
		case SevInfo:
			if worst == "" {
				worst = SevInfo
			}
		}
	}
	return worst
}

// Healthy 报告这次巡检是否没有发现任何需要处理的问题。
func (a *Analysis) Healthy() bool {
	w := a.Worst()
	return w == "" || w == SevInfo
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.Subject.String() == c.Issuer.String()
}

// certNames 汇总证书覆盖的名字，用于把「不匹配」讲清楚。
func certNames(c *x509.Certificate) []string {
	if len(c.DNSNames) > 0 {
		return c.DNSNames
	}
	if c.Subject.CommonName != "" {
		return []string{c.Subject.CommonName}
	}
	return []string{"（无）"}
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	case 0:
		return ""
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// FingerprintOf 返回证书的 SHA-256 指纹（小写十六进制）。
func FingerprintOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
