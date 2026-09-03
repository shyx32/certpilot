package health

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

// issue 建一张证书，caKey 非空时由该 CA 签发，否则自签。
func issue(t *testing.T, cn string, sans []string, notBefore, notAfter time.Time,
	ca *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              sans,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	parent, signKey := tpl, key
	if ca != nil {
		parent, signKey = ca, caKey
		tpl.Issuer = ca.Subject
	} else {
		tpl.IsCA = true
		tpl.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// chainOf 造一条 叶 + 中间 的链。
func chainOf(t *testing.T, cn string, sans []string, notAfter time.Time) []*x509.Certificate {
	t.Helper()
	ca, caKey := issue(t, "Test Intermediate CA", nil, now.Add(-365*24*time.Hour), now.Add(365*24*time.Hour), nil, nil)
	leaf, _ := issue(t, cn, sans, now.Add(-24*time.Hour), notAfter, ca, caKey)
	return []*x509.Certificate{leaf, ca}
}

func codes(a *Analysis) []string {
	out := make([]string, 0, len(a.Issues))
	for _, i := range a.Issues {
		out = append(out, i.Code)
	}
	return out
}

func has(a *Analysis, code string) bool {
	for _, i := range a.Issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

func TestAnalyzeHealthy(t *testing.T) {
	chain := chainOf(t, "example.com", []string{"example.com", "www.example.com"}, now.Add(60*24*time.Hour))
	a := Analyze("example.com", chain, 0x0304, "", now)

	if !a.Healthy() {
		t.Fatalf("正常证书不应有问题: %v", codes(a))
	}
	if a.DaysLeft != 60 {
		t.Errorf("剩余天数 = %d，期望 60", a.DaysLeft)
	}
	if !a.ChainOK || !a.NameMatch {
		t.Errorf("链或域名判定有误: chain=%v name=%v", a.ChainOK, a.NameMatch)
	}
	if a.TLSVersion != "TLS 1.3" {
		t.Errorf("协议版本 = %q", a.TLSVersion)
	}
}

func TestAnalyzeExpiry(t *testing.T) {
	cases := []struct {
		name     string
		after    time.Duration
		wantCode string
		wantSev  string
	}{
		{"充裕", 60 * 24 * time.Hour, "", ""},
		{"临期", 20 * 24 * time.Hour, "expiring_soon", SevWarn},
		{"紧急", 3 * 24 * time.Hour, "expiring_critical", SevDanger},
		{"已过期", -24 * time.Hour, "expired", SevDanger},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			chain := chainOf(t, "a.com", []string{"a.com"}, now.Add(c.after))
			a := Analyze("a.com", chain, 0x0304, "", now)
			if c.wantCode == "" {
				if !a.Healthy() {
					t.Fatalf("不应报警: %v", codes(a))
				}
				return
			}
			if !has(a, c.wantCode) {
				t.Fatalf("期望 %s，实得 %v", c.wantCode, codes(a))
			}
			if a.Worst() != c.wantSev {
				t.Errorf("严重级别 = %s，期望 %s", a.Worst(), c.wantSev)
			}
		})
	}
}

// 缺中间证书时浏览器往往正常，部分客户端却会失败，是最容易漏检的一类。
func TestAnalyzeMissingIntermediate(t *testing.T) {
	full := chainOf(t, "a.com", []string{"a.com"}, now.Add(60*24*time.Hour))
	a := Analyze("a.com", full[:1], 0x0304, "", now)
	if !has(a, "missing_intermediate") {
		t.Fatalf("未检出缺失中间证书: %v", codes(a))
	}
	if a.ChainOK {
		t.Error("ChainOK 应为 false")
	}
}

// 自签证书本身就只有一张，不该再重复报「缺中间证书」。
func TestAnalyzeSelfSignedNotReportedAsMissingChain(t *testing.T) {
	self, _ := issue(t, "self", []string{"self.local"}, now.Add(-time.Hour), now.Add(24*time.Hour), nil, nil)
	a := Analyze("self.local", []*x509.Certificate{self}, 0x0304, "", now)
	if has(a, "missing_intermediate") {
		t.Errorf("自签证书不应报缺中间证书: %v", codes(a))
	}
	if !has(a, "self_signed") {
		t.Errorf("应提示自签: %v", codes(a))
	}
}

func TestAnalyzeNameMismatch(t *testing.T) {
	chain := chainOf(t, "a.com", []string{"a.com"}, now.Add(60*24*time.Hour))
	a := Analyze("other.com", chain, 0x0304, "", now)
	if !has(a, "name_mismatch") {
		t.Fatalf("未检出域名不匹配: %v", codes(a))
	}
	// 提示里要说清楚证书实际覆盖了什么，否则用户无从下手
	for _, i := range a.Issues {
		if i.Code == "name_mismatch" && !strings.Contains(i.Text, "a.com") {
			t.Errorf("提示未说明证书实际覆盖的域名: %s", i.Text)
		}
	}
}

func TestAnalyzeWildcardMatches(t *testing.T) {
	chain := chainOf(t, "*.example.com", []string{"*.example.com"}, now.Add(60*24*time.Hour))
	if a := Analyze("api.example.com", chain, 0x0304, "", now); !a.NameMatch {
		t.Errorf("通配符应匹配子域: %v", codes(a))
	}
	// 通配符不覆盖裸域，这是 TLS 的规则
	if a := Analyze("example.com", chain, 0x0304, "", now); a.NameMatch {
		t.Error("通配符不应匹配裸域")
	}
}

// 这是巡检最核心的一项：续期成功但线上没换，只有它能发现。
func TestAnalyzeFingerprintMismatch(t *testing.T) {
	chain := chainOf(t, "a.com", []string{"a.com"}, now.Add(60*24*time.Hour))
	a := Analyze("a.com", chain, 0x0304, "deadbeef", now)
	if !has(a, "fingerprint_mismatch") {
		t.Fatalf("未检出指纹不一致: %v", codes(a))
	}
	if a.Worst() != SevDanger {
		t.Error("指纹不一致意味着线上跑的不是你以为的证书，应为 danger")
	}
	// 指纹一致时不应报警
	same := Analyze("a.com", chain, 0x0304, FingerprintOf(chain[0]), now)
	if has(same, "fingerprint_mismatch") {
		t.Error("指纹一致却报了不一致")
	}
	// 大小写不同不算不一致
	upper := Analyze("a.com", chain, 0x0304, strings.ToUpper(FingerprintOf(chain[0])), now)
	if has(upper, "fingerprint_mismatch") {
		t.Error("指纹比较应忽略大小写")
	}
}

func TestAnalyzeWeakTLS(t *testing.T) {
	chain := chainOf(t, "a.com", []string{"a.com"}, now.Add(60*24*time.Hour))
	if a := Analyze("a.com", chain, 0x0301, "", now); !has(a, "weak_tls") {
		t.Fatalf("TLS 1.0 应被标记: %v", codes(a))
	}
	if a := Analyze("a.com", chain, 0x0303, "", now); has(a, "weak_tls") {
		t.Error("TLS 1.2 不应被标记")
	}
}

func TestAnalyzeNoCertificate(t *testing.T) {
	a := Analyze("a.com", nil, 0, "", now)
	if a.Healthy() || !has(a, "no_certificate") {
		t.Fatalf("空链应报错: %v", codes(a))
	}
}

func TestAnalyzeNotYetValid(t *testing.T) {
	ca, caKey := issue(t, "CA", nil, now.Add(-time.Hour), now.Add(365*24*time.Hour), nil, nil)
	leaf, _ := issue(t, "a.com", []string{"a.com"}, now.Add(24*time.Hour), now.Add(60*24*time.Hour), ca, caKey)
	a := Analyze("a.com", []*x509.Certificate{leaf, ca}, 0x0304, "", now)
	if !has(a, "not_yet_valid") {
		t.Fatalf("未生效的证书应被标记: %v", codes(a))
	}
}

func TestWorstSeverity(t *testing.T) {
	a := &Analysis{Issues: []Issue{{Severity: SevInfo}, {Severity: SevWarn}}}
	if a.Worst() != SevWarn {
		t.Errorf("= %s", a.Worst())
	}
	a.Issues = append(a.Issues, Issue{Severity: SevDanger})
	if a.Worst() != SevDanger {
		t.Errorf("= %s", a.Worst())
	}
	if (&Analysis{}).Worst() != "" {
		t.Error("无问题时应返回空")
	}
}
