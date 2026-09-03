// Package dnsx 处理域名与 DNS zone 的关系。
//
// 核心是把「用户输入的域名」映射到「哪个凭据能管它、TXT 记录该写在哪个 zone 的
// 哪条主机记录上」。这一步做对了，用户就不需要手工选择 DNS 账号。
package dnsx

import (
	"errors"
	"sort"
	"strings"
)

// ChallengePrefix 是 ACME DNS-01 固定的记录前缀。
const ChallengePrefix = "_acme-challenge"

var (
	ErrNoZone    = errors.New("dnsx: 没有找到能管理该域名的 DNS zone")
	ErrAmbiguous = errors.New("dnsx: 多个凭据都托管了同一个 zone，需要人工选择")
	ErrBadDomain = errors.New("dnsx: 域名不合法")
)

// Zone 是某个凭据下托管的一个 DNS zone。
type Zone struct {
	// Name 是 zone 名，例如 example.com。
	Name string
	// CredentialID 指向托管它的凭据。
	CredentialID int64
	// ProviderZoneID 是云厂商侧的 zone 标识，部分 provider 的写入接口需要它。
	ProviderZoneID string
}

// Match 是一次成功的域名归属判定结果。
type Match struct {
	// Domain 是去掉通配符前缀后的验证目标。
	Domain string
	// Zone 是命中的 zone。
	Zone Zone
	// RecordName 是要写入的主机记录，相对于 Zone.Name，例如 _acme-challenge.a。
	RecordName string
	// FQDN 是该 TXT 记录的完整域名，用于向权威 NS 轮询校验传播。
	FQDN string
}

// ResolveZone 为 domain 找出应当写入 TXT 记录的 zone 与主机记录。
//
// 采用最长后缀匹配：当 example.com 与 b.example.com 都被托管时，
// a.b.example.com 归属更精确的 b.example.com。
//
// 通配符域名 *.example.com 的验证目标是 example.com 本身——这是 ACME 的规定，
// 而不是一个可选实现。
func ResolveZone(domain string, zones []Zone) (*Match, error) {
	d, err := normalize(domain)
	if err != nil {
		return nil, err
	}

	var best []Zone
	var bestLen int
	for _, z := range zones {
		zn, err := normalize(z.Name)
		if err != nil || !covers(zn, d) {
			continue
		}
		switch {
		case len(zn) > bestLen:
			bestLen, best = len(zn), []Zone{z}
		case len(zn) == bestLen:
			best = append(best, z)
		}
	}

	switch len(best) {
	case 0:
		return nil, ErrNoZone
	case 1:
	default:
		// 同名 zone 出现在多个凭据下，交给用户裁决，不静默挑一个。
		if !sameCredential(best) {
			return nil, ErrAmbiguous
		}
	}

	z := best[0]
	zn, _ := normalize(z.Name)
	record := ChallengePrefix
	if d != zn {
		record += "." + strings.TrimSuffix(d[:len(d)-len(zn)-1], ".")
	}
	return &Match{
		Domain:     d,
		Zone:       z,
		RecordName: record,
		FQDN:       record + "." + zn,
	}, nil
}

// covers 判断 zone 是否是 domain 自身或其父域。
func covers(zone, domain string) bool {
	return domain == zone || strings.HasSuffix(domain, "."+zone)
}

func sameCredential(zs []Zone) bool {
	for _, z := range zs[1:] {
		if z.CredentialID != zs[0].CredentialID {
			return false
		}
	}
	return true
}

// normalize 统一大小写、去掉尾点与通配符前缀。
func normalize(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	if d == "" || strings.HasPrefix(d, ".") || strings.Contains(d, "..") || strings.Contains(d, "*") {
		return "", ErrBadDomain
	}
	if !strings.Contains(d, ".") {
		return "", ErrBadDomain
	}
	return d, nil
}

// ResolveAll 为一张证书的全部 SAN 域名各自定位 zone。
//
// 一张证书里的域名可以分属不同 zone、甚至不同云账号，因此逐个解析；
// 任何一个域名无法归属都直接返回错误——SAN 里缺一个都签不出来，
// 与其等 CA 拒绝，不如在预检阶段就说清楚是哪个域名的问题。
func ResolveAll(domains []string, zones []Zone) ([]*Match, error) {
	if len(domains) == 0 {
		return nil, ErrBadDomain
	}
	out := make([]*Match, 0, len(domains))
	seen := make(map[string]bool, len(domains))
	for _, d := range domains {
		m, err := ResolveZone(d, zones)
		if err != nil {
			return nil, &DomainError{Domain: d, Err: err}
		}
		if seen[m.FQDN] {
			// *.example.com 与 example.com 会落到同一条 TXT 上，去重即可。
			continue
		}
		seen[m.FQDN] = true
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FQDN < out[j].FQDN })
	return out, nil
}

// DomainError 指明是哪个域名出的问题，便于界面直接高亮那一行。
type DomainError struct {
	Domain string
	Err    error
}

func (e *DomainError) Error() string { return e.Domain + ": " + e.Err.Error() }
func (e *DomainError) Unwrap() error { return e.Err }
