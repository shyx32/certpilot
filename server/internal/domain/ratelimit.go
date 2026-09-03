package domain

import (
	"fmt"
	"strings"
)

// RateLimits 是对 CA 配额的本地约束。
//
// 默认值参照 Let's Encrypt 的公开限制，但刻意留出余量：
// 主动停下来告警，比撞上 CA 的墙、被锁一整周要好得多。
// 具体数值以 CA 当前公告为准，因此做成可配置的。
type RateLimits struct {
	// PerRegisteredDomain 是每个注册域在滚动窗口内的签发上限。
	PerRegisteredDomain int
	// WindowDays 是滚动窗口长度。
	WindowDays int
	// DuplicateCert 是完全相同的域名组合在窗口内的签发上限。
	DuplicateCert int
}

// DefaultRateLimits 留出约 20% 余量。
func DefaultRateLimits() RateLimits {
	return RateLimits{
		PerRegisteredDomain: 40, // LE 官方 50
		WindowDays:          7,
		DuplicateCert:       4, // LE 官方 5
	}
}

// RegisteredDomain 从域名推算注册域（粗略的 eTLD+1）。
//
// 这里刻意不引入完整的 Public Suffix List：配额计数只需要一个稳定的
// 分组键，偶尔把 example.co.uk 算成 co.uk 会让计数更保守，
// 而保守正是我们想要的方向。
func RegisteredDomain(domain string) string {
	d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "*.")
	d = strings.TrimSuffix(d, ".")
	parts := strings.Split(d, ".")
	if len(parts) <= 2 {
		return d
	}

	// 常见的二级公共后缀，命中时多取一段。
	twoLevel := map[string]bool{
		"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
		"co.uk": true, "org.uk": true, "ac.uk": true, "co.jp": true, "com.hk": true,
		"com.tw": true, "com.au": true, "co.nz": true, "com.br": true, "com.sg": true,
	}
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if twoLevel[last2] && len(parts) >= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return last2
}

// RateLimitVerdict 是一次配额检查的结论。
type RateLimitVerdict struct {
	Allowed bool
	Reason  string
}

// CheckRateLimit 判断此次签发是否应当放行。
//
// issuedInWindow 是该注册域在窗口内已签发的数量，
// duplicatesInWindow 是完全相同域名组合的签发数量。
func (l RateLimits) Check(registeredDomain string, issuedInWindow, duplicatesInWindow int) RateLimitVerdict {
	if l.PerRegisteredDomain > 0 && issuedInWindow >= l.PerRegisteredDomain {
		return RateLimitVerdict{
			Reason: fmt.Sprintf(
				"注册域 %s 在最近 %d 天内已签发 %d 张，达到本地上限 %d。"+
					"继续请求会撞上 CA 的配额并被锁定一整周，因此先停下来。",
				registeredDomain, l.WindowDays, issuedInWindow, l.PerRegisteredDomain),
		}
	}
	if l.DuplicateCert > 0 && duplicatesInWindow >= l.DuplicateCert {
		return RateLimitVerdict{
			Reason: fmt.Sprintf(
				"完全相同的域名组合在最近 %d 天内已签发 %d 次，达到本地上限 %d。"+
					"通常意味着有任务在反复重签，请先检查原因。",
				l.WindowDays, duplicatesInWindow, l.DuplicateCert),
		}
	}
	return RateLimitVerdict{Allowed: true}
}
