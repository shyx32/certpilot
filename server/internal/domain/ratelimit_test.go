package domain

import (
	"strings"
	"testing"
)

func TestRegisteredDomain(t *testing.T) {
	cases := map[string]string{
		"example.com":         "example.com",
		"www.example.com":     "example.com",
		"a.b.c.example.com":   "example.com",
		"*.example.com":       "example.com",
		"EXAMPLE.COM":         "example.com",
		"example.com.":        "example.com",
		"shop.example.com.cn": "example.com.cn",
		"www.example.co.uk":   "example.co.uk",
		"example.co.uk":       "example.co.uk",
		"localhost":           "localhost",
	}
	for in, want := range cases {
		if got := RegisteredDomain(in); got != want {
			t.Errorf("RegisteredDomain(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// 同一注册域下的不同子域必须归到同一个配额桶里——
// CA 的限制就是按注册域计的。
func TestRegisteredDomainGroupsSubdomains(t *testing.T) {
	group := RegisteredDomain("a.example.com")
	for _, d := range []string{"b.example.com", "*.example.com", "x.y.example.com"} {
		if RegisteredDomain(d) != group {
			t.Errorf("%s 未与 a.example.com 归入同一配额桶", d)
		}
	}
}

func TestCheckAllowsUnderLimit(t *testing.T) {
	l := DefaultRateLimits()
	if v := l.Check("example.com", 10, 1); !v.Allowed {
		t.Fatalf("远未达上限却被拦下: %s", v.Reason)
	}
}

func TestCheckBlocksAtDomainLimit(t *testing.T) {
	l := DefaultRateLimits()
	v := l.Check("example.com", l.PerRegisteredDomain, 0)
	if v.Allowed {
		t.Fatal("达到上限应当拦下")
	}
	// 理由要说清楚为什么现在停下来更划算
	if !strings.Contains(v.Reason, "example.com") || !strings.Contains(v.Reason, "锁定") {
		t.Errorf("拦截理由不够清楚: %s", v.Reason)
	}
}

// 反复重签同一组域名通常是有任务在打转，这比总量超限更值得提醒。
func TestCheckBlocksDuplicates(t *testing.T) {
	l := DefaultRateLimits()
	v := l.Check("example.com", 1, l.DuplicateCert)
	if v.Allowed {
		t.Fatal("重复证书达到上限应当拦下")
	}
	if !strings.Contains(v.Reason, "反复重签") {
		t.Errorf("应提示可能有任务在打转: %s", v.Reason)
	}
}

// 本地上限必须比 CA 的实际配额低，否则起不到保护作用。
func TestDefaultsLeaveHeadroom(t *testing.T) {
	l := DefaultRateLimits()
	if l.PerRegisteredDomain >= 50 {
		t.Errorf("每注册域上限 %d 没有为 LE 的 50 留出余量", l.PerRegisteredDomain)
	}
	if l.DuplicateCert >= 5 {
		t.Errorf("重复证书上限 %d 没有为 LE 的 5 留出余量", l.DuplicateCert)
	}
}

func TestZeroLimitDisablesCheck(t *testing.T) {
	l := RateLimits{PerRegisteredDomain: 0, DuplicateCert: 0}
	if v := l.Check("example.com", 9999, 9999); !v.Allowed {
		t.Fatal("上限为 0 应表示不限制")
	}
}
