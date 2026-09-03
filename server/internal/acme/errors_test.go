package acme

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/acme"
)

func TestExplainKnownProblemType(t *testing.T) {
	err := &acme.ProblemDetails{
		Type:   "urn:ietf:params:acme:error:invalidContact",
		Detail: "contact email has forbidden domain example.com",
	}
	got := Explain(err)
	if !strings.Contains(got, "联系邮箱不被 CA 接受") {
		t.Fatalf("未翻译成可行动说明: %q", got)
	}
	if strings.Contains(got, "urn:ietf") {
		t.Errorf("输出里仍有 URN 前缀: %q", got)
	}
}

func TestExplainRateLimitedIsActionable(t *testing.T) {
	got := Explain(&acme.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited"})
	if !strings.Contains(got, "速率限制") {
		t.Fatalf("速率限制应有明确提示: %q", got)
	}
}

// lego 的文本格式错误也要能解析，不能整段抛给用户。
func TestExplainParsesLegoTextFormat(t *testing.T) {
	raw := errors.New("acme: error: 400 :: POST :: https://acme-staging-v02.api.letsencrypt.org/acme/new-acct " +
		":: urn:ietf:params:acme:error:invalidContact :: Error validating contact(s)")
	got := Explain(raw)
	if !strings.Contains(got, "联系邮箱不被 CA 接受") {
		t.Fatalf("文本格式未被解析: %q", got)
	}
	for _, noise := range []string{"https://", "POST", "acme: error: 400"} {
		if strings.Contains(got, noise) {
			t.Errorf("仍包含噪音 %q: %s", noise, got)
		}
	}
}

func TestExplainUnknownTypeKeepsDetail(t *testing.T) {
	got := Explain(&acme.ProblemDetails{Type: "urn:ietf:params:acme:error:serverInternal", Detail: "boom"})
	if !strings.Contains(got, "boom") {
		t.Fatalf("应保留原始 detail: %q", got)
	}
}

func TestExplainWrapped(t *testing.T) {
	inner := &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:caa"}
	got := Explain(fmt.Errorf("签发失败: %w", inner))
	if !strings.Contains(got, "CAA") {
		t.Fatalf("包裹后未识别: %q", got)
	}
}

func TestExplainNil(t *testing.T) {
	if Explain(nil) != "" {
		t.Fatal("nil 应返回空串")
	}
}

func TestIsPermanent(t *testing.T) {
	cases := []struct {
		name string
		typ  string
		want bool
	}{
		// CA 明确拒绝这个域名，重试多少次都一样。
		{"域名被拒", "urn:ietf:params:acme:error:rejectedIdentifier", true},
		{"CAA 不允许", "urn:ietf:params:acme:error:caa", true},
		{"邮箱不合法", "urn:ietf:params:acme:error:invalidContact", true},
		// 这些是暂时的，放弃重试会让证书过期。
		{"速率限制", "urn:ietf:params:acme:error:rateLimited", false},
		{"服务端错误", "urn:ietf:params:acme:error:serverInternal", false},
		{"nonce 过期", "urn:ietf:params:acme:error:badNonce", false},
		{"连接失败", "urn:ietf:params:acme:error:connection", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsPermanent(&acme.ProblemDetails{Type: c.typ}); got != c.want {
				t.Errorf("IsPermanent(%s) = %v, 期望 %v", c.typ, got, c.want)
			}
		})
	}
}

func TestIsPermanentFromWrappedText(t *testing.T) {
	err := fmt.Errorf("签发失败: acme: error: 400 :: POST :: https://x :: %s :: nope",
		"urn:ietf:params:acme:error:rejectedIdentifier")
	if !IsPermanent(err) {
		t.Fatal("文本形式的永久错误未被识别")
	}
}

func TestIsPermanentNil(t *testing.T) {
	if IsPermanent(nil) {
		t.Fatal("nil 不应判为永久失败")
	}
}

// lego 把多域名失败聚合成这种不支持 Unwrap 的错误，
// 真实场景走的是这条路径而不是干净的 ProblemDetails。
type aggregateError struct{ text string }

func (e *aggregateError) Error() string { return e.text }

// 回归：曾经因为 Error() 已被清洗、聚合错误又无法 Unwrap，
// 导致 CA 拒绝的域名被反复重试 5 次。
func TestIsPermanentThroughSanitizedWrapper(t *testing.T) {
	raw := &aggregateError{
		text: "error: one or more domains had a problem:\n[shop.example.com] " +
			"acme: error: 400 :: POST :: https://acme-staging-v02.api.letsencrypt.org/acme/order " +
			":: urn:ietf:params:acme:error:rejectedIdentifier :: Domain is on a block list",
	}
	// Error() 输出的是清洗后的文本，URN 已不在其中。
	wrapped := &Error{Action: "签发失败", Cause: raw}
	if strings.Contains(wrapped.Error(), "urn:ietf") {
		t.Fatal("前提不成立：Error() 本应已清洗掉 URN")
	}
	if !IsPermanent(wrapped) {
		t.Fatal("被清洗的包装错误里未能识别出永久失败")
	}
}

func TestIsPermanentAggregateRateLimitStillRetries(t *testing.T) {
	raw := &aggregateError{
		text: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many certificates",
	}
	if IsPermanent(&Error{Action: "签发失败", Cause: raw}) {
		t.Fatal("速率限制被误判为永久失败，会导致证书过期")
	}
}
