package pipeline

import (
	"errors"
	"testing"

	"github.com/certpilot/server/internal/acme"
	"github.com/certpilot/server/internal/domain"
	lego "github.com/go-acme/lego/v4/acme"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  string
		want domain.RetryClass
	}{
		// 速率限制必须重试——放弃会让证书静静过期。
		{"CA 速率限制", "签发失败：已触发 CA 的速率限制，请稍后再试", domain.RetryBackoff},
		{"云 API 限流", "aliyun: Throttling.User", domain.RetryBackoff},
		{"网络抖动", "dial tcp: i/o timeout", domain.RetryBackoff},

		// 鉴权与配置问题重试只会消耗 CA 的失败配额。
		{"AK 失效", "拉取域名列表失败：AccessKey ID 不存在，请确认填写正确", domain.RetryNever},
		{"签名错误", "SignatureDoesNotMatch", domain.RetryNever},
		{"权限不足", "该子账号缺少所需权限，请检查绑定的 RAM 策略", domain.RetryNever},
		{"域名未托管", "域名归属检查未通过: 无法归属到已托管的 zone", domain.RetryNever},
		{"邮箱被拒", "注册 CA 账号失败：联系邮箱不被 CA 接受", domain.RetryNever},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classify(errors.New(c.err)); got != c.want {
				t.Errorf("classify(%q) = %v, 期望 %v", c.err, got, c.want)
			}
		})
	}
}

// 同时含速率限制与权限字样时，按可重试处理——
// 误判为不可重试会让证书过期，代价比多试一次大得多。
func TestClassifyPrefersRetryOnRateLimit(t *testing.T) {
	err := errors.New("权限检查通过，但已触发 CA 的速率限制")
	if got := classify(err); got != domain.RetryBackoff {
		t.Errorf("速率限制应优先判为可重试，实得 %v", got)
	}
}

// 回归：CA 明确拒绝域名时不能重试。
// 曾经出现过对一个被拒的域名连试 5 次，白白消耗 CA 的失败配额。
func TestClassifyRejectedIdentifierIsPermanent(t *testing.T) {
	err := &acme.Error{
		Action: "签发失败",
		Cause: &lego.ProblemDetails{
			Type:   "urn:ietf:params:acme:error:rejectedIdentifier",
			Detail: "Cannot issue for \"shop.example.com\": Domain is on a block list",
		},
	}
	if got := classify(err); got != domain.RetryNever {
		t.Fatalf("CA 拒绝的域名应停止重试，实得 %v", got)
	}
}

// 但速率限制必须继续重试，否则证书会静静过期。
func TestClassifyRateLimitedStillRetries(t *testing.T) {
	err := &acme.Error{
		Action: "签发失败",
		Cause:  &lego.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited"},
	}
	if got := classify(err); got != domain.RetryBackoff {
		t.Fatalf("速率限制应继续重试，实得 %v", got)
	}
}
