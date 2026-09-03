package acme

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-acme/lego/v4/acme"
)

// hints 把 ACME 的 problem type 翻译成使用者能据以行动的说明。
//
// lego 返回的原始错误形如
//
//	acme: error: 400 :: POST :: https://…/new-acct :: urn:ietf:params:acme:error:invalidContact :: 详情
//
// 直接抛给用户既冗长又不知从何下手。
var hints = map[string]string{
	"urn:ietf:params:acme:error:invalidContact":      "联系邮箱不被 CA 接受，请换一个真实可收信的地址。",
	"urn:ietf:params:acme:error:unsupportedContact":  "联系方式格式不被支持，请填写标准邮箱地址。",
	"urn:ietf:params:acme:error:rateLimited":         "已触发 CA 的速率限制，请稍后再试；频繁失败会延长限制时间。",
	"urn:ietf:params:acme:error:unauthorized":        "域名验证未通过，请确认解析记录已生效且指向正确。",
	"urn:ietf:params:acme:error:rejectedIdentifier":  "CA 拒绝为该域名签发证书，请确认它是可公开解析的真实域名。",
	"urn:ietf:params:acme:error:malformed":           "请求内容不被 CA 接受，请检查域名格式是否正确。",
	"urn:ietf:params:acme:error:dns":                 "CA 查询 DNS 时出错，请确认域名解析正常。",
	"urn:ietf:params:acme:error:connection":          "CA 无法连接到你的服务器，请确认 80 端口可从公网访问。",
	"urn:ietf:params:acme:error:caa":                 "该域名的 CAA 记录不允许这家 CA 签发证书。",
	"urn:ietf:params:acme:error:accountDoesNotExist": "CA 账号不存在，请重新添加账号。",
	"urn:ietf:params:acme:error:badNonce":            "与 CA 的握手需要重试，稍后会自动重来。",
}

// Explain 把 ACME 错误转成简洁、可行动的中文说明。
func Explain(err error) string {
	if err == nil {
		return ""
	}

	var pd *acme.ProblemDetails
	if errors.As(err, &pd) {
		if hint, ok := hints[pd.Type]; ok {
			return hint
		}
		if pd.Detail != "" {
			return fmt.Sprintf("CA 返回错误：%s", firstLine(pd.Detail))
		}
		return fmt.Sprintf("CA 返回错误 %s。", shortType(pd.Type))
	}

	// 不是结构化的 problem，退回按文本解析 lego 的 " :: " 分段格式。
	s := err.Error()
	if parts := strings.Split(s, " :: "); len(parts) >= 2 {
		typ := parts[len(parts)-2]
		detail := firstLine(parts[len(parts)-1])
		if hint, ok := hints[typ]; ok {
			return hint
		}
		if strings.HasPrefix(typ, "urn:ietf:params:acme:error:") {
			return fmt.Sprintf("CA 返回错误 %s：%s", shortType(typ), detail)
		}
		return detail
	}
	return firstLine(s)
}

// shortType 去掉冗长的 URN 前缀，只保留错误名。
func shortType(t string) string {
	return strings.TrimPrefix(t, "urn:ietf:params:acme:error:")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// permanent 是重试也不会改变结果的 problem type。
//
// 这类错误必须一次就停：CA 对失败验证有独立配额，
// 拿着一个注定被拒的域名反复重试，只会把配额耗光并可能触发风控。
var permanent = map[string]bool{
	"urn:ietf:params:acme:error:rejectedIdentifier":    true, // 域名本身被 CA 拒绝
	"urn:ietf:params:acme:error:invalidContact":        true,
	"urn:ietf:params:acme:error:unsupportedContact":    true,
	"urn:ietf:params:acme:error:accountDoesNotExist":   true,
	"urn:ietf:params:acme:error:caa":                   true, // CAA 记录不允许这家 CA
	"urn:ietf:params:acme:error:malformed":             true,
	"urn:ietf:params:acme:error:unsupportedIdentifier": true,
}

// IsPermanent 报告该错误是否为永久性失败，据此决定要不要重试。
//
// 注意 rateLimited 与 serverInternal 不在此列——它们是暂时的，
// 放弃重试会让证书静静过期，代价比多等一会儿大得多。
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	var pd *acme.ProblemDetails
	if errors.As(err, &pd) {
		return permanent[pd.Type]
	}

	// lego 把多个域名的失败聚合成一个不支持 Unwrap 的错误，
	// 而我们自己的 Error() 又已经把 URN 清洗掉了。
	// 因此要沿 Unwrap 链把每一层的原始文本都翻一遍。
	s := rawText(err)
	for typ := range permanent {
		if strings.Contains(s, typ) {
			return true
		}
	}
	return false
}

// rawText 收集 err 及其 Unwrap 链上每一层的原始文本。
func rawText(err error) string {
	var sb strings.Builder
	for e := err; e != nil; e = errors.Unwrap(e) {
		sb.WriteString(e.Error())
		sb.WriteByte('\n')
		if sb.Len() > 64<<10 { // 防御异常长的错误链
			break
		}
	}
	return sb.String()
}

// Error 是带上下文的 ACME 错误。
//
// 它保留原始错误，让调用方既能拿到给人看的说明，
// 也能用 IsPermanent 判断该不该重试。
type Error struct {
	Action string
	Cause  error
}

func (e *Error) Error() string { return e.Action + "：" + Explain(e.Cause) }
func (e *Error) Unwrap() error { return e.Cause }
