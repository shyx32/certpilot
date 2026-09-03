package aliyun

import (
	"errors"
	"fmt"
	"strings"
)

// coded 覆盖阿里云 SDK 的 ServerError/ClientError。
// 用鸭子类型而不是具体类型，避免和 SDK 的内部结构耦合。
type coded interface {
	ErrorCode() string
	Message() string
}

// hints 把常见错误码翻译成使用者能据以行动的说明。
//
// SDK 原始错误里带着 RequestId、RespHeaders 乃至整个 header map，
// 直接抛给用户既看不懂也无从下手，还会把内部细节漏到界面上。
var hints = map[string]string{
	"InvalidAccessKeyId.NotFound": "AccessKey ID 不存在，请确认填写正确且未被删除。",
	"SignatureDoesNotMatch":       "AccessKey Secret 不正确，请重新复制粘贴。",
	"Forbidden.RAM":               "该子账号缺少所需权限，请检查绑定的 RAM 策略。",
	"NoPermission":                "该账号没有执行此操作的权限。",
	"Forbidden":                   "请求被拒绝，通常是权限不足或该服务尚未开通。",
	"InvalidDomainName.NoExist":   "该域名不在这个账号下，请确认选对了凭据。",
	"DomainNotExists":             "该域名不在这个账号下，请确认选对了凭据。",
	"DomainRecordDuplicate":       "已存在同名解析记录。",
	"Throttling":                  "请求过于频繁，稍后会自动重试。",
	"Throttling.User":             "请求过于频繁，稍后会自动重试。",
	"ServiceUnavailable":          "阿里云服务暂时不可用，稍后会自动重试。",
	"EntityAlreadyExists.User":    "同名 RAM 用户已存在，请换一个名称前缀。",
	"EntityAlreadyExists.Policy":  "同名 RAM 策略已存在，请换一个名称前缀。",
	"LimitExceeded.User":          "RAM 用户数量已达上限，请先清理不用的子账号。",
	"NotFound.Certificate":        "指定的证书不存在，可能已被删除。",
}

// Explain 把阿里云 SDK 错误转成简洁、可行动的中文说明。
//
// 保留错误码便于检索，丢弃 RequestId 与响应头等噪音。
func Explain(err error) string {
	if err == nil {
		return ""
	}
	var c coded
	if !errors.As(err, &c) {
		// 不是 SDK 错误，取首行即可——多行堆栈对用户没有意义。
		return firstLine(err.Error())
	}
	code := c.ErrorCode()
	if hint, ok := hints[code]; ok {
		return hint
	}
	msg := firstLine(c.Message())
	if msg == "" {
		return fmt.Sprintf("阿里云返回错误 %s。", code)
	}
	return fmt.Sprintf("阿里云返回错误 %s：%s", code, msg)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
