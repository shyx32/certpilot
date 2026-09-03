package aliyun

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeServerError 模拟阿里云 SDK 的错误：Error() 里塞满了噪音。
type fakeServerError struct {
	code string
	msg  string
}

func (e *fakeServerError) ErrorCode() string { return e.code }
func (e *fakeServerError) Message() string   { return e.msg }
func (e *fakeServerError) Error() string {
	return fmt.Sprintf("SDK.ServerError\nErrorCode: %s\nRequestId: 01A0669A-C4FC\n"+
		"Message: %s\nRespHeaders: map[Connection:[keep-alive] X-Acs-Trace-Id:[2dae2a12]]",
		e.code, e.msg)
}

func TestExplainMapsKnownCodes(t *testing.T) {
	got := Explain(&fakeServerError{code: "InvalidAccessKeyId.NotFound", msg: "Specified access key is not found."})
	if !strings.Contains(got, "AccessKey ID 不存在") {
		t.Fatalf("未翻译成可行动的说明: %q", got)
	}
	// 关键：噪音必须被丢掉。
	for _, noise := range []string{"RequestId", "RespHeaders", "X-Acs-Trace-Id", "SDK.ServerError"} {
		if strings.Contains(got, noise) {
			t.Errorf("输出里仍包含内部细节 %q: %s", noise, got)
		}
	}
}

func TestExplainUnknownCodeKeepsMessage(t *testing.T) {
	got := Explain(&fakeServerError{code: "Weird.Code", msg: "something specific went wrong"})
	if !strings.Contains(got, "Weird.Code") {
		t.Errorf("未知错误码应保留下来便于检索: %q", got)
	}
	if !strings.Contains(got, "something specific") {
		t.Errorf("应保留原始 message: %q", got)
	}
	if strings.Contains(got, "RespHeaders") {
		t.Errorf("仍有噪音: %q", got)
	}
}

// 被 fmt.Errorf(%w) 包裹后仍要能识别出来。
func TestExplainUnwrapsWrappedError(t *testing.T) {
	inner := &fakeServerError{code: "SignatureDoesNotMatch", msg: "bad signature"}
	got := Explain(fmt.Errorf("拉取域名列表失败: %w", inner))
	if !strings.Contains(got, "AccessKey Secret 不正确") {
		t.Fatalf("包裹后未能识别: %q", got)
	}
}

func TestExplainPlainErrorTakesFirstLine(t *testing.T) {
	got := Explain(errors.New("连接超时\n第二行细节\n第三行"))
	if got != "连接超时" {
		t.Fatalf("应只取首行，实得 %q", got)
	}
}

func TestExplainNil(t *testing.T) {
	if Explain(nil) != "" {
		t.Fatal("nil 应返回空串")
	}
}
