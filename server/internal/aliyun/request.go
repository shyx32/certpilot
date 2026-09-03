package aliyun

import (
	"context"
	"time"
)

// timeoutSetter 是 SDK 请求对象共有的超时设置能力（来自 baseRequest）。
type timeoutSetter interface {
	SetConnectTimeout(time.Duration)
	SetReadTimeout(time.Duration)
}

// Prepare 为一次 SDK 调用设置超时，并在发起前检查 context。
//
// 阿里云老版 SDK 不接受 context.Context，无法中途取消，
// 因此这里做两件力所能及的事：不在已取消的上下文里发起新请求，
// 以及给每个请求加上有限的超时，避免 goroutine 永久挂起。
func Prepare(ctx context.Context, r timeoutSetter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.SetConnectTimeout(10 * time.Second)
	r.SetReadTimeout(30 * time.Second)
	return nil
}
