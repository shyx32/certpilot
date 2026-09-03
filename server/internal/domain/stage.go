// Package domain 定义跨层共享的核心类型。
package domain

// Stage 是签发流水线的状态。每个状态都持久化在 job.stage 上，
// 进程重启后从断点继续——这是与 Uptime Kuma 式无状态探测的根本区别：
// ACME Order 是有状态的多步事务，丢了状态就等于向 CA 重新申请一张。
type Stage string

const (
	StagePending    Stage = "pending"     // 已入队
	StagePreflight  Stage = "preflight"   // 前置检查：凭据、zone 归属、投放通道
	StageOrdering   Stage = "ordering"    // 创建 ACME Order，落库 order URL
	StageChallenge  Stage = "challenging" // 投放 TXT / 文件，并自检可达
	StageValidating Stage = "validating"  // 通知 CA 校验并轮询
	StageFinalizing Stage = "finalizing"  // 生成 CSR、下载证书链
	StageIssued     Stage = "issued"      // 证书入库，清理验证痕迹
	StageDeploying  Stage = "deploying"   // 推送到全部绑定目标
	StageVerified   Stage = "verified"    // 外部拨测确认线上指纹已更新
	StageFailed     Stage = "failed"
)

// order 定义状态推进顺序；StageFailed 不在其中，它可以从任意状态进入。
var order = []Stage{
	StagePending, StagePreflight, StageOrdering, StageChallenge,
	StageValidating, StageFinalizing, StageIssued, StageDeploying, StageVerified,
}

// Next 返回 s 的下一个状态。终态或未知状态返回 false。
func (s Stage) Next() (Stage, bool) {
	for i, st := range order {
		if st == s && i+1 < len(order) {
			return order[i+1], true
		}
	}
	return "", false
}

// Terminal 报告 s 是否为终态。注意终态是 Verified 而不是 Issued——
// 证书签出来了但线上没生效，不算完成。
func (s Stage) Terminal() bool { return s == StageVerified || s == StageFailed }

// Valid 报告 s 是否是已知状态。
func (s Stage) Valid() bool {
	if s == StageFailed {
		return true
	}
	for _, st := range order {
		if st == s {
			return true
		}
	}
	return false
}

// RetryClass 决定失败后如何处置。
type RetryClass int

const (
	// RetryBackoff 网络、限流等瞬时问题：指数退避后重试。
	RetryBackoff RetryClass = iota
	// RetryNever 鉴权失效、权限不足、域名配置错误：重试只会浪费
	// CA 的失败配额并可能触发风控，直接转人工。
	RetryNever
)
