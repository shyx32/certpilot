package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/certpilot/server/internal/domain"
	"github.com/certpilot/server/internal/health"
	"github.com/certpilot/server/internal/notify"
	"github.com/certpilot/server/internal/store"
)

// runHealthScan 巡检全部目标，并把发现汇总成一条通知。
//
// 汇总是刻意的：20 个域名同时到期应该是一条消息，而不是 20 条。
// 刷屏的告警等于没有告警。
func (s *Scheduler) runHealthScan(ctx context.Context, job *store.Job) error {
	targets, err := s.store.ProbeTargets(ctx)
	if err != nil {
		return s.store.FailJob(ctx, job, "读取巡检目标失败："+err.Error(), domain.RetryBackoff)
	}
	if len(targets) == 0 {
		_, _ = s.store.AppendLog(ctx, job.ID, domain.StageVerified, "info", "没有需要巡检的域名")
		return s.store.FinishJob(ctx, job.ID, domain.StageVerified)
	}

	_, _ = s.store.AppendLog(ctx, job.ID, domain.StageVerified, "info",
		fmt.Sprintf("开始巡检 %d 个域名", len(targets)))

	prober := health.NewProber()
	prober.CheckRevocation = s.CheckRevocation

	type finding struct {
		domain   string
		severity string
		text     string
	}
	var (
		mu       sync.Mutex
		findings []finding
		okCount  int
	)

	// 并发探测，但不要一次打开太多连接。
	sem := make(chan struct{}, s.ProbeConcurrency)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t store.ProbeTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			a, probeErr := prober.Probe(ctx, health.Target{
				Domain: t.Domain, Port: t.Port, SNI: t.SNI,
				ExpectedFingerprint: t.ExpectedFP,
			})
			if err := s.store.SaveHealthCheck(ctx, t, a, probeErr); err != nil {
				slog.Error("保存巡检结果失败", "domain", t.Domain, "err", err)
			}

			mu.Lock()
			defer mu.Unlock()
			switch {
			case probeErr != nil:
				findings = append(findings, finding{t.Domain, health.SevDanger,
					fmt.Sprintf("%s：无法建立 TLS 连接", t.Domain)})
			case !a.Healthy():
				for _, i := range a.Issues {
					if i.Severity == health.SevInfo {
						continue
					}
					findings = append(findings, finding{t.Domain, i.Severity,
						fmt.Sprintf("%s：%s", t.Domain, i.Text)})
				}
			default:
				okCount++
			}
		}(t)
	}
	wg.Wait()

	summary := fmt.Sprintf("巡检完成：%d 个正常，%d 项待处理", okCount, len(findings))
	_, _ = s.store.AppendLog(ctx, job.ID, domain.StageVerified, "info", summary)
	slog.Info("巡检完成", "total", len(targets), "ok", okCount, "findings", len(findings))

	if len(findings) > 0 {
		// 严重的排前面，人先看到最要紧的。
		sort.SliceStable(findings, func(i, j int) bool {
			return sevRank(findings[i].severity) < sevRank(findings[j].severity)
		})
		level := notify.LevelWarn
		if findings[0].severity == health.SevDanger {
			level = notify.LevelDanger
		}

		lines := make([]string, 0, len(findings))
		for _, f := range findings {
			lines = append(lines, f.text)
		}
		// 一条消息里塞几十行没人看得完，超出部分折叠成一句。
		const maxLines = 15
		if len(lines) > maxLines {
			more := len(lines) - maxLines
			lines = lines[:maxLines]
			lines = append(lines, fmt.Sprintf("…还有 %d 项，详见巡检看板", more))
		}

		s.notifier.Send(ctx, &notify.Message{
			Event:  notify.EventHealth,
			Level:  level,
			Title:  fmt.Sprintf("巡检发现 %d 项问题", len(findings)),
			Lines:  lines,
			Footer: time.Now().Format("2006-01-02 15:04"),
		})
	}

	// 顺手做保留策略清理，避免历史记录无限增长。
	if err := s.store.PruneHealthChecks(ctx, s.KeepHealthDays); err != nil {
		slog.Error("清理历史巡检记录失败", "err", err)
	}
	if err := s.store.PruneJobs(ctx, s.KeepJobDays); err != nil {
		slog.Error("清理历史任务失败", "err", err)
	}

	return s.store.FinishJob(ctx, job.ID, domain.StageVerified)
}

func sevRank(s string) int {
	switch s {
	case health.SevDanger:
		return 0
	case health.SevWarn:
		return 1
	default:
		return 2
	}
}
