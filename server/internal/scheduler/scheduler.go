// Package scheduler 负责到期扫描与任务执行。
//
// 默认与 HTTP 服务同进程运行：按 1000 域名的规模测算，每天只有十几个签发任务，
// 拆成独立进程只会增加运维面。需要拆时用 certpilot worker 启动即可。
package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/certpilot/server/internal/acme"
	"github.com/certpilot/server/internal/domain"
	"github.com/certpilot/server/internal/events"
	"github.com/certpilot/server/internal/pipeline"
	"github.com/certpilot/server/internal/store"
)

type Scheduler struct {
	store  *store.Store
	hub    *events.Hub
	runner *pipeline.Runner

	// ScanInterval 是到期扫描的周期。
	ScanInterval time.Duration
	// PollInterval 是队列空闲时的轮询间隔。
	PollInterval time.Duration
	// Concurrency 是同时执行的任务数上限。
	//
	// 这个值同时约束了对 CA 的并发请求，单进程让限流天然全局有效——
	// 这正是不拆 worker 的一个额外好处。
	Concurrency int
	// StaleAfter 超过此时长仍处于 running 的任务视为进程崩溃遗留。
	StaleAfter time.Duration
}

func New(s *store.Store, hub *events.Hub, challenges acme.HTTPChallenge) *Scheduler {
	return &Scheduler{
		store:        s,
		hub:          hub,
		runner:       pipeline.New(s, hub, challenges),
		ScanInterval: time.Hour,
		PollInterval: 5 * time.Second,
		Concurrency:  3,
		StaleAfter:   30 * time.Minute,
	}
}

// Run 阻塞运行，直到 ctx 取消。
func (s *Scheduler) Run(ctx context.Context) {
	// 上一次进程崩溃时留下的 running 任务必须放回队列，
	// 否则它们会永远卡住，而对应证书静静地过期。
	if n, err := s.store.RequeueStaleJobs(ctx, s.StaleAfter); err != nil {
		slog.Error("回收滞留任务失败", "err", err)
	} else if n > 0 {
		slog.Warn("已把滞留任务放回队列", "count", n)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.scanLoop(ctx) }()
	go func() { defer wg.Done(); s.workLoop(ctx) }()
	wg.Wait()
}

// scanLoop 周期性地把到期证书投入队列。
func (s *Scheduler) scanLoop(ctx context.Context) {
	// 启动时先扫一次，不必等第一个周期。
	s.scanOnce(ctx)

	t := time.NewTicker(s.ScanInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.scanOnce(ctx)
		}
	}
}

func (s *Scheduler) scanOnce(ctx context.Context) {
	due, err := s.store.DueForRenewal(ctx)
	if err != nil {
		slog.Error("扫描待续期证书失败", "err", err)
		return
	}
	for _, cfg := range due {
		kind := "renew"
		if cfg.NotAfter == nil {
			kind = "issue"
		}
		id, err := s.store.EnqueueJob(ctx, kind, &cfg.ID, nil)
		if err != nil {
			slog.Error("投递续期任务失败", "config", cfg.Name, "err", err)
			continue
		}
		slog.Info("已投递任务", "job", id, "kind", kind, "config", cfg.Name)
	}
	if len(due) > 0 {
		slog.Info("到期扫描完成", "queued", len(due))
	}
}

// workLoop 领取并执行任务。
func (s *Scheduler) workLoop(ctx context.Context) {
	sem := make(chan struct{}, s.Concurrency)
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		job, err := s.store.ClaimJob(ctx)
		if errors.Is(err, store.ErrNotFound) {
			// 队列空，等一会儿再看。
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.PollInterval):
			}
			continue
		}
		if err != nil {
			slog.Error("领取任务失败", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.PollInterval):
			}
			continue
		}

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wg.Add(1)
		go func(j *store.Job) {
			defer wg.Done()
			defer func() { <-sem }()
			s.execute(ctx, j)
		}(job)
	}
}

func (s *Scheduler) execute(ctx context.Context, job *store.Job) {
	slog.Info("开始执行任务", "job", job.ID, "kind", job.Kind, "attempt", job.Attempt)
	s.hub.Publish(events.Event{Type: "job_state", JobID: job.ID, Stage: "running"})

	var err error
	switch job.Kind {
	case "issue", "renew":
		err = s.runner.Run(ctx, job)
	case "sync_zones":
		err = s.syncZones(ctx, job)
	default:
		err = s.store.FailJob(ctx, job,
			"未知任务类型 "+job.Kind, domain.RetryNever)
	}
	if err != nil {
		slog.Error("任务执行结束但有错误", "job", job.ID, "err", err)
	}

	final, _ := s.store.GetJob(ctx, job.ID)
	if final != nil {
		s.hub.Publish(events.Event{Type: "job_state", JobID: job.ID, Stage: final.State})
	}
}
