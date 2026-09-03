// certpilot 是控制面的单一入口。
//
//	certpilot serve     接口 + 调度 + 执行（默认，三容器部署下的 api）
//	certpilot worker    只跑调度与执行，规模增长后可拆成独立容器
//	certpilot migrate   执行数据库迁移，作为一次性容器运行
//	certpilot genkey    生成加密主密钥
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/certpilot/server/internal/auth"
	"github.com/certpilot/server/internal/config"
	"github.com/certpilot/server/internal/events"
	"github.com/certpilot/server/internal/httpapi"
	"github.com/certpilot/server/internal/scheduler"
	"github.com/certpilot/server/internal/secretbox"
	"github.com/certpilot/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"

	// 注册各 provider 实现。它们通过 init 把自己登记进注册表，
	// 编排层因此不需要认识任何具体厂商。
	_ "github.com/certpilot/server/internal/provider/deploy/aliyuncdn"
	_ "github.com/certpilot/server/internal/provider/deploy/sshnginx"
	_ "github.com/certpilot/server/internal/provider/dns/alidns"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	// genkey 不需要数据库与配置，放在最前面。
	if cmd == "genkey" {
		k, err := secretbox.GenerateMasterKey()
		if err != nil {
			fatal(err)
		}
		fmt.Println(k)
		fmt.Fprintln(os.Stderr,
			"\n请离线备份这把主密钥，并与数据库备份分开存放。\n"+
				"它不入库——丢失后所有凭据与私钥都无法恢复。")
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fatal(fmt.Errorf("配置有误:\n%w", err))
	}
	box, err := secretbox.New(cfg.MasterKey)
	if err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := connectDB(ctx, cfg.DatabaseDSN)
	if err != nil {
		fatal(err)
	}
	defer pool.Close()

	if cmd == "migrate" {
		if err := store.Migrate(ctx, pool); err != nil {
			fatal(err)
		}
		slog.Info("数据库迁移完成")
		return
	}

	st := store.New(pool, box)
	hub := events.NewHub()

	// HTTP-01 的应答端由 API 与流水线共用：流水线登记 token，
	// API 负责在 CA 来取时应答。
	challenges := httpapi.NewChallengeStore()

	switch cmd {
	case "serve":
		if err := ensureAdmin(ctx, st); err != nil {
			fatal(err)
		}
		runServe(ctx, cfg, st, hub, challenges)
	case "worker":
		runWorker(ctx, cfg, st, hub, challenges)
	default:
		fatal(fmt.Errorf("未知命令 %q（可用：serve worker migrate genkey）", cmd))
	}
}

// connectDB 带重试地连接数据库。
//
// 容器编排下 api 可能比 db 先就绪，直接失败退出会让编排陷入反复重启。
func connectDB(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("解析数据库配置失败: %w", err)
	}
	var lastErr error
	for attempt := 1; attempt <= 30; attempt++ {
		if lastErr = pool.Ping(ctx); lastErr == nil {
			return pool, nil
		}
		if ctx.Err() != nil {
			pool.Close()
			return nil, ctx.Err()
		}
		slog.Info("等待数据库就绪", "attempt", attempt)
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	pool.Close()
	return nil, fmt.Errorf("数据库始终不可达: %w", lastErr)
}

// ensureAdmin 在库中还没有任何用户时创建初始管理员。
//
// 密码优先取 CP_ADMIN_PASSWORD；没有就随机生成并打印到启动日志——
// 绝不使用 admin/admin 这类固定默认口令，那等同于不设防。
func ensureAdmin(ctx context.Context, st *store.Store) error {
	n, err := st.CountUsers(ctx)
	if err != nil {
		return fmt.Errorf("检查用户表失败: %w", err)
	}
	if n > 0 {
		return nil
	}

	pw := os.Getenv("CP_ADMIN_PASSWORD")
	generated := false
	if pw == "" {
		if pw, err = auth.GeneratePassword(); err != nil {
			return err
		}
		generated = true
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return fmt.Errorf("初始密码不合要求: %w", err)
	}
	if _, err := st.CreateUser(ctx, "admin", hash, "admin"); err != nil {
		return fmt.Errorf("创建初始管理员失败: %w", err)
	}

	if generated {
		fmt.Fprintf(os.Stderr,
			"\n────────────────────────────────────────────────\n"+
				"  初始管理员账号已创建\n"+
				"    用户名  admin\n"+
				"    密码    %s\n"+
				"  这串密码只在此刻显示一次，请立即登录并修改。\n"+
				"────────────────────────────────────────────────\n\n", pw)
	} else {
		slog.Info("已用 CP_ADMIN_PASSWORD 创建初始管理员", "username", "admin")
	}
	return nil
}

func runServe(ctx context.Context, cfg *config.Config, st *store.Store, hub *events.Hub,
	challenges *httpapi.ChallengeStore) {
	sessions := auth.NewSessions(12 * time.Hour)

	// 定期清理过期会话，避免内存里堆积无用条目。
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sessions.Cleanup()
			}
		}
	}()

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           httpapi.New(st, hub, challenges, sessions),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if cfg.RunWorker {
		go runWorker(ctx, cfg, st, hub, challenges)
	}

	go func() {
		slog.Info("HTTP 服务启动", "config", cfg.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal(err)
		}
	}()

	<-ctx.Done()
	slog.Info("收到退出信号，开始优雅关闭")

	// 关闭窗口要留够：签发任务可能正跑到一半，
	// 让它有机会把当前 stage 写回数据库，下次启动才能断点续跑。
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("关闭超时", "err", err)
	}
}

func runWorker(ctx context.Context, cfg *config.Config, st *store.Store, hub *events.Hub,
	challenges *httpapi.ChallengeStore) {
	s := scheduler.New(st, hub, challenges)
	s.ScanInterval = cfg.ScanInterval
	slog.Info("调度器启动", "interval", s.ScanInterval, "concurrency", s.Concurrency)
	s.Run(ctx)
	slog.Info("调度器已停止")
}

func fatal(err error) {
	slog.Error(err.Error())
	os.Exit(1)
}
