// Package httpapi 提供 REST 接口与 WebSocket 实时推送。
package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/certpilot/server/internal/auth"
	"github.com/certpilot/server/internal/events"
	"github.com/certpilot/server/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// New 组装全部路由。
//
// 除健康检查与 ACME 验证应答外，所有接口都需要登录：这个系统集中持有
// 全站私钥与云账号密钥，没有「内网所以不设防」的例外。
func New(st *store.Store, hub *events.Hub, challenges *ChallengeStore, sessions *auth.Sessions) http.Handler {
	a := &API{store: st, sessions: sessions}
	ws := &wsHandler{hub: hub, sessions: sessions}

	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Recoverer)

	// ---- 公开路径 ----

	// 健康检查包含数据库连通性——只回 200 而不检查依赖的探针没有意义。
	r.Get("/healthz", func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "degraded", "error": "数据库不可达",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// HTTP-01 集中验证：业务服务器把该路径重定向过来，由这里应答。
	// 必须允许匿名明文访问——CA 不会带任何凭据来取这个文件。
	r.Get("/.well-known/acme-challenge/{token}", challenges.serve)

	r.Post("/api/v1/auth/login", a.login)

	// 指标端点需要登录：它会暴露全部域名，属于内部信息。
	// 让 Prometheus 用一个只读账号抓取即可。
	r.Group(func(r chi.Router) {
		r.Use(a.requireAuth)
		r.Get("/metrics", a.metrics)
	})

	// ---- 需要登录 ----

	r.Group(func(r chi.Router) {
		r.Use(a.requireAuth)

		r.Get("/ws", ws.handle)

		r.Route("/api/v1", func(r chi.Router) {
			r.Post("/auth/logout", a.logout)
			r.Get("/auth/me", a.me)
			r.Post("/auth/password", a.changePassword)

			r.Get("/overview", a.overview)

			r.Route("/credentials", func(r chi.Router) {
				r.Get("/", a.listCredentials)
				r.Get("/{id}/zones", a.getCredentialZones)
				r.Post("/{id}/sync", a.syncCredential)

				// 凭据的写操作会放大权限，限管理员。
				r.Group(func(r chi.Router) {
					r.Use(a.requireAdmin)
					r.Post("/", a.createCredential)
					r.Post("/policy-preview", a.previewPolicy)
					r.Post("/provision", a.provisionCredential)
					r.Delete("/{id}", a.deleteCredential)
				})
			})

			r.Route("/acme-accounts", func(r chi.Router) {
				r.Get("/", a.listACMEAccounts)
				r.With(a.requireAdmin).Post("/", a.createACMEAccount)
			})

			r.Route("/certificates", func(r chi.Router) {
				r.Get("/", a.listCertConfigs)
				r.Post("/", a.createCertConfig)
				r.Post("/resolve", a.resolveDomains)
				r.Get("/{id}", a.getCertConfig)
				r.Post("/{id}/issue", a.issueNow)
				r.Get("/{id}/versions", a.listCertVersions)
				r.Get("/{id}/bindings", a.listBindings)
				r.Post("/{id}/bindings", a.addBinding)
				r.Delete("/{id}/bindings/{targetID}", a.removeBinding)
				r.With(a.requireAdmin).Delete("/{id}", a.deleteCertConfig)
			})

			r.Route("/targets", func(r chi.Router) {
				r.Get("/", a.listTargets)
				r.Post("/", a.createTarget)
				r.With(a.requireAdmin).Delete("/{id}", a.deleteTarget)
			})

			r.Route("/servers", func(r chi.Router) {
				r.Get("/", a.listServers)
				r.Post("/{id}/detect", a.detectServer)
				// 新增与删除主机会改变系统能触达的范围，限管理员。
				r.With(a.requireAdmin).Post("/", a.createServer)
				r.With(a.requireAdmin).Delete("/{id}", a.deleteServer)
			})

			r.Route("/services", func(r chi.Router) {
				r.Get("/", a.listServices)
				r.Post("/{id}/dry-run", a.dryRunService)
				// 自定义命令是特权操作：它决定了远端要执行什么。
				r.With(a.requireAdmin).Put("/{id}/commands", a.updateServiceCommands)
			})

			r.Route("/health-checks", func(r chi.Router) {
				r.Get("/", a.listHealth)
				r.Post("/scan", a.runHealthScan)
				r.Post("/probe", a.probeOnce)
			})

			r.Route("/monitors", func(r chi.Router) {
				r.Get("/", a.listMonitorDomains)
				r.Post("/", a.createMonitorDomain)
				r.Delete("/{id}", a.deleteMonitorDomain)
			})

			r.Route("/notify-channels", func(r chi.Router) {
				r.Get("/", a.listNotifyChannels)
				r.Post("/{id}/test", a.testNotifyChannel)
				// 渠道配置里含 Webhook token，写操作限管理员。
				r.With(a.requireAdmin).Post("/", a.createNotifyChannel)
				r.With(a.requireAdmin).Delete("/{id}", a.deleteNotifyChannel)
			})

			r.Route("/jobs", func(r chi.Router) {
				r.Get("/", a.listJobs)
				r.Get("/{id}", a.getJob)
				r.Get("/{id}/logs", a.jobLogs)
			})
		})
	})

	return r
}
