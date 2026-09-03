package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// publicStatus 是不需要登录的只读看板数据。
//
// 只暴露域名、状态与剩余天数。证书路径、颁发者、任务日志这些内部信息
// 一律不出现在这里——分享链接的持有者不该看到运维细节。
func (a *API) publicStatus(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	link, err := a.store.ResolveShareToken(r.Context(), token)
	if err != nil {
		// 不区分「不存在」与「已过期」，避免泄露 token 是否曾经有效。
		fail(w, http.StatusNotFound, "链接无效或已过期")
		return
	}

	rows, err := a.store.PublicHealth(r.Context())
	if err != nil {
		failErr(w, err, "读取状态失败")
		return
	}

	var danger, warn, ok int
	for _, r := range rows {
		switch r.Severity {
		case "danger":
			danger++
		case "warn":
			warn++
		default:
			ok++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":         link.Name,
		"domains":      rows,
		"ok":           ok,
		"warn":         warn,
		"danger":       danger,
		"generated_at": time.Now().Format(time.RFC3339),
	})
}

func (a *API) listShareLinks(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListShareLinks(r.Context())
	if err != nil {
		failErr(w, err, "读取分享链接失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) createShareLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		TTLDays int    `json:"ttl_days"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" {
		req.Name = "证书状态"
	}
	ttl := time.Duration(req.TTLDays) * 24 * time.Hour
	link, err := a.store.CreateShareLink(r.Context(), req.Name, actorOf(r), ttl)
	if err != nil {
		failErr(w, err, "创建分享链接失败")
		return
	}
	a.store.Audit(r.Context(), actorOf(r), "create_share_link", req.Name, nil)
	writeJSON(w, http.StatusCreated, link)
}

func (a *API) deleteShareLink(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := a.store.DeleteShareLink(r.Context(), id); err != nil {
		failErr(w, err, "删除分享链接失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
