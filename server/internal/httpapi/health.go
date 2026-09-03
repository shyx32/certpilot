package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/certpilot/server/internal/health"
	"github.com/certpilot/server/internal/notify"
	"github.com/certpilot/server/internal/store"
)

func (a *API) listHealth(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.LatestHealth(r.Context())
	if err != nil {
		failErr(w, err, "读取巡检结果失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// runHealthScan 手工触发一次巡检。
func (a *API) runHealthScan(w http.ResponseWriter, r *http.Request) {
	id, err := a.store.EnqueueJob(r.Context(), "health_scan", nil, nil)
	if err != nil {
		failErr(w, err, "投递巡检任务失败")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]int64{"job_id": id})
}

// probeOnce 立刻拨测一个域名并原样返回判读结果。
//
// 用于「这个域名现在到底什么情况」这类即时排查，不写入巡检历史。
func (a *API) probeOnce(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Port   int    `json:"port"`
		SNI    string `json:"sni"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Domain == "" {
		fail(w, http.StatusBadRequest, "请填写要拨测的域名")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	res, err := health.NewProber().Probe(ctx, health.Target{
		Domain: req.Domain, Port: req.Port, SNI: req.SNI,
	})
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ---------- 仅监控的域名 ----------

func (a *API) listMonitorDomains(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListMonitorDomains(r.Context())
	if err != nil {
		failErr(w, err, "读取监控域名失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) createMonitorDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Port   int    `json:"port"`
		SNI    string `json:"sni"`
		Note   string `json:"note"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Domain == "" {
		fail(w, http.StatusBadRequest, "域名不能为空")
		return
	}
	m := &store.MonitorDomain{Domain: req.Domain, Port: req.Port}
	if req.SNI != "" {
		m.SNI = &req.SNI
	}
	if req.Note != "" {
		m.Note = &req.Note
	}
	id, err := a.store.CreateMonitorDomain(r.Context(), m)
	if err != nil {
		failErr(w, err, "保存监控域名失败")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (a *API) deleteMonitorDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := a.store.DeleteMonitorDomain(r.Context(), id); err != nil {
		failErr(w, err, "删除监控域名失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- 通知渠道 ----------

func (a *API) listNotifyChannels(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListNotifyChannels(r.Context())
	if err != nil {
		failErr(w, err, "读取通知渠道失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"channels": list,
		"kinds":    notify.Kinds(),
		"events":   eventOptions(),
	})
}

func eventOptions() []map[string]string {
	out := make([]map[string]string, 0)
	for _, e := range notify.KnownEvents() {
		out = append(out, map[string]string{"value": string(e), "label": e.Label()})
	}
	return out
}

type notifyChannelReq struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	URL     string   `json:"url"`
	Keyword string   `json:"keyword"`
	Events  []string `json:"events"`
}

func (r *notifyChannelReq) config() ([]byte, error) {
	return json.Marshal(map[string]string{"url": r.URL, "keyword": r.Keyword})
}

func (a *API) createNotifyChannel(w http.ResponseWriter, r *http.Request) {
	var req notifyChannelReq
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || req.Kind == "" || req.URL == "" {
		fail(w, http.StatusBadRequest, "名称、类型与 Webhook 地址都是必填项")
		return
	}
	if _, ok := notify.Lookup(req.Kind); !ok {
		fail(w, http.StatusBadRequest, "不支持的渠道类型："+req.Kind)
		return
	}
	cfg, err := req.config()
	if err != nil {
		failErr(w, err, "构造渠道配置失败")
		return
	}
	id, err := a.store.CreateNotifyChannel(r.Context(),
		&store.NotifyChannel{Name: req.Name, Kind: req.Kind, Events: req.Events}, cfg)
	if err != nil {
		failErr(w, err, "保存通知渠道失败")
		return
	}
	a.store.Audit(r.Context(), actorOf(r), "create_notify_channel", req.Name, nil)
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// testNotifyChannel 立刻发一条测试消息。
//
// 通知渠道最常见的失败是「配好了但群里收不到」（钉钉关键词、token 过期），
// 而这类问题只有真发一条才能暴露。
func (a *API) testNotifyChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	ctx := r.Context()
	list, err := a.store.ListNotifyChannels(ctx)
	if err != nil {
		failErr(w, err, "读取通知渠道失败")
		return
	}
	var target *store.NotifyChannel
	for _, c := range list {
		if c.ID == id {
			target = c
		}
	}
	if target == nil {
		fail(w, http.StatusNotFound, "渠道不存在")
		return
	}

	cfg, err := a.store.NotifyConfig(ctx, id)
	if err != nil {
		failErr(w, err, "读取渠道配置失败")
		return
	}
	factory, ok2 := notify.Lookup(target.Kind)
	if !ok2 {
		fail(w, http.StatusBadRequest, "不支持的渠道类型："+target.Kind)
		return
	}
	sender, err := factory(cfg)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}

	sendCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err = sender.Send(sendCtx, &notify.Message{
		Event: notify.EventHealth,
		Level: notify.LevelInfo,
		Title: "CertPilot 测试消息",
		Lines: []string{"看到这条说明渠道配置正确，证书相关事件会发到这里。"},
	})
	if err != nil {
		fail(w, http.StatusBadGateway, "发送失败："+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *API) deleteNotifyChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := a.store.DeleteNotifyChannel(r.Context(), id); err != nil {
		failErr(w, err, "删除通知渠道失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
