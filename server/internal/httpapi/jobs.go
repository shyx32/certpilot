package httpapi

import (
	"net/http"
	"time"
)

func (a *API) listJobs(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListJobs(r.Context(), queryInt(r, "limit", 50))
	if err != nil {
		failErr(w, err, "读取任务列表失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) getJob(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	job, err := a.store.GetJob(r.Context(), id)
	if err != nil {
		failErr(w, err, "读取任务失败")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// jobLogs 返回完整日志。
//
// WebSocket 负责增量推送，这个接口负责首次加载与重连补拉——
// 两者配合才能保证用户看到的日志不缺片段。
func (a *API) jobLogs(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	logs, err := a.store.JobLogs(r.Context(), id)
	if err != nil {
		failErr(w, err, "读取任务日志失败")
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

// overview 是仪表盘的数据源：先给结论，再给明细。
func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	certs, err := a.store.ListCertConfigs(ctx)
	if err != nil {
		failErr(w, err, "读取证书列表失败")
		return
	}

	var expiringSoon, expired, pending int
	domains := map[string]bool{}
	// buckets 按未来 13 周分桶，用来发现「某一周集中到期」。
	buckets := make([]int, 13)
	for _, c := range certs {
		for _, d := range c.Domains {
			domains[d] = true
		}
		if c.DaysLeft == nil {
			pending++
			continue
		}
		switch d := *c.DaysLeft; {
		case d < 0:
			expired++
		case d < 7:
			expired++
		case d <= 30:
			expiringSoon++
		}
		if wk := *c.DaysLeft / 7; wk >= 0 && wk < len(buckets) {
			buckets[wk]++
		}
	}

	jobs, err := a.store.ListJobs(ctx, 10)
	if err != nil {
		failErr(w, err, "读取任务列表失败")
		return
	}
	var failedJobs int
	for _, j := range jobs {
		if j.State == "failed" {
			failedJobs++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"cert_count":    len(certs),
		"domain_count":  len(domains),
		"expiring_soon": expiringSoon,
		"expired":       expired,
		"never_issued":  pending,
		"failed_jobs":   failedJobs,
		"buckets":       buckets,
		"certs":         certs,
		"recent_jobs":   jobs,
		"generated_at":  time.Now().Format(time.RFC3339),
	})
}
