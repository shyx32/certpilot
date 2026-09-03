package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// metrics 以 Prometheus exposition 格式导出指标。
//
// 手写格式而不引入客户端库：这里只有四个指标，且都是查询时现算的，
// 为此背上一个依赖不划算。
//
// 最有价值的是 certpilot_cert_expiry_timestamp_seconds——
// 把它接进已有的告警体系，就不必依赖本系统自己的通知也能收到到期提醒。
func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	certs, jobs, health, err := a.store.MetricsSnapshot(r.Context())
	if err != nil {
		http.Error(w, "# 读取指标失败\n", http.StatusInternalServerError)
		return
	}

	var b strings.Builder
	now := time.Now()

	b.WriteString("# HELP certpilot_cert_expiry_timestamp_seconds 证书到期时间（Unix 秒）。\n")
	b.WriteString("# TYPE certpilot_cert_expiry_timestamp_seconds gauge\n")
	for _, c := range certs {
		if c.NotAfter == nil {
			continue
		}
		fmt.Fprintf(&b, "certpilot_cert_expiry_timestamp_seconds{name=%q,domain=%q} %d\n",
			escape(c.Name), escape(firstDomain(c.Domains)), c.NotAfter.Unix())
	}

	b.WriteString("# HELP certpilot_cert_days_left 证书剩余天数。\n")
	b.WriteString("# TYPE certpilot_cert_days_left gauge\n")
	for _, c := range certs {
		if c.NotAfter == nil {
			continue
		}
		fmt.Fprintf(&b, "certpilot_cert_days_left{name=%q,domain=%q} %.1f\n",
			escape(c.Name), escape(firstDomain(c.Domains)), c.NotAfter.Sub(now).Hours()/24)
	}

	b.WriteString("# HELP certpilot_certs_total 托管的证书配置数量。\n")
	b.WriteString("# TYPE certpilot_certs_total gauge\n")
	var enabled, pending int
	for _, c := range certs {
		if c.Enabled {
			enabled++
		}
		if c.NotAfter == nil {
			pending++
		}
	}
	fmt.Fprintf(&b, "certpilot_certs_total{state=\"enabled\"} %d\n", enabled)
	fmt.Fprintf(&b, "certpilot_certs_total{state=\"never_issued\"} %d\n", pending)

	b.WriteString("# HELP certpilot_jobs_total 各状态的任务数量。\n")
	b.WriteString("# TYPE certpilot_jobs_total gauge\n")
	for _, state := range []string{"queued", "running", "succeeded", "failed", "canceled"} {
		fmt.Fprintf(&b, "certpilot_jobs_total{state=%q} %d\n", state, jobs[state])
	}

	b.WriteString("# HELP certpilot_health_domains 最近一次巡检中各严重级别的域名数量。\n")
	b.WriteString("# TYPE certpilot_health_domains gauge\n")
	for _, sev := range []string{"ok", "info", "warn", "danger"} {
		fmt.Fprintf(&b, "certpilot_health_domains{severity=%q} %d\n", sev, health[sev])
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func firstDomain(d []string) string {
	if len(d) == 0 {
		return ""
	}
	return d[0]
}

// escape 处理标签值里的特殊字符，避免生成出无法解析的指标。
func escape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}
