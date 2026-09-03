package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/certpilot/server/internal/domain"
	dnsprov "github.com/certpilot/server/internal/provider/dns"
	"github.com/certpilot/server/internal/store"
)

// syncZones 刷新某个凭据可管理的 DNS zone 清单。
//
// 它同时兼任凭据健康检查：每天跑一次，AK 失效或权限被收回当天就会暴露，
// 而不是等到六十天后续期时才发现——那时往往已经来不及了。
func (s *Scheduler) syncZones(ctx context.Context, job *store.Job) error {
	var payload struct {
		CredentialID int64 `json:"credential_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return s.store.FailJob(ctx, job, "任务参数无法解析: "+err.Error(), domain.RetryNever)
	}
	if payload.CredentialID == 0 && job.RefID != nil {
		payload.CredentialID = *job.RefID
	}

	n, err := SyncZonesFor(ctx, s.store, payload.CredentialID)
	if err != nil {
		_ = s.store.MarkCredentialChecked(ctx, payload.CredentialID, false, err.Error())
		return s.store.FailJob(ctx, job, err.Error(), domain.RetryBackoff)
	}
	_ = s.store.MarkCredentialChecked(ctx, payload.CredentialID, true, "")
	_, _ = s.store.AppendLog(ctx, job.ID, domain.StageVerified, "info",
		fmt.Sprintf("已同步 %d 个可管理域名", n))
	slog.Info("zone 同步完成", "credential", payload.CredentialID, "zones", n)
	return s.store.FinishJob(ctx, job.ID, domain.StageVerified)
}

// SyncZonesFor 拉取并保存某凭据下的全部 zone。
//
// 独立成函数是因为凭据刚创建时要同步调用一次——用户需要立刻在界面上
// 看到「这个账号能管哪些域名」，而不是等下一轮调度。
func SyncZonesFor(ctx context.Context, st *store.Store, credentialID int64) (int, error) {
	cred, err := st.GetCredential(ctx, credentialID)
	if err != nil {
		return 0, err
	}
	factory, ok := dnsprov.Lookup(cred.Kind)
	if !ok {
		// 不是 DNS 类凭据（例如只用于部署的账号），没有 zone 可同步。
		return 0, nil
	}
	secret, err := st.Secret(ctx, credentialID)
	if err != nil {
		return 0, err
	}
	p, err := factory(ctx, secret)
	if err != nil {
		return 0, err
	}
	lister, ok := p.(dnsprov.ZoneLister)
	if !ok {
		// provider 不支持列举 zone，退化为 PSL 推算，不影响签发。
		return 0, nil
	}
	zones, err := lister.ListZones(ctx)
	if err != nil {
		return 0, err
	}
	for i := range zones {
		zones[i].CredentialID = credentialID
	}
	if err := st.ReplaceZones(ctx, credentialID, zones); err != nil {
		return 0, err
	}
	return len(zones), nil
}
