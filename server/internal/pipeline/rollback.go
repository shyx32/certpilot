package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/certpilot/server/internal/domain"
	"github.com/certpilot/server/internal/notify"
	"github.com/certpilot/server/internal/provider/deploy"
	"github.com/certpilot/server/internal/store"
)

// RollbackPayload 是回滚任务的参数。
type RollbackPayload struct {
	CertificateID int64 `json:"certificate_id"`
}

// Rollback 把某个历史版本重新部署到全部绑定目标。
//
// 证书版本化保存正是为了这一刻：新证书部署后发现问题，
// 能一键退回上一个已知可用的版本，而不必等重新签发。
//
// 注意它不撤销签发记录——库里最新一版仍然是新证书，
// 只是线上跑的换回了旧版。这样下一次续期仍从正确的基线出发。
func (r *Runner) Rollback(ctx context.Context, job *store.Job) error {
	var payload RollbackPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return r.fail(ctx, job, fmt.Errorf("回滚参数无法解析: %w", err), domain.RetryNever)
	}
	if payload.CertificateID == 0 {
		return r.fail(ctx, job, errors.New("回滚任务缺少证书版本 ID"), domain.RetryNever)
	}

	cert, keyPEM, err := r.store.CertificateByID(ctx, payload.CertificateID)
	if err != nil {
		return r.fail(ctx, job, fmt.Errorf("读取证书版本失败: %w", err), domain.RetryNever)
	}
	cfg, err := r.store.GetCertConfig(ctx, cert.CertConfigID)
	if err != nil {
		return r.fail(ctx, job, fmt.Errorf("读取证书配置失败: %w", err), domain.RetryNever)
	}

	r.stage(ctx, job, domain.StageDeploying, fmt.Sprintf(
		"回滚 %s 到 %s 签发的版本（指纹 %s，有效期至 %s）",
		cfg.Name, cert.CreatedAt.Format(time.DateOnly), short(cert.Fingerprint),
		cert.NotAfter.Format(time.DateOnly)))

	if time.Now().After(cert.NotAfter) {
		// 回滚到一张已过期的证书没有意义，而且会让线上立刻不可用。
		return r.fail(ctx, job, fmt.Errorf(
			"这一版已于 %s 过期，回滚过去会让线上立刻不可用",
			cert.NotAfter.Format(time.DateOnly)), domain.RetryNever)
	}

	bundle := &deploy.Bundle{
		Domains:     cfg.Domains,
		CertPEM:     []byte(cert.CertPEM),
		ChainPEM:    []byte(cert.ChainPEM),
		KeyPEM:      keyPEM,
		Fingerprint: cert.Fingerprint,
		NotAfter:    cert.NotAfter,
	}
	if err := r.deployAll(ctx, job, cfg, cert.ID, bundle); err != nil {
		return r.fail(ctx, job, err, domain.RetryBackoff)
	}

	r.stage(ctx, job, domain.StageVerified, "回滚完成，线上已确认换回该版本")
	r.notify(ctx, &notify.Message{
		Event: notify.EventDeployFailed, // 回滚本身就意味着出过问题，归入同一订阅
		Level: notify.LevelWarn,
		Title: cfg.Name + " 已回滚到历史版本",
		Lines: []string{
			"指纹：" + short(cert.Fingerprint),
			"该版本有效期至：" + cert.NotAfter.Format(time.DateOnly),
			"库中最新版本未变，下次续期仍从最新基线出发。",
		},
	})
	return r.store.FinishJob(ctx, job.ID, domain.StageVerified)
}
