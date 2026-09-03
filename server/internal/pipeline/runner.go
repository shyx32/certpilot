// Package pipeline 编排证书的签发、部署与生效校验。
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/certpilot/server/internal/acme"
	"github.com/certpilot/server/internal/dnsx"
	"github.com/certpilot/server/internal/domain"
	"github.com/certpilot/server/internal/events"
	"github.com/certpilot/server/internal/provider/deploy"
	"github.com/certpilot/server/internal/provider/deploy/sshnginx"
	dnsprov "github.com/certpilot/server/internal/provider/dns"
	"github.com/certpilot/server/internal/store"
)

// Runner 执行一个签发/续期任务。
type Runner struct {
	store      *store.Store
	hub        *events.Hub
	challenges acme.HTTPChallenge
	// KeepVersions 是每个配置保留的历史证书版本数。
	KeepVersions int
}

func New(s *store.Store, hub *events.Hub, challenges acme.HTTPChallenge) *Runner {
	return &Runner{store: s, hub: hub, challenges: challenges, KeepVersions: 5}
}

// Run 按状态机推进一个任务，并把每一步写进日志与事件流。
func (r *Runner) Run(ctx context.Context, job *store.Job) error {
	if job.RefID == nil {
		return r.fail(ctx, job, errors.New("任务缺少证书配置 ID"), domain.RetryNever)
	}
	cfg, err := r.store.GetCertConfig(ctx, *job.RefID)
	if err != nil {
		return r.fail(ctx, job, fmt.Errorf("读取证书配置失败: %w", err), domain.RetryNever)
	}

	r.log(ctx, job, domain.StagePreflight, "info",
		fmt.Sprintf("开始处理 %s（%s）", cfg.Name, strings.Join(cfg.Domains, ", ")))

	// ---- PREFLIGHT ----
	zones, err := r.preflight(ctx, job, cfg)
	if err != nil {
		return r.fail(ctx, job, err, domain.RetryNever)
	}

	// ---- ORDERING → FINALIZING ----
	// lego 把 Order 创建、challenge 投放、CA 校验与 finalize 封装成一次调用，
	// 因此这几个阶段在日志上通过回调体现，而不是各自独立的状态跃迁。
	r.stage(ctx, job, domain.StageOrdering, "向 CA 创建 Order")

	acct, keyPEM, err := r.store.ACMEAccountKey(ctx, cfg.ACMEAccountID)
	if err != nil {
		return r.fail(ctx, job, fmt.Errorf("读取 CA 账号失败: %w", err), domain.RetryNever)
	}

	result, err := acme.Obtain(ctx, &acme.Account{
		ID:           acct.ID,
		DirectoryURL: acct.DirectoryURL,
		Email:        acct.Email,
		KID:          deref(acct.KID),
		KeyPEM:       keyPEM,
	}, &acme.Request{
		Domains:       cfg.Domains,
		KeyType:       cfg.KeyType,
		ChallengeType: cfg.ChallengeType,
		Zones:         zones,
		ResolveProvider: func(credentialID int64) (dnsprov.Provider, error) {
			return r.dnsProvider(ctx, credentialID)
		},
		OnRecord: func(m *dnsx.Match, _ string) {
			r.stage(ctx, job, domain.StageChallenge,
				fmt.Sprintf("已写入 TXT 记录 %s（zone %s）", m.FQDN, m.Zone.Name))
		},
		HTTPChallenge: r.challenges,
		OnToken: func(d, token string) {
			r.stage(ctx, job, domain.StageChallenge,
				fmt.Sprintf("已登记 %s 的验证 token（等待 CA 回取）", d))
		},
	})
	if err != nil {
		_ = r.store.RecordFailure(ctx, cfg.ID)
		return r.fail(ctx, job, err, classify(err))
	}

	// 首次注册后记下账号 URL，后续复用而不重复注册。
	if acct.KID == nil || *acct.KID == "" {
		if result.AccountKID != "" {
			_ = r.store.SetACMEAccountKID(ctx, acct.ID, result.AccountKID)
		}
	}

	// ---- ISSUED ----
	r.stage(ctx, job, domain.StageFinalizing, "已下载证书链")

	leaf := result.Leaf
	fingerprint := deploy.Fingerprint(leaf)
	certID, err := r.store.SaveCertificate(ctx, &store.Certificate{
		CertConfigID: cfg.ID,
		Serial:       leaf.SerialNumber.Text(16),
		Fingerprint:  fingerprint,
		CertPEM:      string(result.CertPEM),
		ChainPEM:     string(result.ChainPEM),
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		Issuer:       leaf.Issuer.CommonName,
	}, result.KeyPEM, result.OrderURL)
	if err != nil {
		return r.fail(ctx, job, fmt.Errorf("保存证书失败: %w", err), domain.RetryBackoff)
	}
	_ = r.store.ResetFailure(ctx, cfg.ID)

	r.stage(ctx, job, domain.StageIssued, fmt.Sprintf(
		"证书已签发，有效期至 %s，指纹 %s",
		leaf.NotAfter.Format(time.DateOnly), short(fingerprint)))

	if len(result.ChainPEM) == 0 {
		// 缺中间证书时浏览器往往正常，部分客户端却会失败，值得显式提醒。
		r.log(ctx, job, domain.StageIssued, "warn", "证书链中没有中间证书，部分客户端可能校验失败")
	}

	// ---- DEPLOYING → VERIFIED ----
	bundle := &deploy.Bundle{
		Domains:     cfg.Domains,
		CertPEM:     result.CertPEM,
		ChainPEM:    result.ChainPEM,
		KeyPEM:      result.KeyPEM,
		Fingerprint: fingerprint,
		NotAfter:    leaf.NotAfter,
	}
	if err := r.deployAll(ctx, job, cfg, certID, bundle); err != nil {
		// 部署失败不撤销签发：证书已经是资产，先入库，
		// 失败的目标单独重试，不牵连其他目标。
		return r.fail(ctx, job, err, domain.RetryBackoff)
	}

	_ = r.store.PruneCertificates(ctx, cfg.ID, r.KeepVersions)
	r.stage(ctx, job, domain.StageVerified, "全部目标已确认线上生效")
	return r.store.FinishJob(ctx, job.ID, domain.StageVerified)
}

// preflight 在向 CA 发出任何请求之前，先确认每个域名都能归属到已托管的 zone。
//
// CA 对失败验证有独立配额，把试错留在自己这一侧比留给 CA 便宜得多。
func (r *Runner) preflight(ctx context.Context, job *store.Job, cfg *store.CertConfig) ([]dnsx.Zone, error) {
	r.stage(ctx, job, domain.StagePreflight, "检查域名归属与凭据")

	// HTTP-01 不需要 zone 归属，但要求验证服务可被 CA 取到。
	// 这一步只能提示，真正的可达性由 CA 的实际回取决定。
	if cfg.ChallengeType == "http-01" {
		if r.challenges == nil {
			return nil, errors.New("HTTP-01 验证服务不可用")
		}
		for _, d := range cfg.Domains {
			if strings.HasPrefix(d, "*.") {
				return nil, fmt.Errorf("通配符域名 %s 只能使用 DNS-01 验证", d)
			}
		}
		r.log(ctx, job, domain.StagePreflight, "info",
			"使用 HTTP-01 集中验证：请确保各域名的 /.well-known/acme-challenge/ 已重定向到本服务，且 80 端口可从公网访问")
		return nil, nil
	}

	zones, err := r.store.AllZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("读取 zone 清单失败: %w", err)
	}
	matches, err := dnsx.ResolveAll(cfg.Domains, zones)
	if err != nil {
		return nil, fmt.Errorf("域名归属检查未通过: %w", err)
	}
	for _, m := range matches {
		r.log(ctx, job, domain.StagePreflight, "info",
			fmt.Sprintf("%s → zone %s，记录 %s", m.Domain, m.Zone.Name, m.RecordName))
	}
	return zones, nil
}

// deployAll 把证书推送到全部绑定目标。
//
// 单个目标失败不影响其余目标——一个坏目标不该拖垮整张证书的部署。
func (r *Runner) deployAll(ctx context.Context, job *store.Job, cfg *store.CertConfig,
	certID int64, b *deploy.Bundle) error {

	bindings, err := r.store.BindingsOf(ctx, cfg.ID)
	if err != nil {
		return err
	}
	if len(bindings) == 0 {
		r.log(ctx, job, domain.StageDeploying, "warn", "没有绑定任何部署目标，证书仅保存在库中")
		return nil
	}

	r.stage(ctx, job, domain.StageDeploying, fmt.Sprintf("开始部署到 %d 个目标", len(bindings)))

	var failures []string
	for _, bind := range bindings {
		if err := r.deployOne(ctx, job, cfg, bind, certID, b); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", bind.TargetName, err))
			_ = r.store.MarkBinding(ctx, cfg.ID, bind.DeployTargetID, 0, "failed", err.Error())
			r.log(ctx, job, domain.StageDeploying, "error",
				fmt.Sprintf("目标 %s 部署失败: %v", bind.TargetName, err))
			continue
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d/%d 个目标未完成: %s",
			len(failures), len(bindings), strings.Join(failures, "; "))
	}
	return nil
}

func (r *Runner) deployOne(ctx context.Context, job *store.Job, cfg *store.CertConfig,
	bind *store.Binding, certID int64, b *deploy.Bundle) error {

	target, err := r.store.GetDeployTarget(ctx, bind.DeployTargetID)
	if err != nil {
		return err
	}
	factory, ok := deploy.Lookup(target.Kind)
	if !ok {
		return fmt.Errorf("未知的部署目标类型 %q", target.Kind)
	}

	var secret []byte
	if target.CredentialID != nil {
		if secret, err = r.store.Secret(ctx, *target.CredentialID); err != nil {
			return fmt.Errorf("读取凭据失败: %w", err)
		}
	}

	// SSH 类目标需要主机与服务信息，它们存在别的表里，
	// 由编排层读出后注入 params——这样 provider 本身仍然无状态。
	params := target.Params
	if target.ServerServiceID != nil {
		if params, err = r.enrichSSHParams(ctx, params, *target.ServerServiceID, cfg); err != nil {
			return err
		}
	}

	d, err := factory(ctx, params, secret)
	if err != nil {
		return err
	}

	if err := d.Deploy(ctx, b); err != nil {
		return err
	}
	_ = r.store.MarkBinding(ctx, cfg.ID, bind.DeployTargetID, certID, "deployed", "")
	r.log(ctx, job, domain.StageDeploying, "info", fmt.Sprintf("目标 %s 已下发", target.Name))

	// 下发成功不等于生效：CDN 有分钟级延迟，必须拨测确认。
	if err := r.verifyWithRetry(ctx, job, d, b, target.Name); err != nil {
		// 已下发但未确认生效，这个状态比单纯失败更需要人看一眼。
		_ = r.store.MarkBinding(ctx, cfg.ID, bind.DeployTargetID, certID, "deployed", err.Error())
		return err
	}
	_ = r.store.MarkBinding(ctx, cfg.ID, bind.DeployTargetID, certID, "verified", "")
	r.log(ctx, job, domain.StageDeploying, "info", fmt.Sprintf("目标 %s 已确认生效", target.Name))
	return nil
}

// verifyWithRetry 在目标的生效窗口内反复拨测。
func (r *Runner) verifyWithRetry(ctx context.Context, job *store.Job,
	d deploy.Deployer, b *deploy.Bundle, name string) error {

	window := deploy.DefaultWindow
	if h, ok := d.(deploy.WindowHinter); ok {
		window = h.RetryWindow()
	}

	deadline := time.Now().Add(window.Max)
	wait := window.Initial
	var lastErr error
	for attempt := 1; ; attempt++ {
		if lastErr = d.Verify(ctx, b); lastErr == nil {
			return nil
		}
		if time.Now().Add(wait).After(deadline) {
			break
		}
		r.log(ctx, job, domain.StageDeploying, "info",
			fmt.Sprintf("目标 %s 尚未生效，%s 后重试（第 %d 次）", name, wait, attempt))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if wait *= 2; wait > time.Minute {
			wait = time.Minute
		}
	}
	return fmt.Errorf("在 %s 内未确认生效: %w", window.Max, lastErr)
}

// enrichSSHParams 把主机连接信息与探测到的服务形态注入部署参数。
func (r *Runner) enrichSSHParams(ctx context.Context, raw json.RawMessage,
	serviceID int64, cfg *store.CertConfig) (json.RawMessage, error) {

	rec, err := r.store.GetService(ctx, serviceID)
	if err != nil {
		return nil, fmt.Errorf("读取服务信息失败: %w", err)
	}
	host, err := r.store.GetSSHHost(ctx, rec.SSHHostID)
	if err != nil {
		return nil, fmt.Errorf("读取主机信息失败: %w", err)
	}

	var m map[string]json.RawMessage
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("部署目标配置无法解析: %w", err)
		}
	}
	if m == nil {
		m = map[string]json.RawMessage{}
	}

	spec := sshnginx.HostSpec{
		Host: host.Host, Port: host.Port, User: host.Username,
	}
	if host.HostKeyFP != nil {
		spec.Fingerprint = *host.HostKeyFP
	}
	if host.JumpHostID != nil {
		if jump, err := r.store.GetSSHHost(ctx, *host.JumpHostID); err == nil {
			js := &sshnginx.HostSpec{Host: jump.Host, Port: jump.Port, User: jump.Username}
			if jump.HostKeyFP != nil {
				js.Fingerprint = *jump.HostKeyFP
			}
			if sec, err := r.store.Secret(ctx, jump.CredentialID); err == nil {
				js2 := json.RawMessage(sec)
				spec.JumpSecret = js2
			}
			spec.Jump = js
		}
	}

	m["host"], _ = json.Marshal(spec)
	m["service"], _ = json.Marshal(rec.ToService())
	// 没有显式配置拨测域名时，用证书自身的域名（去掉通配符）。
	if _, ok := m["verify_domains"]; !ok {
		m["verify_domains"], _ = json.Marshal(verifiableDomains(cfg.Domains))
	}
	return json.Marshal(m)
}

// verifiableDomains 过滤出可以直接拨测的域名。
//
// 通配符本身不能解析，跳过它——否则每次都会因为连不上而判定未生效。
func verifiableDomains(domains []string) []string {
	out := []string{}
	for _, d := range domains {
		if !strings.HasPrefix(d, "*.") {
			out = append(out, d)
		}
	}
	return out
}

func (r *Runner) dnsProvider(ctx context.Context, credentialID int64) (dnsprov.Provider, error) {
	cred, err := r.store.GetCredential(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	factory, ok := dnsprov.Lookup(cred.Kind)
	if !ok {
		return nil, fmt.Errorf("未知的 DNS provider 类型 %q", cred.Kind)
	}
	secret, err := r.store.Secret(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	return factory(ctx, secret)
}

// classify 判断失败是否值得重试。
//
// 鉴权与配置类错误重试只会浪费时间、消耗 CA 的失败配额，
// 甚至触发风控，所以直接转人工。
func classify(err error) domain.RetryClass {
	// CA 明确拒绝的错误（域名不合法、CAA 不允许、邮箱被拒）重试也不会变，
	// 只会耗光 CA 的失败配额。这一判断基于 problem type，比关键词匹配可靠。
	if acme.IsPermanent(err) {
		return domain.RetryNever
	}

	s := strings.ToLower(err.Error())

	// 速率限制是暂时的，必须退避重试而不是放弃——放弃会让证书静静过期。
	// 这一条要排在不可重试的判断之前，否则会被下面的关键词误伤。
	for _, kw := range []string{"速率限制", "ratelimited", "throttling", "过于频繁"} {
		if strings.Contains(s, kw) {
			return domain.RetryBackoff
		}
	}

	// 鉴权与配置类错误重试只会浪费时间、消耗 CA 的失败配额，甚至触发风控。
	for _, kw := range []string{
		"forbidden", "unauthorized", "invalidaccesskey", "signaturedoesnotmatch",
		"nopermission", "accessdenied", "unknown provider",
		"无法归属", "不存在", "不正确", "权限", "邮箱不被",
	} {
		if strings.Contains(s, kw) {
			return domain.RetryNever
		}
	}
	return domain.RetryBackoff
}

func (r *Runner) stage(ctx context.Context, job *store.Job, st domain.Stage, msg string) {
	_ = r.store.SetStage(ctx, job.ID, st)
	r.log(ctx, job, st, "info", msg)
}

func (r *Runner) log(ctx context.Context, job *store.Job, st domain.Stage, level, msg string) {
	entry, err := r.store.AppendLog(ctx, job.ID, st, level, msg)
	if err != nil {
		slog.Error("写入任务日志失败", "job", job.ID, "err", err)
		return
	}
	r.hub.Publish(events.Event{
		Type: "job_log", JobID: job.ID, Stage: string(st),
		Level: level, Message: msg, At: entry.At.Format(time.RFC3339),
	})
}

func (r *Runner) fail(ctx context.Context, job *store.Job, cause error, class domain.RetryClass) error {
	r.log(ctx, job, domain.StageFailed, "error", cause.Error())
	r.hub.Publish(events.Event{
		Type: "job_state", JobID: job.ID, Stage: string(domain.StageFailed),
		Message: cause.Error(),
	})
	return r.store.FailJob(ctx, job, cause.Error(), class)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func short(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}
