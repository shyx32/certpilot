package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/certpilot/server/internal/acme"
	"github.com/certpilot/server/internal/dnsx"
	"github.com/certpilot/server/internal/store"
)

type createCertReq struct {
	Name            string   `json:"name"`
	Domains         []string `json:"domains"`
	KeyType         string   `json:"key_type"`
	ChallengeType   string   `json:"challenge_type"`
	ACMEAccountID   int64    `json:"acme_account_id"`
	RenewBeforeDays int      `json:"renew_before_days"`
	TargetIDs       []int64  `json:"target_ids"`
}

func (a *API) createCertConfig(w http.ResponseWriter, r *http.Request) {
	var req createCertReq
	if !decode(w, r, &req) {
		return
	}
	req.Domains = cleanDomains(req.Domains)
	if req.Name == "" || len(req.Domains) == 0 {
		fail(w, http.StatusBadRequest, "名称与至少一个域名都是必填项")
		return
	}
	if req.KeyType == "" {
		req.KeyType = "EC256"
	}
	if req.ChallengeType == "" {
		req.ChallengeType = "dns-01"
	}
	if req.RenewBeforeDays <= 0 {
		req.RenewBeforeDays = 30
	}
	if req.ChallengeType != "dns-01" && req.ChallengeType != "http-01" {
		fail(w, http.StatusBadRequest, "验证方式只支持 dns-01 或 http-01")
		return
	}
	// 通配符只能走 DNS-01，这是 ACME 的规定而非实现限制。
	if req.ChallengeType != "dns-01" && hasWildcard(req.Domains) {
		fail(w, http.StatusBadRequest, "通配符域名只能使用 DNS-01 验证")
		return
	}

	ctx := r.Context()
	id, err := a.store.CreateCertConfig(ctx, &store.CertConfig{
		Name: req.Name, Domains: req.Domains, KeyType: req.KeyType,
		ChallengeType: req.ChallengeType, ACMEAccountID: req.ACMEAccountID,
		RenewBeforeDays: req.RenewBeforeDays, Enabled: true,
	})
	if err != nil {
		failErr(w, err, "创建证书配置失败")
		return
	}
	for _, tid := range req.TargetIDs {
		if err := a.store.BindTarget(ctx, id, tid); err != nil {
			failErr(w, err, "绑定部署目标失败")
			return
		}
	}
	cfg, err := a.store.GetCertConfig(ctx, id)
	if err != nil {
		failErr(w, err, "读取证书配置失败")
		return
	}
	writeJSON(w, http.StatusCreated, cfg)
}

func (a *API) listCertConfigs(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListCertConfigs(r.Context())
	if err != nil {
		failErr(w, err, "读取证书列表失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) getCertConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	cfg, err := a.store.GetCertConfig(r.Context(), id)
	if err != nil {
		failErr(w, err, "读取证书配置失败")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (a *API) deleteCertConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := a.store.DeleteCertConfig(r.Context(), id); err != nil {
		failErr(w, err, "删除证书配置失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// issueNow 手工触发一次签发。
func (a *API) issueNow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	cfg, err := a.store.GetCertConfig(r.Context(), id)
	if err != nil {
		failErr(w, err, "读取证书配置失败")
		return
	}
	kind := "renew"
	if cfg.NotAfter == nil {
		kind = "issue"
	}
	jobID, err := a.store.EnqueueJob(r.Context(), kind, &id, nil)
	if err != nil {
		failErr(w, err, "投递任务失败")
		return
	}
	// 手工触发意味着人已经在处理，清掉失败冷却让它立刻能跑。
	_ = a.store.ResetFailure(r.Context(), id)
	writeJSON(w, http.StatusAccepted, map[string]int64{"job_id": jobID})
}

func (a *API) listCertVersions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	list, err := a.store.ListCertificates(r.Context(), id)
	if err != nil {
		failErr(w, err, "读取证书版本失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// resolveDomains 在用户输入域名的当下就告诉他能不能签、用哪个账号签。
//
// 这把「提交之后看日志排查失败原因」提前成了「输入时就知道结果」，
// 是自动识别最实际的收益。
func (a *API) resolveDomains(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains []string `json:"domains"`
	}
	if !decode(w, r, &req) {
		return
	}
	req.Domains = cleanDomains(req.Domains)
	if len(req.Domains) == 0 {
		fail(w, http.StatusBadRequest, "请至少输入一个域名")
		return
	}

	zones, err := a.store.AllZones(r.Context())
	if err != nil {
		failErr(w, err, "读取域名清单失败")
		return
	}
	creds, err := a.store.ListCredentials(r.Context())
	if err != nil {
		failErr(w, err, "读取凭据失败")
		return
	}
	names := map[int64]string{}
	for _, c := range creds {
		names[c.ID] = c.Name
	}

	type item struct {
		Domain     string `json:"domain"`
		OK         bool   `json:"ok"`
		Zone       string `json:"zone,omitempty"`
		Record     string `json:"record,omitempty"`
		Credential string `json:"credential,omitempty"`
		Reason     string `json:"reason,omitempty"`
	}
	out := make([]item, 0, len(req.Domains))
	for _, d := range req.Domains {
		m, err := dnsx.ResolveZone(d, zones)
		if err != nil {
			out = append(out, item{Domain: d, OK: false, Reason: reasonFor(err)})
			continue
		}
		out = append(out, item{
			Domain: d, OK: true, Zone: m.Zone.Name, Record: m.RecordName,
			Credential: names[m.Zone.CredentialID],
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// reasonFor 把内部错误翻译成使用者能据以行动的说明。
func reasonFor(err error) string {
	switch {
	case strings.Contains(err.Error(), dnsx.ErrNoZone.Error()):
		return "没有找到能管理该域名的 DNS 账号。请添加对应凭据，或改用 HTTP-01 验证。"
	case strings.Contains(err.Error(), dnsx.ErrAmbiguous.Error()):
		return "有多个凭据都托管了这个域名，请指定使用哪一个。"
	default:
		return "域名格式不合法。"
	}
}

func cleanDomains(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

func hasWildcard(domains []string) bool {
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			return true
		}
	}
	return false
}

// ---------- 绑定 ----------

func (a *API) listBindings(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	list, err := a.store.BindingsOf(r.Context(), id)
	if err != nil {
		failErr(w, err, "读取部署绑定失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) addBinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		TargetID int64 `json:"target_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := a.store.BindTarget(r.Context(), id, req.TargetID); err != nil {
		failErr(w, err, "绑定部署目标失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) removeBinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	targetID, ok := pathID(w, r, "targetID")
	if !ok {
		return
	}
	if err := a.store.UnbindTarget(r.Context(), id, targetID); err != nil {
		failErr(w, err, "解绑部署目标失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- CA 账号 ----------

func (a *API) listACMEAccounts(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListACMEAccounts(r.Context())
	if err != nil {
		failErr(w, err, "读取 CA 账号失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) createACMEAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		Email        string `json:"email"`
		DirectoryURL string `json:"directory_url"`
		IsStaging    bool   `json:"is_staging"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Email == "" {
		fail(w, http.StatusBadRequest, "邮箱不能为空，CA 用它发送到期提醒")
		return
	}
	if req.DirectoryURL == "" {
		fail(w, http.StatusBadRequest, "请选择 CA 目录地址")
		return
	}
	if req.Name == "" {
		req.Name = req.Email
	}

	key, err := acme.GenerateAccountKey()
	if err != nil {
		failErr(w, err, "生成账号私钥失败")
		return
	}
	id, err := a.store.CreateACMEAccount(r.Context(), &store.ACMEAccount{
		Name: req.Name, Email: req.Email,
		DirectoryURL: req.DirectoryURL, IsStaging: req.IsStaging,
	}, key)
	if err != nil {
		failErr(w, err, "保存 CA 账号失败")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// ---------- 部署目标 ----------

func (a *API) listTargets(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListDeployTargets(r.Context())
	if err != nil {
		failErr(w, err, "读取部署目标失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) createTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name            string          `json:"name"`
		Kind            string          `json:"kind"`
		CredentialID    *int64          `json:"credential_id"`
		ServerServiceID *int64          `json:"server_service_id"`
		Params          json.RawMessage `json:"params"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || req.Kind == "" {
		fail(w, http.StatusBadRequest, "名称与类型都是必填项")
		return
	}
	// SSH 类目标的连接信息来自服务记录，没有它就无从下发。
	if req.Kind == "ssh_nginx" && req.ServerServiceID == nil {
		fail(w, http.StatusBadRequest, "请先选择一个已探测到的 nginx 服务")
		return
	}
	id, err := a.store.CreateDeployTarget(r.Context(), &store.DeployTarget{
		Name: req.Name, Kind: req.Kind, CredentialID: req.CredentialID,
		ServerServiceID: req.ServerServiceID, Params: req.Params, Enabled: true,
	})
	if err != nil {
		failErr(w, err, "创建部署目标失败")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (a *API) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := a.store.DeleteDeployTarget(r.Context(), id); err != nil {
		failErr(w, err, "删除部署目标失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
