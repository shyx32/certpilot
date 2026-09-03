package httpapi

import (
	"net/http"

	"github.com/certpilot/server/internal/aliyun"
	"github.com/certpilot/server/internal/scheduler"
	"github.com/certpilot/server/internal/store"
)

type createCredentialReq struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	Region          string `json:"region"`
}

// createCredential 保存一条凭据，并立刻扫描它能管理的域名。
//
// 「录入即扫描」让用户马上看到这个账号能管哪些域名，
// 之后新增证书时就不必再手工选择 DNS 账号。
func (a *API) createCredential(w http.ResponseWriter, r *http.Request) {
	var req createCredentialReq
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" {
		fail(w, http.StatusBadRequest, "凭据名称不能为空")
		return
	}
	if req.Kind == "" {
		req.Kind = "aliyun_ak"
	}
	secret, err := aliyun.MarshalCredential(req.AccessKeyID, req.AccessKeySecret, req.Region)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}

	id, err := a.store.CreateCredential(r.Context(), &store.Credential{
		Name: req.Name, Kind: req.Kind, Origin: "manual", Region: &req.Region,
	}, secret)
	if err != nil {
		failErr(w, err, "保存凭据失败")
		return
	}

	// 同步扫描一次。失败不影响凭据本身已保存，只记录检查结果。
	n, scanErr := scheduler.SyncZonesFor(r.Context(), a.store, id)
	if scanErr != nil {
		_ = a.store.MarkCredentialChecked(r.Context(), id, false, scanErr.Error())
	} else {
		_ = a.store.MarkCredentialChecked(r.Context(), id, true, "")
	}

	cred, err := a.store.GetCredential(r.Context(), id)
	if err != nil {
		failErr(w, err, "读取凭据失败")
		return
	}
	resp := map[string]any{"credential": cred, "zones_synced": n}
	if scanErr != nil {
		resp["scan_error"] = "凭据已保存，但扫描域名失败：" + scanErr.Error()
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (a *API) listCredentials(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListCredentials(r.Context())
	if err != nil {
		failErr(w, err, "读取凭据列表失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) getCredentialZones(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	zones, err := a.store.ZonesOf(r.Context(), id)
	if err != nil {
		failErr(w, err, "读取域名清单失败")
		return
	}
	writeJSON(w, http.StatusOK, zones)
}

// syncCredential 手工触发一次 zone 重扫。
func (a *API) syncCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	n, err := scheduler.SyncZonesFor(r.Context(), a.store, id)
	if err != nil {
		_ = a.store.MarkCredentialChecked(r.Context(), id, false, err.Error())
		fail(w, http.StatusBadGateway, "扫描失败："+err.Error())
		return
	}
	_ = a.store.MarkCredentialChecked(r.Context(), id, true, "")
	writeJSON(w, http.StatusOK, map[string]int{"zones": n})
}

func (a *API) deleteCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := a.store.DeleteCredential(r.Context(), id); err != nil {
		failErr(w, err, "删除凭据失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- RAM 子账号自动创建 ----------

type provisionReq struct {
	Name                 string   `json:"name"`
	AdminAccessKeyID     string   `json:"admin_access_key_id"`
	AdminAccessKeySecret string   `json:"admin_access_key_secret"`
	Capabilities         []string `json:"capabilities"`
	DNSResources         []string `json:"dns_resources"`
	Region               string   `json:"region"`
}

// previewPolicy 在创建之前把完整策略 JSON 展示给用户。
//
// 一个索要管理凭据的功能，透明度就是它的信任基础——
// 藏着掖着的自动化没人敢用。
func (a *API) previewPolicy(w http.ResponseWriter, r *http.Request) {
	var req provisionReq
	if !decode(w, r, &req) {
		return
	}
	doc, err := aliyun.BuildPolicy(toCaps(req.Capabilities), req.DNSResources)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	js, err := doc.JSON()
	if err != nil {
		failErr(w, err, "生成策略失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"policy": js})
}

// provisionCredential 用一次性的管理凭据创建最小权限子账号。
//
// 管理凭据只存在于本次请求的内存中：不入库、不落盘、不进日志。
// 只有创建出来的子账号 AK 会被加密保存。
func (a *API) provisionCredential(w http.ResponseWriter, r *http.Request) {
	var req provisionReq
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" {
		fail(w, http.StatusBadRequest, "凭据名称不能为空")
		return
	}
	if req.AdminAccessKeyID == "" || req.AdminAccessKeySecret == "" {
		fail(w, http.StatusBadRequest, "请提供用于创建子账号的管理凭据")
		return
	}

	ctx := r.Context()
	result, err := aliyun.Provision(ctx, &aliyun.ProvisionRequest{
		AdminAccessKeyID:     req.AdminAccessKeyID,
		AdminAccessKeySecret: req.AdminAccessKeySecret,
		Capabilities:         toCaps(req.Capabilities),
		DNSResources:         req.DNSResources,
	})
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}

	secret, err := aliyun.MarshalCredential(result.AccessKeyID, result.AccessKeySecret, req.Region)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}

	// AccessKeySecret 只在创建响应里出现一次，此后再也读不到。
	// 入库失败必须立刻撤销这把 AK，否则会在用户账号里留下一把
	// 谁也不知道密码的僵尸凭据。
	id, err := a.store.CreateCredential(ctx, &store.Credential{
		Name:          req.Name,
		Kind:          "aliyun_ak",
		Origin:        "auto",
		RAMUserName:   &result.UserName,
		RAMPolicyName: &result.PolicyName,
		Region:        &req.Region,
	}, secret)
	if err != nil {
		if revErr := aliyun.RevokeAccessKey(ctx, req.AdminAccessKeyID, req.AdminAccessKeySecret,
			result.UserName, result.AccessKeyID); revErr != nil {
			fail(w, http.StatusInternalServerError,
				"保存凭据失败，且撤销新建 AccessKey 也失败，请手工删除 RAM 用户 "+result.UserName)
			return
		}
		failErr(w, err, "保存凭据失败，已撤销新建的 AccessKey")
		return
	}

	n, scanErr := scheduler.SyncZonesFor(ctx, a.store, id)
	_ = a.store.MarkCredentialChecked(ctx, id, scanErr == nil, errText(scanErr))

	cred, err := a.store.GetCredential(ctx, id)
	if err != nil {
		failErr(w, err, "读取凭据失败")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"credential":   cred,
		"ram_user":     result.UserName,
		"policy_name":  result.PolicyName,
		"zones_synced": n,
	})
}

func toCaps(in []string) []aliyun.Capability {
	out := make([]aliyun.Capability, 0, len(in))
	for _, s := range in {
		out = append(out, aliyun.Capability(s))
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// rotateCredential 零停机更换子账号的 AccessKey。
//
// 顺序是刻意的：建新 → 验证能用 → 入库 → 删旧。
// 反过来（先删旧）会在任何一步出错时让两把 AK 都不可用。
func (a *API) rotateCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		AdminAccessKeyID     string `json:"admin_access_key_id"`
		AdminAccessKeySecret string `json:"admin_access_key_secret"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.AdminAccessKeyID == "" || req.AdminAccessKeySecret == "" {
		fail(w, http.StatusBadRequest,
			"轮换需要管理凭据：子账号自己没有创建 AccessKey 的权限，这正是最小权限的应有之义。")
		return
	}

	ctx := r.Context()
	cred, err := a.store.GetCredential(ctx, id)
	if err != nil {
		failErr(w, err, "读取凭据失败")
		return
	}
	if cred.Origin != "auto" || cred.RAMUserName == nil {
		fail(w, http.StatusBadRequest,
			"只有由 CertPilot 创建的子账号才能自动轮换；手动录入的凭据请到控制台自行更换。")
		return
	}

	// 取出当前 AK ID，验证通过后用它删除旧凭据。
	oldSecret, err := a.store.Secret(ctx, id)
	if err != nil {
		failErr(w, err, "读取现有凭据失败")
		return
	}
	oldCred, err := aliyun.ParseCredential(oldSecret)
	if err != nil {
		failErr(w, err, "现有凭据格式不正确")
		return
	}

	// 1. 建新
	res, err := aliyun.RotateAccessKey(ctx, &aliyun.RotateRequest{
		AdminAccessKeyID:     req.AdminAccessKeyID,
		AdminAccessKeySecret: req.AdminAccessKeySecret,
		UserName:             *cred.RAMUserName,
		OldAccessKeyID:       oldCred.AccessKeyID,
	})
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}

	newSecret, err := aliyun.MarshalCredential(res.AccessKeyID, res.AccessKeySecret, oldCred.Region)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 2. 入库。失败就撤销刚建的 AK——旧的还在用，线上不受影响。
	if err := a.store.ReplaceSecret(ctx, id, newSecret); err != nil {
		if revErr := aliyun.RevokeAccessKey(ctx, req.AdminAccessKeyID, req.AdminAccessKeySecret,
			*cred.RAMUserName, res.AccessKeyID); revErr != nil {
			fail(w, http.StatusInternalServerError,
				"保存新凭据失败，且撤销新建 AccessKey 也失败，请手工删除 "+res.AccessKeyID)
			return
		}
		failErr(w, err, "保存新凭据失败，已撤销新建的 AccessKey，原凭据仍然可用")
		return
	}

	// 3. 验证新凭据能用。用不了就说明轮换有问题，但旧 AK 尚未删除，
	//    用户可以按提示手工恢复。
	if _, scanErr := scheduler.SyncZonesFor(ctx, a.store, id); scanErr != nil {
		_ = a.store.MarkCredentialChecked(ctx, id, false, scanErr.Error())
		fail(w, http.StatusBadGateway,
			"新凭据已保存但校验失败："+scanErr.Error()+"。旧 AccessKey 尚未删除，可到控制台确认。")
		return
	}
	_ = a.store.MarkCredentialChecked(ctx, id, true, "")

	// 4. 删旧。到这一步新凭据已确认可用，删除是安全的。
	warn := ""
	if err := aliyun.RevokeAccessKey(ctx, req.AdminAccessKeyID, req.AdminAccessKeySecret,
		*cred.RAMUserName, oldCred.AccessKeyID); err != nil {
		warn = "新凭据已生效，但删除旧 AccessKey 失败，请到控制台手工删除 " + oldCred.AccessKeyID
	}

	a.store.Audit(ctx, actorOf(r), "rotate_credential", cred.Name,
		map[string]any{"ram_user": *cred.RAMUserName})
	resp := map[string]any{"ok": true, "new_access_key_id": res.AccessKeyID}
	if warn != "" {
		resp["warning"] = warn
	}
	writeJSON(w, http.StatusOK, resp)
}

// upgradeCredential 更新子账号的权限策略。
//
// 子账号 AK 不变，无需重新分发；同样需要一次性的管理凭据，
// 因为子账号自己没有改策略的权限。
func (a *API) upgradeCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		AdminAccessKeyID     string   `json:"admin_access_key_id"`
		AdminAccessKeySecret string   `json:"admin_access_key_secret"`
		Capabilities         []string `json:"capabilities"`
		DNSResources         []string `json:"dns_resources"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.AdminAccessKeyID == "" || req.AdminAccessKeySecret == "" {
		fail(w, http.StatusBadRequest, "更新策略需要管理凭据")
		return
	}

	ctx := r.Context()
	cred, err := a.store.GetCredential(ctx, id)
	if err != nil {
		failErr(w, err, "读取凭据失败")
		return
	}
	if cred.Origin != "auto" || cred.RAMPolicyName == nil {
		fail(w, http.StatusBadRequest, "只有由 CertPilot 创建的子账号才能自动更新策略。")
		return
	}

	policyJSON, err := aliyun.UpdatePolicy(ctx, req.AdminAccessKeyID, req.AdminAccessKeySecret,
		*cred.RAMPolicyName, toCaps(req.Capabilities), req.DNSResources)
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	a.store.Audit(ctx, actorOf(r), "upgrade_credential_policy", cred.Name,
		map[string]any{"capabilities": req.Capabilities})
	writeJSON(w, http.StatusOK, map[string]string{"policy": policyJSON})
}
