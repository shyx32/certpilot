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
