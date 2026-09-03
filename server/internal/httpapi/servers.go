package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/certpilot/server/internal/nginxsvc"
	"github.com/certpilot/server/internal/sshx"
	"github.com/certpilot/server/internal/store"
)

type createHostReq struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	JumpHostID *int64 `json:"jump_host_id"`

	// 凭据二选一：现有凭据，或就地新建一条 SSH 凭据。
	CredentialID  int64  `json:"credential_id"`
	PrivateKeyPEM string `json:"private_key_pem"`
	Passphrase    string `json:"passphrase"`
	Password      string `json:"password"`
}

func (a *API) createServer(w http.ResponseWriter, r *http.Request) {
	var req createHostReq
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || req.Host == "" || req.Username == "" {
		fail(w, http.StatusBadRequest, "名称、地址与登录用户都是必填项")
		return
	}
	ctx := r.Context()

	credID := req.CredentialID
	if credID == 0 {
		if req.PrivateKeyPEM == "" && req.Password == "" {
			fail(w, http.StatusBadRequest, "请提供 SSH 私钥或密码，或选择一条已有凭据")
			return
		}
		kind := "ssh_key"
		if req.PrivateKeyPEM == "" {
			kind = "ssh_password"
		}
		secret, err := json.Marshal(map[string]string{
			"private_key_pem": req.PrivateKeyPEM,
			"passphrase":      req.Passphrase,
			"password":        req.Password,
		})
		if err != nil {
			failErr(w, err, "构造凭据失败")
			return
		}
		credID, err = a.store.CreateCredential(ctx, &store.Credential{
			Name: "ssh:" + req.Name, Kind: kind, Origin: "manual",
		}, secret)
		if err != nil {
			failErr(w, err, "保存 SSH 凭据失败")
			return
		}
	}

	id, err := a.store.CreateSSHHost(ctx, &store.SSHHost{
		Name: req.Name, Host: req.Host, Port: req.Port,
		Username: req.Username, CredentialID: credID, JumpHostID: req.JumpHostID,
	})
	if err != nil {
		failErr(w, err, "保存主机失败")
		return
	}
	a.store.Audit(ctx, actorOf(r), "create_server", req.Name, map[string]any{"host": req.Host})

	host, err := a.store.GetSSHHost(ctx, id)
	if err != nil {
		failErr(w, err, "读取主机失败")
		return
	}
	writeJSON(w, http.StatusCreated, host)
}

func (a *API) listServers(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListSSHHosts(r.Context())
	if err != nil {
		failErr(w, err, "读取主机列表失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) deleteServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := a.store.DeleteSSHHost(r.Context(), id); err != nil {
		failErr(w, err, "删除主机失败")
		return
	}
	a.store.Audit(r.Context(), actorOf(r), "delete_server", fmt.Sprint(id), nil)
	w.WriteHeader(http.StatusNoContent)
}

// detectServer 连上目标并探测 nginx 形态。
//
// 全程只读命令。识别不出来不是失败——返回空列表并给出下一步指引。
func (a *API) detectServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	client, host, err := a.dialHost(ctx, id)
	if err != nil {
		_ = a.store.MarkHostProbed(ctx, id, false, err.Error(), nil)
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()

	// 首次接入时把看到的指纹固化下来，之后不匹配即拒绝连接。
	if host.HostKeyFP == nil && client.SeenFingerprint != "" {
		_ = a.store.SetHostKey(ctx, id, client.SeenFingerprint)
	}

	detection, err := nginxsvc.Detect(ctx, client)
	if err != nil {
		_ = a.store.MarkHostProbed(ctx, id, false, err.Error(), nil)
		fail(w, http.StatusBadGateway, "探测失败："+err.Error())
		return
	}
	if err := a.store.SaveDetectedServices(ctx, id, detection.Services); err != nil {
		failErr(w, err, "保存探测结果失败")
		return
	}
	_ = a.store.MarkHostProbed(ctx, id, true, "", detection)

	services, err := a.store.ListServices(ctx, id)
	if err != nil {
		failErr(w, err, "读取服务列表失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"detection": detection,
		"services":  services,
	})
}

// dialHost 按库中记录建立 SSH 连接。
func (a *API) dialHost(ctx context.Context, id int64) (*sshx.Client, *store.SSHHost, error) {
	host, err := a.store.GetSSHHost(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("读取主机信息失败：%w", err)
	}
	target, err := a.buildTarget(ctx, host, 0)
	if err != nil {
		return nil, nil, err
	}
	client, err := sshx.Dial(ctx, target)
	if err != nil {
		return nil, nil, fmt.Errorf("连接 %s 失败：%w", host.Host, err)
	}
	return client, host, nil
}

func (a *API) buildTarget(ctx context.Context, host *store.SSHHost, depth int) (*sshx.Target, error) {
	if depth > 5 {
		return nil, fmt.Errorf("跳板机层级过深")
	}
	secret, err := a.store.Secret(ctx, host.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("读取 SSH 凭据失败：%w", err)
	}
	var s struct {
		PrivateKeyPEM string `json:"private_key_pem"`
		Passphrase    string `json:"passphrase"`
		Password      string `json:"password"`
	}
	if err := json.Unmarshal(secret, &s); err != nil {
		return nil, fmt.Errorf("SSH 凭据格式不正确：%w", err)
	}

	t := &sshx.Target{
		Host: host.Host, Port: host.Port, User: host.Username,
		Auth: sshx.Auth{
			PrivateKeyPEM: []byte(s.PrivateKeyPEM),
			Passphrase:    s.Passphrase,
			Password:      s.Password,
		},
	}
	if host.HostKeyFP != nil {
		t.HostKeyFingerprint = *host.HostKeyFP
	}
	if host.JumpHostID != nil {
		jump, err := a.store.GetSSHHost(ctx, *host.JumpHostID)
		if err != nil {
			return nil, fmt.Errorf("读取跳板机信息失败：%w", err)
		}
		if t.Jump, err = a.buildTarget(ctx, jump, depth+1); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (a *API) listServices(w http.ResponseWriter, r *http.Request) {
	var hostID int64
	if v := r.URL.Query().Get("host_id"); v != "" {
		id, ok := parseID(v)
		if !ok {
			fail(w, http.StatusBadRequest, "host_id 不是合法 ID")
			return
		}
		hostID = id
	}
	list, err := a.store.ListServices(r.Context(), hostID)
	if err != nil {
		failErr(w, err, "读取服务列表失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// dryRunService 只执行预检命令并原样回显输出。
//
// 不碰任何证书文件，纯粹验证「这条命令在这台机器上能不能跑通、
// 有没有权限、容器能不能定位到」。
func (a *API) dryRunService(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	rec, err := a.store.GetService(ctx, id)
	if err != nil {
		failErr(w, err, "读取服务失败")
		return
	}
	client, _, err := a.dialHost(ctx, rec.SSHHostID)
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()

	svc := rec.ToService()
	if svc.Kind == nginxsvc.KindDocker {
		loc := svc.Locator()
		res, err := client.Run(ctx, loc)
		if err != nil || len(res.Stdout) == 0 {
			fail(w, http.StatusBadGateway,
				"没有找到运行中的容器，请确认它已启动（"+svc.DisplayName()+"）")
			return
		}
		svc.ContainerID = firstField(res.Stdout)
		svc.TestArgv, svc.ReloadArgv = nginxsvc.BuildCommands(nginxsvc.KindDocker, svc.ContainerID)
	}

	argv := svc.TestArgv
	if len(argv) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     false,
			"output": "该服务没有配置预检命令。无法预检意味着配置写错时 reload 会直接失败，请先补上。",
		})
		return
	}
	// 与部署保持一致：nginx 命令的提权判断独立于写文件的权限。
	if rec.ReloadNeedsSudo || rec.UseSudo {
		argv = sshx.WithSudo(argv)
	}
	res, err := client.Run(ctx, argv)
	if err != nil {
		fail(w, http.StatusBadGateway, "执行失败："+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        res.ExitCode == 0,
		"exit_code": res.ExitCode,
		"command":   argv,
		"output":    res.Combined(),
	})
}

// updateServiceCommands 保存管理员自定义的预检与重载命令。
//
// 命令以 argv 数组保存，执行时逐个转义，用户填的内容永远只是参数。
func (a *API) updateServiceCommands(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		TestArgv   []string `json:"test_argv"`
		ReloadArgv []string `json:"reload_argv"`
		UseSudo    bool     `json:"use_sudo"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.ReloadArgv) == 0 {
		fail(w, http.StatusBadRequest, "重载命令不能为空")
		return
	}
	if err := a.store.UpdateServiceCommands(r.Context(), id, req.TestArgv, req.ReloadArgv, req.UseSudo); err != nil {
		failErr(w, err, "保存命令失败")
		return
	}
	a.store.Audit(r.Context(), actorOf(r), "update_service_commands", fmt.Sprint(id),
		map[string]any{"reload": req.ReloadArgv, "sudo": req.UseSudo})
	w.WriteHeader(http.StatusNoContent)
}

func firstField(s string) string {
	for _, f := range splitFields(s) {
		return f
	}
	return ""
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
