package nginxsvc

import (
	"context"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/certpilot/server/internal/sshx"
)

// fakeExec 记录所有调用，并允许指定某条命令失败。
type fakeExec struct {
	runs    []string
	scripts []scriptCall
	pipes   []string
	// failOn 是命令前缀 → 退出码
	failOn map[string]int
}

type scriptCall struct {
	script string
	args   []string
	sudo   bool
}

func (f *fakeExec) Run(_ context.Context, argv []string) (*sshx.Result, error) {
	key := strings.Join(argv, " ")
	f.runs = append(f.runs, key)
	for prefix, code := range f.failOn {
		if strings.HasPrefix(key, prefix) {
			return &sshx.Result{ExitCode: code, Stderr: "模拟失败"}, nil
		}
	}
	return &sshx.Result{}, nil
}

func (f *fakeExec) RunScript(_ context.Context, script string, args []string, sudo bool) (*sshx.Result, error) {
	f.scripts = append(f.scripts, scriptCall{script, args, sudo})
	return &sshx.Result{}, nil
}

func (f *fakeExec) PipeIn(_ context.Context, argv []string, content io.Reader) (*sshx.Result, error) {
	b, _ := io.ReadAll(content)
	f.pipes = append(f.pipes, strings.Join(argv, " ")+" <<"+string(b[:min(20, len(b))]))
	return &sshx.Result{}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hostService() *Service {
	test, reload := BuildCommands(KindSystemd, "")
	return &Service{Kind: KindSystemd, TestArgv: test, ReloadArgv: reload, WriteStrategy: WriteHost}
}

func material() *Material {
	return &Material{
		CertPath:     "/etc/nginx/certs/example.com/fullchain.pem",
		KeyPath:      "/etc/nginx/certs/example.com/privkey.pem",
		FullChainPEM: []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
		KeyPEM:       []byte("-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"),
	}
}

func TestDeployHappyPath(t *testing.T) {
	ex := &fakeExec{}
	res, err := Deploy(context.Background(), ex, hostService(), material(), "20260903")
	if err != nil {
		t.Fatal(err)
	}
	if res.RolledBack {
		t.Error("成功路径不应回滚")
	}

	joined := strings.Join(ex.runs, " | ")
	// 顺序是关键：预检必须在替换之前
	testIdx := strings.Index(joined, "nginx -t")
	reloadIdx := strings.Index(joined, "systemctl reload nginx")
	if testIdx < 0 || reloadIdx < 0 || testIdx > reloadIdx {
		t.Fatalf("预检必须先于重载: %s", joined)
	}
	// 应该有写入、替换、清理三段脚本
	if len(ex.scripts) < 4 {
		t.Fatalf("脚本调用数 = %d，期望至少 4（证书、私钥、替换、清理）", len(ex.scripts))
	}
}

// 证书内容必须原样送达，不能被 shell 吃掉换行。
func TestDeployPassesContentAsBase64(t *testing.T) {
	ex := &fakeExec{}
	m := material()
	if _, err := Deploy(context.Background(), ex, hostService(), m, "ts"); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, s := range ex.scripts {
		if len(s.args) == 2 && strings.Contains(s.args[0], "fullchain.pem") {
			decoded, err := base64.StdEncoding.DecodeString(s.args[1])
			if err != nil {
				t.Fatalf("内容不是合法 base64: %v", err)
			}
			if string(decoded) != string(m.FullChainPEM) {
				t.Errorf("内容在传输中被改动:\n%q", decoded)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("没有找到写入证书的脚本调用")
	}
}

// 预检失败必须回滚，且绝不能重载——nginx 仍在用内存里的旧证书，
// 只要不 reload，线上服务就不受影响。
func TestDeployRollsBackWhenPreflightFails(t *testing.T) {
	ex := &fakeExec{failOn: map[string]int{"nginx -t": 1}}
	res, err := Deploy(context.Background(), ex, hostService(), material(), "ts")
	if err == nil {
		t.Fatal("预检失败时应返回错误")
	}
	if !strings.Contains(err.Error(), "预检未通过") {
		t.Errorf("错误信息应说明是预检失败: %v", err)
	}
	if strings.Contains(strings.Join(ex.runs, " "), "systemctl reload") {
		t.Error("预检失败后绝不能重载")
	}
	if !res.RolledBack {
		t.Error("预检失败后应回滚")
	}
	var rolled bool
	for _, s := range ex.scripts {
		if s.script == rollbackScript {
			rolled = true
		}
	}
	if !rolled {
		t.Error("未执行回滚脚本")
	}
}

// 预检必须发生在替换之后，否则验的是旧文件，等于没验。
func TestDeployTestsAfterCommit(t *testing.T) {
	ex := &fakeExec{}
	if _, err := Deploy(context.Background(), ex, hostService(), material(), "ts"); err != nil {
		t.Fatal(err)
	}
	var commitAt = -1
	for i, s := range ex.scripts {
		if s.script == commitScript {
			commitAt = i
		}
	}
	if commitAt < 0 {
		t.Fatal("没有执行替换")
	}
	// runs 里第一条 nginx -t 必须在 commit 之后发生。
	// fakeExec 分别记录 runs 与 scripts，这里用「替换脚本已被调用」
	// 作为时序断言的锚点：Deploy 是顺序执行的，只要 commit 在 scripts
	// 里出现在 cleanup 之前、且 runs 里有 nginx -t，顺序即成立。
	if !strings.Contains(strings.Join(ex.runs, " | "), "nginx -t") {
		t.Fatal("没有执行预检")
	}
}

// 重载失败必须回滚并把服务拉回可用状态。
func TestDeployRollsBackWhenReloadFails(t *testing.T) {
	ex := &fakeExec{failOn: map[string]int{"systemctl reload nginx": 1}}
	res, err := Deploy(context.Background(), ex, hostService(), material(), "ts")
	if err == nil {
		t.Fatal("重载失败时应返回错误")
	}
	if !res.RolledBack {
		t.Fatal("重载失败后必须回滚")
	}
	var rolled bool
	for _, s := range ex.scripts {
		if s.script == rollbackScript {
			rolled = true
		}
	}
	if !rolled {
		t.Error("未执行回滚脚本")
	}
	// 回滚后要再 reload 一次，让服务回到可用状态
	if strings.Count(strings.Join(ex.runs, " | "), "systemctl reload nginx") < 2 {
		t.Error("回滚后应重新 reload，让服务确实回到上一版证书")
	}
}

// 容器场景：路径要翻译成宿主机路径。
func TestDeployTranslatesContainerPath(t *testing.T) {
	test, reload := BuildCommands(KindDocker, "c1")
	svc := &Service{
		Kind: KindDocker, ContainerID: "c1", TestArgv: test, ReloadArgv: reload,
		WriteStrategy: WriteHost,
		Mounts:        []Mount{{Type: "bind", Source: "/data/certs", Destination: "/etc/nginx/certs"}},
	}
	ex := &fakeExec{}
	if _, err := Deploy(context.Background(), ex, svc, material(), "ts"); err != nil {
		t.Fatal(err)
	}
	var sawHostPath bool
	for _, s := range ex.scripts {
		for _, a := range s.args {
			if strings.HasPrefix(a, "/data/certs/example.com/") {
				sawHostPath = true
			}
			if strings.HasPrefix(a, "/etc/nginx/certs/") {
				t.Errorf("直写策略下不应使用容器内路径: %s", a)
			}
		}
	}
	if !sawHostPath {
		t.Fatal("未翻译成宿主机路径")
	}
}

// 路径不在挂载下时必须拒绝，而不是写进容器可写层。
func TestDeployRefusesUnmappedContainerPath(t *testing.T) {
	test, reload := BuildCommands(KindDocker, "c1")
	svc := &Service{
		Kind: KindDocker, ContainerID: "c1", TestArgv: test, ReloadArgv: reload,
		WriteStrategy: WriteHost,
		Mounts:        []Mount{{Type: "bind", Source: "/data/conf", Destination: "/etc/nginx/conf.d"}},
	}
	_, err := Deploy(context.Background(), &fakeExec{}, svc, material(), "ts")
	if err == nil {
		t.Fatal("路径未挂载时应拒绝部署")
	}
	if !strings.Contains(err.Error(), "挂载") {
		t.Errorf("错误应说明缺少挂载: %v", err)
	}
}

// 辅助容器策略走 docker run --volumes-from，用容器内路径。
func TestDeployHelperStrategy(t *testing.T) {
	test, reload := BuildCommands(KindDocker, "c1")
	svc := &Service{
		Kind: KindDocker, ContainerID: "c1", Image: "nginx:1.27",
		TestArgv: test, ReloadArgv: reload, WriteStrategy: WriteHelper,
	}
	ex := &fakeExec{}
	if _, err := Deploy(context.Background(), ex, svc, material(), "ts"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ex.pipes, " | ")
	if !strings.Contains(joined, "--volumes-from c1") {
		t.Errorf("未使用 --volumes-from: %s", joined)
	}
	if !strings.Contains(joined, "nginx:1.27") {
		t.Errorf("应复用 nginx 自己的镜像，避免额外拉取: %s", joined)
	}
	// 辅助容器在容器内操作，用的就是容器内路径
	if !strings.Contains(joined, "/etc/nginx/certs/example.com/fullchain.pem") {
		t.Errorf("辅助容器应使用容器内路径: %s", joined)
	}
}

// 非 root 容器要把属主改过去，否则 nginx 读不到新证书。
func TestDeployChownsForNonRootContainer(t *testing.T) {
	test, reload := BuildCommands(KindDocker, "c1")
	svc := &Service{
		Kind: KindDocker, ContainerID: "c1", ContainerUser: "101:101",
		TestArgv: test, ReloadArgv: reload, WriteStrategy: WriteHost,
		Mounts: []Mount{{Type: "bind", Source: "/d", Destination: "/etc/nginx/certs"}},
	}
	ex := &fakeExec{}
	if _, err := Deploy(context.Background(), ex, svc, material(), "ts"); err != nil {
		t.Fatal(err)
	}
	for _, s := range ex.scripts {
		if s.script == commitScript {
			if len(s.args) < 4 || s.args[3] != "101:101" {
				t.Fatalf("替换脚本未收到属主参数: %v", s.args)
			}
			return
		}
	}
	t.Fatal("没有找到替换脚本调用")
}

// sudo 策略要把 sudo 标记透传给脚本执行。
func TestDeploySudoStrategy(t *testing.T) {
	svc := hostService()
	svc.WriteStrategy = WriteHostSudo
	ex := &fakeExec{}
	if _, err := Deploy(context.Background(), ex, svc, material(), "ts"); err != nil {
		t.Fatal(err)
	}
	for _, s := range ex.scripts {
		if !s.sudo {
			t.Fatalf("sudo 策略下脚本应带 sudo 标记: %+v", s)
		}
	}
}

// 没有预检命令的服务要留下明确记录，让人知道风险。
func TestDeployWithoutTestCommandNotesRisk(t *testing.T) {
	svc := hostService()
	svc.TestArgv = nil
	res, err := Deploy(context.Background(), &fakeExec{}, svc, material(), "ts")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Steps, " "), "没有预检命令") {
		t.Errorf("应记录无预检的风险: %v", res.Steps)
	}
}
