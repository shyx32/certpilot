package nginxsvc

import (
	"context"
	"strings"
	"testing"

	"github.com/certpilot/server/internal/sshx"
)

// fakeRunner 按命令前缀返回预设输出，让整条探测流程可以离线测试。
type fakeRunner struct {
	responses map[string]*sshx.Result
	calls     []string
}

func (f *fakeRunner) Run(_ context.Context, argv []string) (*sshx.Result, error) {
	key := strings.Join(argv, " ")
	f.calls = append(f.calls, key)
	for prefix, res := range f.responses {
		if strings.HasPrefix(key, prefix) {
			return res, nil
		}
	}
	// 未预设的命令一律当作「不存在」，模拟真实环境里的失败退出码。
	return &sshx.Result{ExitCode: 127}, nil
}

func ok(stdout string) *sshx.Result { return &sshx.Result{Stdout: stdout} }

const nginxDump = `
http {
    server {
        listen 443 ssl;
        server_name example.com www.example.com;
        ssl_certificate     /etc/nginx/certs/example.com/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/example.com/privkey.pem;
    }
}`

func TestDetectDockerCompose(t *testing.T) {
	r := &fakeRunner{responses: map[string]*sshx.Result{
		"sudo -n true":                    ok(""),
		"docker version":                  ok("29.7.2"),
		"docker ps":                       ok("abc123\tproj-nginx-1\tnginx:1.27-alpine\tproj\tnginx"),
		"docker exec abc123 nginx -v":     ok("nginx version: nginx/1.27.0"),
		"docker inspect abc123":           ok(`[{"Mounts":[{"Type":"bind","Source":"/data/certs","Destination":"/etc/nginx/certs","RW":false}],"Config":{"User":"","Image":"nginx:1.27-alpine"}}]`),
		"docker exec abc123 nginx -T":     ok(nginxDump),
		"test -w /data/certs/example.com": ok(""),
		"sh -c ss -lntp":                  ok("LISTEN 0 4096 *:443 *:* users:((\"docker-proxy\",pid=1234,fd=4))"),
	}}

	d, err := Detect(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !d.DockerAvailable || !d.SudoAvailable {
		t.Fatalf("环境能力探测有误: docker=%v sudo=%v", d.DockerAvailable, d.SudoAvailable)
	}
	if len(d.Services) != 1 {
		t.Fatalf("应发现 1 个服务，实得 %d", len(d.Services))
	}

	s := d.Services[0]
	if s.Kind != KindDocker {
		t.Errorf("形态 = %s", s.Kind)
	}
	if s.ComposeProject != "proj" || s.ComposeService != "nginx" {
		t.Errorf("compose 标签丢失: %+v", s)
	}
	// bind mount + 宿主机可写 → 直写，不必绕辅助容器
	if s.WriteStrategy != WriteHost {
		t.Errorf("写入策略 = %s（%s），bind mount 可写时应直写", s.WriteStrategy, s.StrategyReason)
	}
	if len(s.Certs) != 1 || len(s.Certs[0].Domains) != 2 {
		t.Errorf("证书发现有误: %+v", s.Certs)
	}
	// docker-proxy 占用 443 应被记入提示
	if !strings.Contains(strings.Join(d.Notes, " "), "docker-proxy") {
		t.Errorf("未提示 443 由容器提供: %v", d.Notes)
	}
}

// named volume 必须走辅助容器：/var/lib/docker/volumes 是 700 的 root 目录。
func TestDetectNamedVolumeUsesHelper(t *testing.T) {
	r := &fakeRunner{responses: map[string]*sshx.Result{
		"docker version":          ok("29.7.2"),
		"docker ps":               ok("v1\tweb\tnginx:alpine\t\t"),
		"docker exec v1 nginx -v": ok("nginx/1.27"),
		"docker inspect v1":       ok(`[{"Mounts":[{"Type":"volume","Name":"certs","Source":"/var/lib/docker/volumes/certs/_data","Destination":"/etc/nginx/certs","RW":true}],"Config":{"User":"101"}}]`),
		"docker exec v1 nginx -T": ok(nginxDump),
		// 即使宿主机路径「看起来」可写
		"test -w /var/lib/docker/volumes/certs/_data/example.com": ok(""),
	}}
	d, _ := Detect(context.Background(), r)
	if len(d.Services) != 1 {
		t.Fatalf("服务数 = %d", len(d.Services))
	}
	if d.Services[0].WriteStrategy != WriteHelper {
		t.Fatalf("named volume 应走辅助容器，实得 %s", d.Services[0].WriteStrategy)
	}
	// 非 root 容器要提示 chown
	if !strings.Contains(strings.Join(d.Services[0].Notes, " "), "chown") {
		t.Errorf("非 root 容器未提示 chown: %v", d.Services[0].Notes)
	}
}

func TestDetectHostSystemd(t *testing.T) {
	r := &fakeRunner{responses: map[string]*sshx.Result{
		"command -v nginx":                        ok("/usr/sbin/nginx"),
		"systemctl list-unit-files nginx.service": ok("nginx.service enabled"),
		"nginx -T":                             ok(nginxDump),
		"test -w /etc/nginx/certs/example.com": ok(""),
	}}
	d, _ := Detect(context.Background(), r)
	if len(d.Services) != 1 {
		t.Fatalf("服务数 = %d", len(d.Services))
	}
	s := d.Services[0]
	if s.Kind != KindSystemd {
		t.Errorf("有 systemd 单元时应识别为 %s，实得 %s", KindSystemd, s.Kind)
	}
	if strings.Join(s.ReloadArgv, " ") != "systemctl reload nginx" {
		t.Errorf("重载命令 = %v", s.ReloadArgv)
	}
}

func TestDetectHostBare(t *testing.T) {
	r := &fakeRunner{responses: map[string]*sshx.Result{
		"command -v nginx": ok("/usr/local/nginx/sbin/nginx"),
		"nginx -T":         ok(nginxDump),
	}}
	d, _ := Detect(context.Background(), r)
	if len(d.Services) != 1 || d.Services[0].Kind != KindBare {
		t.Fatalf("无 systemd 单元时应识别为 %s: %+v", KindBare, d.Services)
	}
	if strings.Join(d.Services[0].ReloadArgv, " ") != "nginx -s reload" {
		t.Errorf("重载命令 = %v", d.Services[0].ReloadArgv)
	}
}

// 证书打进镜像（不在任何挂载下）时必须给出明确提示。
func TestDetectWarnsWhenCertNotMounted(t *testing.T) {
	r := &fakeRunner{responses: map[string]*sshx.Result{
		"docker version":          ok("29.7.2"),
		"docker ps":               ok("x1\tweb\tnginx\t\t"),
		"docker exec x1 nginx -v": ok("nginx/1.27"),
		"docker inspect x1":       ok(`[{"Mounts":[{"Type":"bind","Source":"/data/conf","Destination":"/etc/nginx/conf.d"}],"Config":{}}]`),
		"docker exec x1 nginx -T": ok(nginxDump),
	}}
	d, _ := Detect(context.Background(), r)
	notes := strings.Join(d.Services[0].Notes, " ")
	if !strings.Contains(notes, "不在任何挂载卷下") {
		t.Fatalf("未警告证书路径未挂载: %v", d.Services[0].Notes)
	}
}

// 镜像名像 nginx 但容器里没有 nginx 的，不能算数。
func TestDetectSkipsFalsePositiveImage(t *testing.T) {
	r := &fakeRunner{responses: map[string]*sshx.Result{
		"docker version": ok("29.7.2"),
		"docker ps":      ok("y1\tnginx-exporter\tprom/nginx-exporter:latest\t\t"),
		// docker exec nginx -v 失败（未预设 → 退出码 127）
	}}
	d, _ := Detect(context.Background(), r)
	if len(d.Services) != 0 {
		t.Fatalf("交叉验证失败的容器不应计入: %+v", d.Services)
	}
}

func TestDetectNothingFoundGivesGuidance(t *testing.T) {
	d, _ := Detect(context.Background(), &fakeRunner{responses: map[string]*sshx.Result{}})
	if len(d.Services) != 0 {
		t.Fatal("空环境不应发现服务")
	}
	if len(d.Notes) == 0 || !strings.Contains(d.Notes[0], "未能自动识别") {
		t.Errorf("识别不出时应给出下一步指引: %v", d.Notes)
	}
}
