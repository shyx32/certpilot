package nginxsvc

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseDockerPS(t *testing.T) {
	out := "abc123\tproj-nginx-1\tnginx:1.27-alpine\tproj\tnginx\n" +
		"def456\tstandalone-web\tmy/custom-nginx:v2\t\t\n" +
		"\n"
	got := ParseDockerPS(out)
	if len(got) != 2 {
		t.Fatalf("应解析出 2 行，实得 %d", len(got))
	}
	if got[0].ComposeProject != "proj" || got[0].ComposeService != "nginx" {
		t.Errorf("compose 标签解析错误: %+v", got[0])
	}
	if got[1].ComposeProject != "" {
		t.Errorf("非 compose 容器不应有项目名: %+v", got[1])
	}
}

func TestLooksLikeNginx(t *testing.T) {
	yes := []Container{
		{Image: "nginx:1.27"},
		{Image: "openresty/openresty:alpine"},
		{Image: "registry.local/tengine:v1"},
		{Image: "my/web:v1", ComposeService: "nginx"},
	}
	for _, c := range yes {
		if !LooksLikeNginx(c) {
			t.Errorf("应识别为 nginx: %+v", c)
		}
	}
	if LooksLikeNginx(Container{Image: "postgres:16", Name: "db"}) {
		t.Error("postgres 被误判为 nginx")
	}
}

const inspectJSON = `[{
  "Mounts": [
    {"Type":"bind","Source":"/data/certs","Destination":"/etc/nginx/certs","RW":false},
    {"Type":"volume","Name":"logs","Source":"/var/lib/docker/volumes/logs/_data","Destination":"/var/log/nginx","RW":true}
  ],
  "Config": {"User":"101:101","Image":"nginxinc/nginx-unprivileged:1.27"}
}]`

func TestParseInspect(t *testing.T) {
	mounts, user, err := ParseInspect(inspectJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 {
		t.Fatalf("挂载数 = %d", len(mounts))
	}
	if mounts[0].Type != "bind" || mounts[0].Source != "/data/certs" {
		t.Errorf("bind 挂载解析错误: %+v", mounts[0])
	}
	if user != "101:101" {
		t.Errorf("运行用户 = %q", user)
	}
}

func TestParseInspectSingleObject(t *testing.T) {
	single := strings.TrimPrefix(strings.TrimSuffix(inspectJSON, "]"), "[")
	if _, _, err := ParseInspect(single); err != nil {
		t.Fatalf("单对象形式应也能解析: %v", err)
	}
}

func TestParseInspectErrors(t *testing.T) {
	if _, _, err := ParseInspect(""); err == nil {
		t.Error("空输出应报错")
	}
	if _, _, err := ParseInspect("[]"); err == nil {
		t.Error("空数组应报错（容器不存在）")
	}
	if _, _, err := ParseInspect("not json"); err == nil {
		t.Error("非法 JSON 应报错")
	}
}

func TestBuildCommandsUsesReloadNotRestart(t *testing.T) {
	for _, k := range []Kind{KindSystemd, KindBare, KindDocker} {
		test, reload := BuildCommands(k, "c1")
		if len(test) == 0 || len(reload) == 0 {
			t.Fatalf("%s 未生成命令", k)
		}
		joined := strings.Join(reload, " ")
		if strings.Contains(joined, "restart") {
			t.Errorf("%s 用了 restart，会断开所有连接: %v", k, reload)
		}
		// 预检和重载必须成对：没有预检就等于闭着眼睛 reload
		if !strings.Contains(strings.Join(test, " "), "-t") &&
			!strings.Contains(strings.Join(test, " "), "configtest") {
			t.Errorf("%s 的预检命令可疑: %v", k, test)
		}
	}
}

func TestBuildCommandsDockerUsesContainer(t *testing.T) {
	test, reload := BuildCommands(KindDocker, "proj-nginx-1")
	if !reflect.DeepEqual(test, []string{"docker", "exec", "proj-nginx-1", "nginx", "-t"}) {
		t.Errorf("预检命令 = %v", test)
	}
	if reload[2] != "proj-nginx-1" {
		t.Errorf("重载命令未带容器名: %v", reload)
	}
}

// compose 场景必须用标签定位，容器名和 ID 都会变。
func TestLocatorPrefersComposeLabels(t *testing.T) {
	s := &Service{Kind: KindDocker, ComposeProject: "proj", ComposeService: "nginx", ContainerName: "proj-nginx-1"}
	loc := strings.Join(s.Locator(), " ")
	if !strings.Contains(loc, "com.docker.compose.project=proj") {
		t.Errorf("未使用 compose 标签: %s", loc)
	}
	if !strings.Contains(loc, "com.docker.compose.service=nginx") {
		t.Errorf("未使用服务标签: %s", loc)
	}
}

func TestLocatorFallsBackToName(t *testing.T) {
	s := &Service{Kind: KindDocker, ContainerName: "standalone"}
	loc := strings.Join(s.Locator(), " ")
	if !strings.Contains(loc, "name=^standalone$") {
		t.Errorf("非 compose 容器应按名精确匹配: %s", loc)
	}
}

// 非 root 镜像必须 chown，否则 reload 后握手失败。
func TestNeedsChown(t *testing.T) {
	if u, need := NeedsChown("101:101"); !need || u != "101:101" {
		t.Errorf("非 root 用户应需要 chown: %q %v", u, need)
	}
	for _, root := range []string{"", "root", "0", "0:0"} {
		if _, need := NeedsChown(root); need {
			t.Errorf("%q 不应需要 chown", root)
		}
	}
}
