package nginxsvc

import (
	"errors"
	"testing"
)

var mounts = []Mount{
	{Type: "bind", Source: "/data/nginx/conf.d", Destination: "/etc/nginx/conf.d", RW: false},
	{Type: "bind", Source: "/data/nginx/certs", Destination: "/etc/nginx/certs", RW: false},
	{Type: "volume", Source: "/var/lib/docker/volumes/nginx_logs/_data", Destination: "/var/log/nginx", Name: "nginx_logs"},
}

func TestResolveHostPath(t *testing.T) {
	cases := []struct {
		name      string
		container string
		wantHost  string
	}{
		{"证书文件", "/etc/nginx/certs/example.com/fullchain.pem", "/data/nginx/certs/example.com/fullchain.pem"},
		{"挂载点本身", "/etc/nginx/certs", "/data/nginx/certs"},
		{"配置文件", "/etc/nginx/conf.d/default.conf", "/data/nginx/conf.d/default.conf"},
		{"named volume", "/var/log/nginx/access.log", "/var/lib/docker/volumes/nginx_logs/_data/access.log"},
		{"路径含多余斜杠", "/etc/nginx/certs//a//b.pem", "/data/nginx/certs/a/b.pem"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ResolveHostPath(c.container, mounts)
			if err != nil {
				t.Fatal(err)
			}
			if got.HostPath != c.wantHost {
				t.Errorf("宿主机路径 = %q，期望 %q", got.HostPath, c.wantHost)
			}
		})
	}
}

// 最长前缀匹配：同时挂了父目录和子目录时，归属更精确的那条。
func TestResolveHostPathPrefersLongestMatch(t *testing.T) {
	ms := []Mount{
		{Type: "bind", Source: "/srv/nginx", Destination: "/etc/nginx"},
		{Type: "bind", Source: "/secure/certs", Destination: "/etc/nginx/certs"},
	}
	got, err := ResolveHostPath("/etc/nginx/certs/a.pem", ms)
	if err != nil {
		t.Fatal(err)
	}
	if got.HostPath != "/secure/certs/a.pem" {
		t.Fatalf("应命中更精确的挂载，实得 %q", got.HostPath)
	}
}

// 后缀相似的目录不能误判：/etc/nginx-extra 不属于 /etc/nginx。
func TestResolveHostPathRejectsSiblingLookalike(t *testing.T) {
	ms := []Mount{{Type: "bind", Source: "/srv/nginx", Destination: "/etc/nginx"}}
	if _, err := ResolveHostPath("/etc/nginx-extra/a.pem", ms); !errors.Is(err, ErrNotMounted) {
		t.Fatal("/etc/nginx-extra 不应命中 /etc/nginx")
	}
}

// 证书打进镜像时必须拒绝，而不是写进容器可写层。
func TestResolveHostPathNotMounted(t *testing.T) {
	if _, err := ResolveHostPath("/usr/share/nginx/ssl/a.pem", mounts); !errors.Is(err, ErrNotMounted) {
		t.Fatalf("期望 ErrNotMounted，实得 %v", err)
	}
	if _, err := ResolveHostPath("relative/path", mounts); !errors.Is(err, ErrNotMounted) {
		t.Error("相对路径应被拒绝")
	}
}

func TestResolveHostPathRootMount(t *testing.T) {
	ms := []Mount{{Type: "bind", Source: "/hostroot", Destination: "/"}}
	got, err := ResolveHostPath("/etc/nginx/a.pem", ms)
	if err != nil {
		t.Fatal(err)
	}
	if got.HostPath != "/hostroot/etc/nginx/a.pem" {
		t.Fatalf("根挂载解析错误: %q", got.HostPath)
	}
}

func TestChooseStrategy(t *testing.T) {
	bind := &Mount{Type: "bind", Source: "/data/certs", Destination: "/etc/nginx/certs"}
	vol := &Mount{Type: "volume", Source: "/var/lib/docker/volumes/c/_data", Destination: "/etc/nginx/certs"}

	cases := []struct {
		name string
		in   StrategyInput
		want WriteStrategy
	}{
		{"宿主机可写", StrategyInput{HostWritable: true}, WriteHost},
		{"宿主机需提权", StrategyInput{SudoAvailable: true}, WriteHostSudo},
		{"容器 bind 可写", StrategyInput{InContainer: true, Mount: bind, HostWritable: true}, WriteHost},
		{"容器 bind 需提权", StrategyInput{InContainer: true, Mount: bind, SudoAvailable: true}, WriteHostSudo},
		// named volume 即使宿主机「看起来」可写也走辅助容器：
		// /var/lib/docker/volumes 是 700 的 root 目录。
		{"named volume", StrategyInput{InContainer: true, Mount: vol, HostWritable: true}, WriteHelper},
		{"未命中挂载", StrategyInput{InContainer: true, Mount: nil}, WriteHelper},
		{"容器且都不可写", StrategyInput{InContainer: true, Mount: bind}, WriteHelper},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := ChooseStrategy(c.in)
			if got != c.want {
				t.Errorf("策略 = %q，期望 %q（理由：%s）", got, c.want, reason)
			}
			if reason == "" {
				t.Error("必须给出选择理由，否则界面上无法解释")
			}
		})
	}
}
