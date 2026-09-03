package nginxsvc

import (
	"reflect"
	"testing"
)

const dump = `
# configuration file /etc/nginx/nginx.conf:
user nginx;
http {
    include /etc/nginx/conf.d/*.conf;

# configuration file /etc/nginx/conf.d/site.conf:
    server {
        listen 80;
        server_name example.com www.example.com;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name example.com www.example.com;
        ssl_certificate     /etc/nginx/certs/example.com/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/example.com/privkey.pem;

        location / {
            proxy_pass http://app:3000;
        }
        location /health { return 200; }
    }

    server {
        listen 443 ssl;
        server_name api.example.com;
        ssl_certificate "/etc/nginx/certs/api/fullchain.pem";
        ssl_certificate_key '/etc/nginx/certs/api/privkey.pem';
    }

    # 共用同一张证书的另一个站点
    server {
        listen 443 ssl;
        server_name shop.example.com;
        ssl_certificate     /etc/nginx/certs/example.com/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/example.com/privkey.pem;
    }
}
`

func TestParseServers(t *testing.T) {
	got := ParseServers(dump)
	if len(got) != 3 {
		t.Fatalf("应解析出 3 个带证书的 server 块，实得 %d: %+v", len(got), got)
	}

	if !reflect.DeepEqual(got[0].Names, []string{"example.com", "www.example.com"}) {
		t.Errorf("第一个块域名 = %v", got[0].Names)
	}
	if got[0].CertPath != "/etc/nginx/certs/example.com/fullchain.pem" {
		t.Errorf("证书路径 = %q", got[0].CertPath)
	}
	if !got[0].TLS {
		t.Error("listen 443 ssl 应被识别为 TLS")
	}
	// 引号要去掉，否则拼出来的路径在远端不存在。
	if got[1].CertPath != "/etc/nginx/certs/api/fullchain.pem" {
		t.Errorf("带引号的路径未去引号: %q", got[1].CertPath)
	}
	if got[1].KeyPath != "/etc/nginx/certs/api/privkey.pem" {
		t.Errorf("单引号路径未去引号: %q", got[1].KeyPath)
	}
}

// 纯 80 端口的跳转块没有证书，不应出现在结果里。
func TestParseServersSkipsNonTLS(t *testing.T) {
	for _, b := range ParseServers(dump) {
		if b.CertPath == "" {
			t.Fatal("出现了没有证书的 server 块")
		}
	}
}

// location 块的花括号不能让解析器提前结束 server 块。
func TestParseServersHandlesNestedBlocks(t *testing.T) {
	got := ParseServers(dump)
	if got[0].CertPath == "" {
		t.Fatal("含 location 嵌套的 server 块解析失败")
	}
}

func TestParseServersInheritsHttpLevelCert(t *testing.T) {
	cfg := `
http {
    ssl_certificate     /etc/ssl/default.pem;
    ssl_certificate_key /etc/ssl/default.key;
    server {
        listen 443 ssl;
        server_name fallback.example.com;
    }
}`
	got := ParseServers(cfg)
	if len(got) != 1 || got[0].CertPath != "/etc/ssl/default.pem" {
		t.Fatalf("未继承 http 级别的证书指令: %+v", got)
	}
}

// server_name _ 是 nginx 的默认站点占位，不是真实域名。
func TestParseServersSkipsUnderscoreName(t *testing.T) {
	cfg := `
server {
    listen 443 ssl;
    server_name _ real.example.com;
    ssl_certificate /a.pem;
}`
	got := ParseServers(cfg)
	if len(got) != 1 {
		t.Fatalf("实得 %d 个块", len(got))
	}
	if !reflect.DeepEqual(got[0].Names, []string{"real.example.com"}) {
		t.Errorf("下划线占位未被过滤: %v", got[0].Names)
	}
}

func TestParseServersIgnoresComments(t *testing.T) {
	cfg := `
server {
    # ssl_certificate /commented/out.pem;
    listen 443 ssl;
    server_name c.example.com;
    ssl_certificate /real.pem;   # 行尾注释
}`
	got := ParseServers(cfg)
	if len(got) != 1 || got[0].CertPath != "/real.pem" {
		t.Fatalf("注释处理有误: %+v", got)
	}
}

// 归并是为了让界面显示「1 张证书覆盖 3 个域名」，而不是 3 行重复项。
func TestGroupByCert(t *testing.T) {
	got := GroupByCert(ParseServers(dump))
	if len(got) != 2 {
		t.Fatalf("应归并成 2 张证书，实得 %d: %+v", len(got), got)
	}
	first := got[0]
	want := []string{"example.com", "www.example.com", "shop.example.com"}
	if !reflect.DeepEqual(first.Domains, want) {
		t.Errorf("共用证书的域名未合并: %v", first.Domains)
	}
	if first.KeyPath == "" {
		t.Error("私钥路径丢失")
	}
}

func TestParseServersEmpty(t *testing.T) {
	if got := ParseServers(""); len(got) != 0 {
		t.Fatalf("空输入应返回空结果，实得 %+v", got)
	}
}
