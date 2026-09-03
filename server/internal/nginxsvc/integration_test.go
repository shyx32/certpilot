//go:build integration

// 针对一台真实的 SSH + nginx 目标机跑通探测与部署。
//
// 用 test/target 里的镜像起一台目标机后运行：
//
//	CP_TEST_SSH_HOST=127.0.0.1 CP_TEST_SSH_PORT=2222 \
//	CP_TEST_SSH_USER=deploy CP_TEST_SSH_KEY=/tmp/cp_test_key \
//	go test -tags integration ./internal/nginxsvc/ -v
package nginxsvc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/server/internal/sshx"
)

func dialTarget(t *testing.T) *sshx.Client {
	t.Helper()
	host := os.Getenv("CP_TEST_SSH_HOST")
	if host == "" {
		t.Skip("未设置 CP_TEST_SSH_HOST，跳过集成测试")
	}
	port, _ := strconv.Atoi(os.Getenv("CP_TEST_SSH_PORT"))
	if port == 0 {
		port = 22
	}
	key, err := os.ReadFile(os.Getenv("CP_TEST_SSH_KEY"))
	if err != nil {
		t.Fatalf("读取测试私钥失败: %v", err)
	}

	c, err := sshx.Dial(context.Background(), &sshx.Target{
		Host: host, Port: port,
		User: os.Getenv("CP_TEST_SSH_USER"),
		Auth: sshx.Auth{PrivateKeyPEM: key},
	})
	if err != nil {
		t.Fatalf("连接目标机失败: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestIntegrationSSHConnectAndFingerprint(t *testing.T) {
	c := dialTarget(t)
	if c.SeenFingerprint == "" {
		t.Fatal("未取得主机指纹，首次接入无法固化")
	}
	if !strings.HasPrefix(c.SeenFingerprint, "SHA256:") {
		t.Errorf("指纹格式异常: %s", c.SeenFingerprint)
	}
	t.Logf("主机指纹 %s", c.SeenFingerprint)
}

// 转义必须在真实 shell 上成立，而不只是在单元测试里。
func TestIntegrationQuotingAgainstRealShell(t *testing.T) {
	c := dialTarget(t)
	ctx := context.Background()

	hostile := []string{
		"; touch /tmp/pwned_semicolon",
		"$(touch /tmp/pwned_subshell)",
		"`touch /tmp/pwned_backtick`",
		"&& touch /tmp/pwned_and",
		"| tee /tmp/pwned_pipe",
	}
	for _, h := range hostile {
		// 把恶意串作为 echo 的参数：如果转义失效，副作用文件会被创建。
		res, err := c.Run(ctx, []string{"echo", h})
		if err != nil {
			t.Fatalf("执行失败: %v", err)
		}
		if res.Stdout != h {
			t.Errorf("参数被 shell 改写：传入 %q，回显 %q", h, res.Stdout)
		}
	}

	check, err := c.Run(ctx, []string{"sh", "-c", "ls /tmp/pwned_* 2>/dev/null | wc -l"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(check.Stdout) != "0" {
		t.Fatalf("shell 元字符逃逸了，产生了副作用文件：%s", check.Stdout)
	}
}

func TestIntegrationDetect(t *testing.T) {
	c := dialTarget(t)
	d, err := Detect(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Services) != 1 {
		t.Fatalf("应探测到 1 个 nginx，实得 %d（notes: %v）", len(d.Services), d.Notes)
	}

	svc := d.Services[0]
	t.Logf("形态=%s 策略=%s（%s）", svc.Kind, svc.WriteStrategy, svc.StrategyReason)

	if svc.Kind != KindBare {
		t.Errorf("容器里没有 systemd，应识别为 %s，实得 %s", KindBare, svc.Kind)
	}
	if strings.Join(svc.ReloadArgv, " ") != "nginx -s reload" {
		t.Errorf("重载命令 = %v", svc.ReloadArgv)
	}
	// nginx -T 应该发现 site.conf 里配置的证书
	if len(svc.Certs) != 1 {
		t.Fatalf("应发现 1 张证书，实得 %d: %+v", len(svc.Certs), svc.Certs)
	}
	cert := svc.Certs[0]
	if cert.CertPath != "/etc/nginx/certs/test.local/fullchain.pem" {
		t.Errorf("证书路径 = %q", cert.CertPath)
	}
	if len(cert.Domains) != 2 {
		t.Errorf("应发现 2 个域名，实得 %v", cert.Domains)
	}
	// deploy 用户对证书目录有写权限，应判定为直写
	if svc.WriteStrategy != WriteHost {
		t.Errorf("证书目录可写时应直写，实得 %s（%s）", svc.WriteStrategy, svc.StrategyReason)
	}
	// 这台目标机刻意配置成「能写证书目录、但 nginx 主进程是 root」，
	// 正是生产里最常见的组合。
	if !svc.ReloadNeedsSudo {
		t.Error("nginx 主进程以 root 运行，应判定重载需要提权")
	}
}

// 完整走一遍部署：写入、预检、替换、重载，并确认线上证书真的换了。
func TestIntegrationDeployReplacesLiveCertificate(t *testing.T) {
	c := dialTarget(t)
	ctx := context.Background()

	d, err := Detect(ctx, c)
	if err != nil || len(d.Services) == 0 {
		t.Fatalf("探测失败: %v", err)
	}
	svc := &d.Services[0]

	before := readRemote(t, c, "/etc/nginx/certs/test.local/fullchain.pem")
	certPEM, keyPEM := selfSigned(t, "integration-test.example")

	res, err := Deploy(ctx, c, svc, &Material{
		CertPath:     "/etc/nginx/certs/test.local/fullchain.pem",
		KeyPath:      "/etc/nginx/certs/test.local/privkey.pem",
		FullChainPEM: certPEM,
		KeyPEM:       keyPEM,
	}, time.Now().UTC().Format("20060102150405"))
	if err != nil {
		t.Fatalf("部署失败: %v（步骤: %v）", err, res.Steps)
	}
	t.Logf("部署步骤: %v", res.Steps)

	after := readRemote(t, c, "/etc/nginx/certs/test.local/fullchain.pem")
	if after == before {
		t.Fatal("证书文件内容没有变化")
	}
	// Run 会去掉尾部换行，比较时对齐
	if strings.TrimSpace(after) != strings.TrimSpace(string(certPEM)) {
		t.Errorf("远端证书与下发内容不一致\n远端:\n%s\n下发:\n%s", after, certPEM)
	}

	// 私钥权限必须是 600——它和证书不同，不能让同机其他用户读到。
	perm := run(t, c, []string{"stat", "-c", "%a", "/etc/nginx/certs/test.local/privkey.pem"})
	if strings.TrimSpace(perm) != "600" {
		t.Errorf("私钥权限 = %s，应为 600", perm)
	}
	// 备份应该留下了
	baks := run(t, c, []string{"sh", "-c", "ls /etc/nginx/certs/test.local/*.bak.* 2>/dev/null | wc -l"})
	if strings.TrimSpace(baks) == "0" {
		t.Error("没有留下备份文件，回滚将无从依据")
	}
	// 临时文件应该被清理
	news := run(t, c, []string{"sh", "-c", "ls /etc/nginx/certs/test.local/*.new 2>/dev/null | wc -l"})
	if strings.TrimSpace(news) != "0" {
		t.Errorf("临时文件未清理: %s", news)
	}
}

// 预检失败时必须中止，绝不能碰线上文件。
func TestIntegrationPreflightFailureLeavesLiveFileIntact(t *testing.T) {
	c := dialTarget(t)
	ctx := context.Background()

	d, _ := Detect(ctx, c)
	if len(d.Services) == 0 {
		t.Skip("未探测到服务")
	}
	svc := &d.Services[0]
	before := readRemote(t, c, "/etc/nginx/certs/test.local/fullchain.pem")

	// 下发一份不是证书的内容，nginx -t 会拒绝
	_, err := Deploy(ctx, c, svc, &Material{
		CertPath:     "/etc/nginx/certs/test.local/fullchain.pem",
		KeyPath:      "/etc/nginx/certs/test.local/privkey.pem",
		FullChainPEM: []byte("this is not a certificate\n"),
		KeyPEM:       []byte("neither is this\n"),
	}, "badts")
	if err == nil {
		t.Fatal("下发非法证书时应当失败")
	}
	t.Logf("如期失败: %v", err)

	// 预检失败后必须回滚到原内容
	after := readRemote(t, c, "/etc/nginx/certs/test.local/fullchain.pem")
	if strings.TrimSpace(after) != strings.TrimSpace(before) {
		t.Fatal("预检失败后没有回滚，线上证书被改动了")
	}
	// nginx 必须仍然可用（用与部署相同的权限执行）
	testArgv := svc.TestArgv
	if svc.ReloadNeedsSudo {
		testArgv = sshx.WithSudo(testArgv)
	}
	if out := run(t, c, testArgv); !strings.Contains(out, "successful") {
		t.Errorf("失败后 nginx 配置不再有效: %s", out)
	}
}

func run(t *testing.T, c *sshx.Client, argv []string) string {
	t.Helper()
	res, err := c.Run(context.Background(), argv)
	if err != nil {
		t.Fatalf("执行 %v 失败: %v", argv, err)
	}
	return res.Combined()
}

func readRemote(t *testing.T, c *sshx.Client, path string) string {
	t.Helper()
	return run(t, c, []string{"cat", path})
}

// selfSigned 生成一张自签证书，内容每次都不同。
func selfSigned(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
