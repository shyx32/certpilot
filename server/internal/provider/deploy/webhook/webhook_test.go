package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/server/internal/provider/deploy"
)

func bundle() *deploy.Bundle {
	return &deploy.Bundle{
		Domains:     []string{"example.com"},
		CertPEM:     []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"),
		ChainPEM:    []byte("-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n"),
		KeyPEM:      []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"),
		Fingerprint: "abc123",
		NotAfter:    time.Now().Add(60 * 24 * time.Hour),
	}
}

func newTarget(t *testing.T, cfg map[string]any, h http.HandlerFunc) *Deployer {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg["url"] = srv.URL
	raw, _ := json.Marshal(cfg)
	d, err := New(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDeploySendsCertificate(t *testing.T) {
	var got payload
	d := newTarget(t, map[string]any{}, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	})

	if err := d.Deploy(context.Background(), bundle()); err != nil {
		t.Fatal(err)
	}
	if got.Event != "certificate" || got.Fingerprint != "abc123" {
		t.Fatalf("载荷有误: %+v", got)
	}
	// fullchain 必须是 leaf + chain，缺中间证书会让部分客户端失败
	if !strings.Contains(got.FullChain, "leaf") || !strings.Contains(got.FullChain, "chain") {
		t.Errorf("fullchain 不完整: %q", got.FullChain)
	}
	if got.Key == "" {
		t.Error("默认应包含私钥，否则对端多半用不了")
	}
}

// 私钥离开本系统是重大决定，必须能关掉。
func TestIncludeKeyCanBeDisabled(t *testing.T) {
	var got payload
	no := false
	d := newTarget(t, map[string]any{"include_key": &no}, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
	})
	if err := d.Deploy(context.Background(), bundle()); err != nil {
		t.Fatal(err)
	}
	if got.Key != "" {
		t.Fatal("关闭后仍然发送了私钥")
	}
	if got.FullChain == "" {
		t.Error("证书本身仍应发送")
	}
}

// 签名让对端能确认请求确实来自本系统。
func TestSigningSecretProducesValidHMAC(t *testing.T) {
	var sig string
	var body []byte
	d := newTarget(t, map[string]any{"signing_secret": "s3cret"}, func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get("X-CertPilot-Signature")
		body, _ = io.ReadAll(r.Body)
	})
	if err := d.Deploy(context.Background(), bundle()); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig != want {
		t.Fatalf("签名不匹配\n实得 %s\n期望 %s", sig, want)
	}
}

func TestCustomHeadersSent(t *testing.T) {
	var token string
	d := newTarget(t, map[string]any{"headers": map[string]string{"X-Api-Key": "k1"}},
		func(w http.ResponseWriter, r *http.Request) { token = r.Header.Get("X-Api-Key") })
	if err := d.Deploy(context.Background(), bundle()); err != nil {
		t.Fatal(err)
	}
	if token != "k1" {
		t.Fatalf("自定义请求头未发送: %q", token)
	}
}

// 对端的失败原因必须带回来，否则用户只看到一句没信息量的「部署失败」。
func TestErrorIncludesResponseBody(t *testing.T) {
	d := newTarget(t, map[string]any{}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bucket not found"))
	})
	err := d.Deploy(context.Background(), bundle())
	if err == nil || !strings.Contains(err.Error(), "bucket not found") {
		t.Fatalf("错误未带上对端原因: %v", err)
	}
}

// Validate 是连通性测试，绝不能把证书发出去。
func TestValidateSendsNoCertificate(t *testing.T) {
	var body []byte
	d := newTarget(t, map[string]any{}, func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
	})
	if err := d.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "BEGIN") {
		t.Fatalf("连通性测试泄露了证书内容: %s", body)
	}
}

func TestRejectsBadConfig(t *testing.T) {
	if _, err := New([]byte(`{}`), nil); err == nil {
		t.Error("缺少 URL 时应报错")
	}
	if _, err := New([]byte(`{"url":"ftp://x"}`), nil); err == nil {
		t.Error("非 http(s) 地址应被拒绝")
	}
}

// 没有可拨测的域名时跳过，不能假装失败。
func TestVerifySkipsWithoutDomains(t *testing.T) {
	d := newTarget(t, map[string]any{}, func(w http.ResponseWriter, _ *http.Request) {})
	if err := d.Verify(context.Background(), bundle()); err != nil {
		t.Fatalf("未配置拨测域名时应跳过: %v", err)
	}
}
