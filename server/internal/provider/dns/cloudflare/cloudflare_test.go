package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certpilot/server/internal/dnsx"
)

// newTestProvider 让 provider 指向本地假服务器。
func newTestProvider(t *testing.T, h http.HandlerFunc) (*Provider, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	p, err := New([]byte(`{"api_token":"test-token"}`))
	if err != nil {
		t.Fatal(err)
	}
	// 覆盖 base URL：用一个把请求改写到测试服务器的 transport。
	p.client = &http.Client{Transport: rewriteTo(srv.URL)}
	return p, srv.Close
}

type rewrite struct{ base string }

func rewriteTo(base string) http.RoundTripper { return &rewrite{base: base} }

func (r *rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	target := strings.TrimPrefix(r.base, "http://")
	u.Scheme = "http"
	u.Host = target
	req2 := req.Clone(req.Context())
	req2.URL = &u
	return http.DefaultTransport.RoundTrip(req2)
}

func ok(result any) string {
	b, _ := json.Marshal(map[string]any{
		"success": true, "errors": []any{}, "result": result,
		"result_info": map[string]int{"page": 1, "total_pages": 1},
	})
	return string(b)
}

func TestListZones(t *testing.T) {
	p, done := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ok([]map[string]string{
			{"id": "z1", "name": "example.com"},
			{"id": "z2", "name": "example.net"},
		})))
	})
	defer done()

	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 || zones[0].Name != "example.com" || zones[0].ProviderZoneID != "z1" {
		t.Fatalf("区域解析有误: %+v", zones)
	}
}

func TestPresentCreatesTXT(t *testing.T) {
	var created record
	p, done := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "dns_records"):
			w.Write([]byte(ok([]record{}))) // 没有旧记录
		case r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &created)
			w.Write([]byte(ok(record{ID: "r1"})))
		default:
			w.Write([]byte(ok([]any{})))
		}
	})
	defer done()

	m := &dnsx.Match{
		Domain: "example.com", RecordName: "_acme-challenge",
		FQDN: "_acme-challenge.example.com",
		Zone: dnsx.Zone{Name: "example.com", ProviderZoneID: "z1"},
	}
	if err := p.Present(context.Background(), m, "token-value"); err != nil {
		t.Fatal(err)
	}
	if created.Type != "TXT" || created.Name != m.FQDN || created.Content != "token-value" {
		t.Fatalf("写入的记录有误: %+v", created)
	}
}

// 清理时 Cloudflare 返回的内容带引号，比较前必须去掉，
// 否则会漏删自己刚写的记录。
func TestCleanUpStripsQuotes(t *testing.T) {
	deleted := []string{}
	p, done := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			parts := strings.Split(r.URL.Path, "/")
			deleted = append(deleted, parts[len(parts)-1])
			w.Write([]byte(ok(map[string]string{"id": "r1"})))
			return
		}
		w.Write([]byte(ok([]record{
			{ID: "r1", Name: "_acme-challenge.example.com", Type: "TXT", Content: `"token-value"`},
			{ID: "r2", Name: "_acme-challenge.example.com", Type: "TXT", Content: `"other"`},
		})))
	})
	defer done()

	m := &dnsx.Match{FQDN: "_acme-challenge.example.com",
		Zone: dnsx.Zone{Name: "example.com", ProviderZoneID: "z1"}}
	if err := p.CleanUp(context.Background(), m, "token-value"); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "r1" {
		t.Fatalf("应只删除内容匹配的那条，实得 %v", deleted)
	}
}

// value 为空时删除全部同名记录——失败路径也要清理干净。
func TestCleanUpDeletesAllWhenValueEmpty(t *testing.T) {
	deleted := 0
	p, done := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted++
			w.Write([]byte(ok(map[string]string{})))
			return
		}
		w.Write([]byte(ok([]record{{ID: "r1"}, {ID: "r2"}})))
	})
	defer done()

	m := &dnsx.Match{FQDN: "_acme-challenge.example.com",
		Zone: dnsx.Zone{Name: "example.com", ProviderZoneID: "z1"}}
	if err := p.CleanUp(context.Background(), m, ""); err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("应删除全部 2 条，实得 %d", deleted)
	}
}

// Cloudflare 业务失败时也返回 200，只在 success 字段体现。
// 不检查它会出现「调用成功但记录没写进去」。
func TestBusinessErrorOnHTTP200(t *testing.T) {
	p, done := newTestProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
	})
	defer done()

	_, err := p.ListZones(context.Background())
	if err == nil {
		t.Fatal("success=false 时应报错")
	}
	// 错误码要翻译成可行动的说明
	if !strings.Contains(err.Error(), "权限") {
		t.Errorf("未翻译成可行动的说明: %v", err)
	}
}

func TestMissingTokenRejected(t *testing.T) {
	if _, err := New([]byte(`{}`)); err == nil {
		t.Fatal("缺少 Token 时应报错")
	}
}
