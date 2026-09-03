// Package cloudflare 是 Cloudflare DNS 的 provider 实现。
//
// 直接调 REST API 而不引入官方 SDK：只用到 zones 与 dns_records 两组接口，
// 为此背上一个大依赖不划算。
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/certpilot/server/internal/dnsx"
	dnsprov "github.com/certpilot/server/internal/provider/dns"
)

func init() {
	dnsprov.Register("cloudflare", func(ctx context.Context, secret []byte) (dnsprov.Provider, error) {
		return New(secret)
	})
}

const apiBase = "https://api.cloudflare.com/client/v4"

// Credential 是 Cloudflare 凭据。
//
// 推荐使用 API Token 而非 Global API Key：Token 可以只授予
// 「区域 - DNS - 编辑」权限，泄露后的影响面小得多。
type Credential struct {
	APIToken string `json:"api_token"`
}

type Provider struct {
	token  string
	client *http.Client
}

func New(secret []byte) (*Provider, error) {
	var c Credential
	if err := json.Unmarshal(secret, &c); err != nil {
		return nil, fmt.Errorf("cloudflare: 凭据无法解析: %w", err)
	}
	if c.APIToken == "" {
		return nil, fmt.Errorf("cloudflare: 缺少 API Token")
	}
	return &Provider{token: c.APIToken, client: &http.Client{Timeout: 30 * time.Second}}, nil
}

// apiResponse 是 Cloudflare 统一的响应外壳。
type apiResponse struct {
	Success bool            `json:"success"`
	Errors  []apiError      `json:"errors"`
	Result  json.RawMessage `json:"result"`
	Info    struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// call 发起一次 API 调用并解开外壳。
//
// Cloudflare 业务失败时也可能返回 200，因此必须检查 success 字段，
// 否则会出现「调用成功但记录没写进去」。
func (p *Provider) call(ctx context.Context, method, path string, body any) (*apiResponse, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 Cloudflare 失败：%w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var out apiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("Cloudflare 返回了无法解析的内容（HTTP %d）", resp.StatusCode)
	}
	if !out.Success {
		return nil, fmt.Errorf("Cloudflare 拒绝了请求：%s", explain(out.Errors))
	}
	return &out, nil
}

// explain 把错误码翻译成可行动的说明。
func explain(errs []apiError) string {
	if len(errs) == 0 {
		return "未提供原因"
	}
	e := errs[0]
	switch e.Code {
	case 10000:
		return "API Token 无效或权限不足，请确认它有「区域 - DNS - 编辑」权限。"
	case 81044, 81045:
		return "找不到对应的 DNS 记录。"
	case 81057:
		return "已存在同名记录。"
	}
	return fmt.Sprintf("%s（code %d）", e.Message, e.Code)
}

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ListZones 拉取该 Token 可管理的全部区域。
func (p *Provider) ListZones(ctx context.Context) ([]dnsx.Zone, error) {
	out := []dnsx.Zone{}
	for page := 1; page <= 100; page++ {
		resp, err := p.call(ctx, http.MethodGet,
			fmt.Sprintf("/zones?per_page=50&page=%d", page), nil)
		if err != nil {
			return nil, err
		}
		var zones []zone
		if err := json.Unmarshal(resp.Result, &zones); err != nil {
			return nil, err
		}
		for _, z := range zones {
			out = append(out, dnsx.Zone{Name: z.Name, ProviderZoneID: z.ID})
		}
		if len(zones) == 0 || page >= resp.Info.TotalPages {
			break
		}
	}
	return out, nil
}

// zoneID 解析出 zone 的 Cloudflare ID。
//
// 优先用已缓存的 ProviderZoneID，避免每次都多一次查询。
func (p *Provider) zoneID(ctx context.Context, m *dnsx.Match) (string, error) {
	if m.Zone.ProviderZoneID != "" {
		return m.Zone.ProviderZoneID, nil
	}
	resp, err := p.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(m.Zone.Name), nil)
	if err != nil {
		return "", err
	}
	var zones []zone
	if err := json.Unmarshal(resp.Result, &zones); err != nil {
		return "", err
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("这个 Token 下找不到区域 %s", m.Zone.Name)
	}
	return zones[0].ID, nil
}

type record struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

func (p *Provider) Present(ctx context.Context, m *dnsx.Match, value string) error {
	// 先清掉同名旧记录，避免 CA 读到上一轮遗留的值。
	if err := p.CleanUp(ctx, m, ""); err != nil {
		return err
	}
	zid, err := p.zoneID(ctx, m)
	if err != nil {
		return err
	}
	_, err = p.call(ctx, http.MethodPost, "/zones/"+zid+"/dns_records", record{
		Name: m.FQDN, Type: "TXT", Content: value, TTL: 120,
	})
	if err != nil {
		return fmt.Errorf("写入 TXT 记录 %s 失败：%w", m.FQDN, err)
	}
	return nil
}

func (p *Provider) CleanUp(ctx context.Context, m *dnsx.Match, value string) error {
	zid, err := p.zoneID(ctx, m)
	if err != nil {
		return err
	}
	resp, err := p.call(ctx, http.MethodGet,
		fmt.Sprintf("/zones/%s/dns_records?type=TXT&name=%s", zid, url.QueryEscape(m.FQDN)), nil)
	if err != nil {
		return fmt.Errorf("查询 TXT 记录 %s 失败：%w", m.FQDN, err)
	}
	var records []record
	if err := json.Unmarshal(resp.Result, &records); err != nil {
		return err
	}
	for _, r := range records {
		// Cloudflare 返回的 TXT 内容带引号，比较前去掉。
		if value != "" && strings.Trim(r.Content, `"`) != value {
			continue
		}
		if _, err := p.call(ctx, http.MethodDelete, "/zones/"+zid+"/dns_records/"+r.ID, nil); err != nil {
			return fmt.Errorf("删除 TXT 记录失败：%w", err)
		}
	}
	return nil
}

// Check 用一次只读调用验证凭据。
func (p *Provider) Check(ctx context.Context) error {
	_, err := p.call(ctx, http.MethodGet, "/zones?per_page=1", nil)
	return err
}
