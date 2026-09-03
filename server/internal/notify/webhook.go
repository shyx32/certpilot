package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func init() {
	Register("dingtalk", func(c []byte) (Sender, error) { return newHook(c, renderDingTalk) })
	Register("wecom", func(c []byte) (Sender, error) { return newHook(c, renderWeCom) })
	Register("feishu", func(c []byte) (Sender, error) { return newHook(c, renderFeishu) })
	Register("webhook", func(c []byte) (Sender, error) { return newHook(c, renderGeneric) })
}

// hookConfig 是所有 webhook 类渠道的共同配置。
type hookConfig struct {
	URL string `json:"url"`
	// Keyword 供钉钉「自定义关键词」安全设置使用：
	// 机器人会拒绝不含该词的消息。
	Keyword string `json:"keyword,omitempty"`
}

type renderer func(m *Message, cfg hookConfig) any

type hookSender struct {
	cfg    hookConfig
	render renderer
}

func newHook(raw []byte, r renderer) (Sender, error) {
	var c hookConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("notify: 配置无法解析: %w", err)
	}
	if c.URL == "" {
		return nil, fmt.Errorf("%w：缺少 Webhook 地址", ErrNotConfigured)
	}
	return &hookSender{cfg: c, render: r}, nil
}

func (h *hookSender) Send(ctx context.Context, m *Message) error {
	body, err := json.Marshal(h.render(m, h.cfg))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("发送失败：%w", err)
	}
	defer resp.Body.Close()

	// 这些平台即使业务失败也常返回 200，因此正文要读出来放进错误里，
	// 否则用户只会看到「发送成功」但群里什么都没有。
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("对端返回 %d：%s", resp.StatusCode, truncate(string(respBody), 200))
	}
	return checkPlatformError(respBody)
}

// checkPlatformError 解析各平台统一的 errcode 字段。
func checkPlatformError(body []byte) error {
	var r struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
		Code    int    `json:"code"`
		Msg     string `json:"msg"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil // 不是这种格式，按成功处理
	}
	if r.ErrCode != 0 {
		return fmt.Errorf("对端拒绝（errcode %d）：%s", r.ErrCode, r.ErrMsg)
	}
	if r.Code != 0 {
		return fmt.Errorf("对端拒绝（code %d）：%s", r.Code, r.Msg)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func renderDingTalk(m *Message, cfg hookConfig) any {
	text := m.Markdown()
	// 钉钉的关键词校验发生在服务端，缺了它整条消息会被丢弃。
	if cfg.Keyword != "" {
		text = cfg.Keyword + "\n" + text
	}
	return map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"title": m.Title, "text": text},
	}
}

func renderWeCom(m *Message, _ hookConfig) any {
	return map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"content": m.Markdown()},
	}
}

func renderFeishu(m *Message, _ hookConfig) any {
	return map[string]any{
		"msg_type": "text",
		"content":  map[string]string{"text": m.Text()},
	}
}

// renderGeneric 是通用 Webhook：把结构化数据原样发出去，
// 让接收方自己决定怎么处理。这条路径让所有没有内置支持的场景都有出路。
func renderGeneric(m *Message, _ hookConfig) any {
	return map[string]any{
		"event": string(m.Event),
		"level": string(m.Level),
		"title": m.Title,
		"lines": m.Lines,
		"text":  m.Text(),
	}
}
