package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func msg() *Message {
	return &Message{
		Event: EventHealth,
		Level: LevelDanger,
		Title: "巡检发现 3 个问题",
		Lines: []string{
			"api.example.com：线上证书与本地最新一版不一致",
			"shop.example.com：还有 3 天到期",
		},
		Footer: "2026-09-03 04:00",
	}
}

func TestMessageRendering(t *testing.T) {
	m := msg()
	text := m.Text()
	if !strings.Contains(text, m.Title) {
		t.Error("正文缺少标题")
	}
	for _, l := range m.Lines {
		if !strings.Contains(text, l) {
			t.Errorf("正文缺少内容: %s", l)
		}
	}
	if !strings.Contains(text, "🔴") {
		t.Error("严重级别应有视觉标记")
	}
	if !strings.Contains(m.Markdown(), "- "+m.Lines[0]) {
		t.Error("Markdown 未渲染成列表")
	}
}

func newTestChannel(t *testing.T, kind string, extra map[string]string) (Sender, *[]string) {
	t.Helper()
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.Write([]byte(`{"errcode":0}`))
	}))
	t.Cleanup(srv.Close)

	cfg := map[string]string{"url": srv.URL}
	for k, v := range extra {
		cfg[k] = v
	}
	raw, _ := json.Marshal(cfg)
	f, ok := Lookup(kind)
	if !ok {
		t.Fatalf("渠道 %s 未注册", kind)
	}
	s, err := f(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s, &bodies
}

func TestAllChannelsSend(t *testing.T) {
	for _, kind := range Kinds() {
		t.Run(kind, func(t *testing.T) {
			s, bodies := newTestChannel(t, kind, nil)
			if err := s.Send(context.Background(), msg()); err != nil {
				t.Fatal(err)
			}
			if len(*bodies) != 1 {
				t.Fatalf("应发送 1 条，实得 %d", len(*bodies))
			}
			// 内容必须真的带上，而不是只发了个空壳
			if !strings.Contains((*bodies)[0], "api.example.com") {
				t.Errorf("消息内容丢失: %s", (*bodies)[0])
			}
		})
	}
}

// 钉钉的关键词校验在服务端，缺了它整条消息会被静默丢弃。
func TestDingTalkIncludesKeyword(t *testing.T) {
	s, bodies := newTestChannel(t, "dingtalk", map[string]string{"keyword": "CertPilot"})
	if err := s.Send(context.Background(), msg()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains((*bodies)[0], "CertPilot") {
		t.Fatalf("未带上关键词: %s", (*bodies)[0])
	}
}

// 这些平台业务失败时也返回 HTTP 200，只在 body 里给 errcode。
// 不解析它就会出现「显示成功但群里没消息」。
func TestPlatformErrorIsSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"errcode":310000,"errmsg":"keywords not in content"}`))
	}))
	defer srv.Close()

	raw, _ := json.Marshal(map[string]string{"url": srv.URL})
	f, _ := Lookup("dingtalk")
	s, _ := f(raw)

	err := s.Send(context.Background(), msg())
	if err == nil {
		t.Fatal("平台返回 errcode 时应报错，否则用户会以为发送成功了")
	}
	if !strings.Contains(err.Error(), "310000") || !strings.Contains(err.Error(), "keywords") {
		t.Errorf("错误信息应包含平台原因: %v", err)
	}
}

func TestHTTPErrorIncludesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("token invalid"))
	}))
	defer srv.Close()

	raw, _ := json.Marshal(map[string]string{"url": srv.URL})
	f, _ := Lookup("webhook")
	s, _ := f(raw)

	err := s.Send(context.Background(), msg())
	if err == nil || !strings.Contains(err.Error(), "token invalid") {
		t.Fatalf("错误应包含对端正文以便排查: %v", err)
	}
}

func TestMissingURLRejected(t *testing.T) {
	for _, kind := range Kinds() {
		f, _ := Lookup(kind)
		if _, err := f([]byte(`{}`)); err == nil {
			t.Errorf("%s: 缺少 URL 时应报错", kind)
		}
	}
}

// 通用 Webhook 要发结构化数据，让接收方自己处理。
func TestGenericWebhookIsStructured(t *testing.T) {
	s, bodies := newTestChannel(t, "webhook", nil)
	if err := s.Send(context.Background(), msg()); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Event string   `json:"event"`
		Level string   `json:"level"`
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal([]byte((*bodies)[0]), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Event != "health" || payload.Level != "danger" {
		t.Errorf("结构化字段有误: %+v", payload)
	}
	if len(payload.Lines) != 2 {
		t.Errorf("明细行丢失: %v", payload.Lines)
	}
}

// 不填订阅表示订阅全部——新建渠道时不勾也能收到消息。
func TestSubscribedDefaultsToAll(t *testing.T) {
	if !Subscribed(nil, EventHealth) {
		t.Error("空订阅应视为订阅全部")
	}
	if !Subscribed([]string{"health", "issued"}, EventHealth) {
		t.Error("显式订阅未生效")
	}
	if Subscribed([]string{"issued"}, EventHealth) {
		t.Error("未订阅的事件不应通过")
	}
}
