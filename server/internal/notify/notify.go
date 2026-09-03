// Package notify 把事件送到聊天群或自定义端点。
//
// 一个设计取舍贯穿全包：**合并优先于及时**。20 个域名同时到期应该是
// 一条消息而不是 20 条——刷屏的告警等于没有告警。
package notify

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Level 决定消息的呈现方式与是否 @人。
type Level string

const (
	LevelInfo   Level = "info"
	LevelWarn   Level = "warn"
	LevelDanger Level = "danger"
)

func (l Level) Emoji() string {
	switch l {
	case LevelDanger:
		return "🔴"
	case LevelWarn:
		return "🟡"
	default:
		return "🟢"
	}
}

func (l Level) Label() string {
	switch l {
	case LevelDanger:
		return "严重"
	case LevelWarn:
		return "警告"
	default:
		return "通知"
	}
}

// Event 是事件类型，用于订阅过滤。
type Event string

const (
	EventIssued       Event = "issued"        // 证书签发成功
	EventIssueFailed  Event = "issue_failed"  // 签发或续期失败
	EventDeployFailed Event = "deploy_failed" // 部署失败
	EventExpiring     Event = "expiring"      // 临期
	EventHealth       Event = "health"        // 巡检发现问题
	EventCredential   Event = "credential"    // 凭据失效
)

// KnownEvents 按固定顺序返回全部事件类型，供界面渲染。
func KnownEvents() []Event {
	return []Event{EventIssued, EventIssueFailed, EventDeployFailed,
		EventExpiring, EventHealth, EventCredential}
}

var eventLabels = map[Event]string{
	EventIssued:       "证书签发成功",
	EventIssueFailed:  "签发或续期失败",
	EventDeployFailed: "部署失败",
	EventExpiring:     "证书临期",
	EventHealth:       "巡检发现问题",
	EventCredential:   "凭据失效",
}

func (e Event) Label() string {
	if l, ok := eventLabels[e]; ok {
		return l
	}
	return string(e)
}

// Message 是一条待发送的通知。
type Message struct {
	Event Event
	Level Level
	Title string
	// Lines 是正文，每行一条。已经是合并后的结果。
	Lines []string
	// Footer 通常放访问链接或时间。
	Footer string
}

// Text 渲染成纯文本，适合大多数渠道。
func (m *Message) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", m.Level.Emoji(), m.Title)
	for _, l := range m.Lines {
		b.WriteString("\n")
		b.WriteString(l)
	}
	if m.Footer != "" {
		b.WriteString("\n\n")
		b.WriteString(m.Footer)
	}
	return b.String()
}

// Markdown 渲染成 Markdown，供支持的渠道使用。
func (m *Message) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "### %s %s\n", m.Level.Emoji(), m.Title)
	for _, l := range m.Lines {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	if m.Footer != "" {
		fmt.Fprintf(&b, "\n> %s", m.Footer)
	}
	return b.String()
}

// Sender 是一个通知渠道。
type Sender interface {
	Send(ctx context.Context, m *Message) error
}

// Factory 按渠道配置构造 Sender。
type Factory func(config []byte) (Sender, error)

var registry = map[string]Factory{}

// Register 注册一种渠道。
func Register(kind string, f Factory) { registry[kind] = f }

// Lookup 取出构造器。
func Lookup(kind string) (Factory, bool) { f, ok := registry[kind]; return f, ok }

// Kinds 列出已注册的渠道类型，供界面渲染。
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ErrNotConfigured 表示渠道配置不完整。
var ErrNotConfigured = errors.New("notify: 渠道配置不完整")

// Subscribed 判断某渠道是否订阅了该事件。
//
// 空订阅列表表示订阅全部——新建渠道时不填就能收到所有消息，
// 比要求用户先勾一遍更符合预期。
func Subscribed(events []string, e Event) bool {
	if len(events) == 0 {
		return true
	}
	for _, s := range events {
		if Event(s) == e {
			return true
		}
	}
	return false
}
