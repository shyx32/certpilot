package notify

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ChannelSource 提供已启用的渠道，由 store 实现。
type ChannelSource interface {
	EnabledChannels(ctx context.Context) ([]ChannelSpec, error)
}

// ChannelSpec 是一个渠道的运行时描述。
type ChannelSpec struct {
	ID     int64
	Name   string
	Kind   string
	Events []string
	Config []byte
}

// Dispatcher 把消息分发到所有订阅了该事件的渠道。
type Dispatcher struct {
	source ChannelSource
}

func NewDispatcher(src ChannelSource) *Dispatcher {
	return &Dispatcher{source: src}
}

// Send 分发一条消息。
//
// 通知失败永远不影响主流程：证书已经签好了，发不出群消息不该让任务变成失败。
// 因此这里只记日志，不向上返回错误。
func (d *Dispatcher) Send(ctx context.Context, m *Message) {
	if d == nil || d.source == nil {
		return
	}
	channels, err := d.source.EnabledChannels(ctx)
	if err != nil {
		slog.Error("读取通知渠道失败", "err", err)
		return
	}

	// 单条消息的分发不该拖住调用方太久。
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for _, spec := range channels {
		if !Subscribed(spec.Events, m.Event) {
			continue
		}
		factory, ok := Lookup(spec.Kind)
		if !ok {
			slog.Warn("未知的通知渠道类型", "kind", spec.Kind, "channel", spec.Name)
			continue
		}
		wg.Add(1)
		go func(spec ChannelSpec, factory Factory) {
			defer wg.Done()
			sender, err := factory(spec.Config)
			if err != nil {
				slog.Error("构造通知渠道失败", "channel", spec.Name, "err", err)
				return
			}
			if err := sender.Send(ctx, m); err != nil {
				slog.Error("发送通知失败", "channel", spec.Name, "err", err)
			}
		}(spec, factory)
	}
	wg.Wait()
}
