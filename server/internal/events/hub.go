// Package events 是进程内的事件总线，负责把任务进度推给正在观看的浏览器。
package events

import (
	"sync"
)

// Event 是一条推送给界面的消息。
type Event struct {
	Type    string `json:"type"` // job_log | job_state | cert_updated
	JobID   int64  `json:"job_id,omitempty"`
	Stage   string `json:"stage,omitempty"`
	Level   string `json:"level,omitempty"`
	Message string `json:"message,omitempty"`
	At      string `json:"at,omitempty"`
}

// Hub 把事件广播给所有订阅者。
//
// 单进程内存实现——多副本时每个副本只推自己处理的任务，
// 而界面本来就会在重连时补拉一次完整日志，所以这个取舍是安全的。
type Hub struct {
	mu   sync.RWMutex
	subs map[chan Event]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: make(map[chan Event]struct{})}
}

// Subscribe 返回一个事件通道与取消函数。
func (h *Hub) Subscribe() (<-chan Event, func()) {
	// 带缓冲，慢消费者不会阻塞发布方。
	ch := make(chan Event, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()

	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Publish 广播一条事件。订阅者缓冲满时丢弃该条，
// 绝不阻塞正在跑签发的流水线。
func (h *Hub) Publish(e Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Count 返回当前订阅者数量，用于健康检查与调试。
func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}
