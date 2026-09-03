package events

import (
	"testing"
	"time"
)

func TestPublishReachesSubscribers(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe()
	defer cancel()

	h.Publish(Event{Type: "job_log", Message: "hello"})
	select {
	case e := <-ch:
		if e.Message != "hello" {
			t.Fatalf("收到 %q", e.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("订阅者没有收到事件")
	}
}

// 慢消费者不能拖住流水线：缓冲满之后 Publish 必须立即返回。
func TestPublishNeverBlocks(t *testing.T) {
	h := NewHub()
	_, cancel := h.Subscribe()
	defer cancel()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			h.Publish(Event{Type: "job_log"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish 被慢消费者阻塞了")
	}
}

func TestCancelUnsubscribes(t *testing.T) {
	h := NewHub()
	_, cancel := h.Subscribe()
	if h.Count() != 1 {
		t.Fatalf("订阅数应为 1，实得 %d", h.Count())
	}
	cancel()
	if h.Count() != 0 {
		t.Fatalf("取消后订阅数应为 0，实得 %d", h.Count())
	}
	cancel() // 重复取消不应 panic
}
