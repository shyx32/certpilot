package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/certpilot/server/internal/auth"
	"github.com/certpilot/server/internal/events"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type wsHandler struct {
	hub      *events.Hub
	sessions *auth.Sessions
}

// handle 把事件流推给浏览器。
//
// 签发是 1–5 分钟的长流程，用户会盯着日志看；实时推送比轮询体验好一个量级，
// 排错时尤其明显。
func (h *wsHandler) handle(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// 反向代理与前端同源，无需跨源；开发模式下 Vite 代理也保持同源。
		InsecureSkipVerify: false,
	})
	if err != nil {
		slog.Debug("WebSocket 握手失败", "err", err)
		return
	}
	defer conn.CloseNow()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	sub, unsubscribe := h.hub.Subscribe()
	defer unsubscribe()

	// 读协程只负责感知断开：客户端不需要向服务端发消息。
	go func() {
		defer cancel()
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-sub:
			if !ok {
				return
			}
			writeCtx, cancelWrite := context.WithTimeout(ctx, 10*time.Second)
			err := wsjson.Write(writeCtx, conn, e)
			cancelWrite()
			if err != nil {
				return
			}
		case <-ping.C:
			// 保活，避免中间的反向代理因空闲而断开连接。
			pingCtx, cancelPing := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pingCtx)
			cancelPing()
			if err != nil {
				return
			}
		}
	}
}
