import { useEffect, useRef } from "react";

export interface ServerEvent {
  type: "job_log" | "job_state" | "cert_updated";
  job_id?: number;
  stage?: string;
  level?: string;
  message?: string;
  at?: string;
}

/**
 * 订阅后端事件流。
 *
 * 签发是 1–5 分钟的长流程，用户会盯着日志看；推送比轮询体验好一个量级。
 * 断线后自动重连——但只在页面可见时重连，避免后台标签页无谓地重试。
 */
export function useEvents(onEvent: (e: ServerEvent) => void) {
  // 用 ref 持有回调，避免调用方每次渲染都重建 WebSocket。
  const handler = useRef(onEvent);
  handler.current = onEvent;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let closed = false;
    let backoff = 1000;

    const connect = () => {
      if (closed) return;
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      ws = new WebSocket(`${proto}//${location.host}/ws`);

      ws.onopen = () => {
        backoff = 1000;
      };
      ws.onmessage = (ev) => {
        try {
          handler.current(JSON.parse(ev.data));
        } catch {
          // 忽略无法解析的帧
        }
      };
      ws.onclose = () => {
        if (closed) return;
        retry = setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, 30_000);
      };
    };

    connect();
    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      ws?.close();
    };
  }, []);
}
