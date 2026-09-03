-- M4：可分享的只读看板。
--
-- 给不需要登录后台的人看一眼「证书还好吗」。token 不可猜，
-- 且页面只暴露域名与状态，不含证书路径、凭据或任务日志。

BEGIN;

CREATE TABLE IF NOT EXISTS share_link (
    id         bigserial PRIMARY KEY,
    token      text        NOT NULL UNIQUE,
    name       text        NOT NULL,
    enabled    boolean     NOT NULL DEFAULT true,
    -- 过期后自动失效，避免临时分享的链接一直有效。
    expires_at timestamptz,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz
);

COMMIT;
