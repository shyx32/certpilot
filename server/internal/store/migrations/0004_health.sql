-- M3：巡检。
--
-- 0001 里的 health_check 是按设计稿建的，实现后需要补上判读结论
-- （颁发者、协议版本、严重级别）以及结构化的问题列表。

BEGIN;

ALTER TABLE health_check
    ADD COLUMN IF NOT EXISTS subject     text,
    ADD COLUMN IF NOT EXISTS issuer      text,
    ADD COLUMN IF NOT EXISTS tls_version text,
    ADD COLUMN IF NOT EXISTS days_left   integer,
    ADD COLUMN IF NOT EXISTS chain_len   integer,
    -- severity 是这次巡检的最高级别：空串表示一切正常。
    ADD COLUMN IF NOT EXISTS severity    text NOT NULL DEFAULT '',
    -- findings 保留完整判读结果，界面直接展示，不必再解析 issues 文本。
    ADD COLUMN IF NOT EXISTS findings    jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- 连不上时记录原因，这本身就是一种需要告警的状态。
    ADD COLUMN IF NOT EXISTS probe_error text;

-- 「仅监控不管理」的域名：证书不是本系统签的（别人管的、买的商业证书），
-- 但仍然希望到期前有人知道。
CREATE TABLE IF NOT EXISTS monitor_domain (
    id         bigserial PRIMARY KEY,
    domain     text        NOT NULL,
    port       integer     NOT NULL DEFAULT 443,
    sni        text,
    note       text,
    enabled    boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (domain, port)
);

-- 看板要按域名取最近一次结果，这个索引支撑该查询。
CREATE INDEX IF NOT EXISTS health_check_latest_idx
    ON health_check (domain, port, checked_at DESC);

COMMIT;
