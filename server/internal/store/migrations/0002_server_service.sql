-- M2：服务探测所需的字段。
--
-- 0001 里的 server_service 是按设计稿建的，实现后有几处需要对齐：
-- 探测结果里还包含镜像名、发现的证书用法、策略选择理由与提示。

BEGIN;

ALTER TABLE server_service
    ADD COLUMN IF NOT EXISTS container_image  text,
    ADD COLUMN IF NOT EXISTS strategy_reason  text,
    -- discovered_certs 是 nginx -T 发现的「哪些证书服务了哪些域名」，
    -- 接入时据此批量导入，不必手工录入几十个域名。
    ADD COLUMN IF NOT EXISTS discovered_certs jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS notes            text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS enabled          boolean NOT NULL DEFAULT true;

-- 探测结果整体保存，便于回看上一次探到了什么。
ALTER TABLE ssh_host
    ADD COLUMN IF NOT EXISTS last_detection jsonb;

-- 一台主机上同一个 compose 服务只应有一条记录，重复探测要能覆盖而不是堆积。
CREATE UNIQUE INDEX IF NOT EXISTS server_service_compose_uk
    ON server_service (ssh_host_id, compose_project, compose_service)
    WHERE compose_project IS NOT NULL AND compose_service IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS server_service_container_uk
    ON server_service (ssh_host_id, container_name)
    WHERE container_name IS NOT NULL AND compose_project IS NULL;

-- 宿主机形态每台机器最多一条。
CREATE UNIQUE INDEX IF NOT EXISTS server_service_host_kind_uk
    ON server_service (ssh_host_id, kind)
    WHERE container_name IS NULL AND compose_project IS NULL;

COMMIT;
