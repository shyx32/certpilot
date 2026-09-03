-- CertPilot 初始 schema
--
-- 约定：
--   * 所有敏感字段以 _enc 结尾，存放 secretbox 信封（{"dek":…,"ct":…}），主密钥不在库中。
--   * 时间一律 timestamptz，应用侧统一用 UTC。
--   * 软删除只用于 credential 与 cert_config，其余表直接删。

BEGIN;

-- ---------- CA 账号 ----------
CREATE TABLE acme_account (
    id              bigserial PRIMARY KEY,
    name            text        NOT NULL,
    directory_url   text        NOT NULL,
    email           text        NOT NULL,
    -- ACME 账号私钥，注册后不可再生成，丢失等于账号作废
    private_key_enc jsonb       NOT NULL,
    kid             text,                    -- 注册后 CA 返回的账号 URL
    eab_kid         text,                    -- 部分 CA（ZeroSSL 等）需要
    eab_hmac_enc    jsonb,
    is_staging      boolean     NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (directory_url, email)
);

-- ---------- 凭据 ----------
CREATE TABLE credential (
    id              bigserial PRIMARY KEY,
    name            text        NOT NULL,
    -- aliyun_ak | tencent | cloudflare | ssh_key | ssh_password | k8s_kubeconfig
    kind            text        NOT NULL,
    secret_enc      jsonb       NOT NULL,
    -- auto = 由 CertPilot 通过 RAM 自动创建；manual = 用户手工粘贴
    origin          text        NOT NULL DEFAULT 'manual',
    -- origin=auto 时记录对应的 RAM 用户名与策略名，供轮换与权限升级使用
    ram_user_name   text,
    ram_policy_name text,
    region          text,
    last_checked_at timestamptz,
    last_check_ok   boolean,
    last_check_err  text,
    deleted_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT credential_origin_ck CHECK (origin IN ('auto', 'manual'))
);
CREATE UNIQUE INDEX credential_name_uk ON credential (name) WHERE deleted_at IS NULL;

-- 凭据可管理的 DNS zone，录入时扫描、每日刷新。域名到账号的自动匹配依赖此表。
CREATE TABLE credential_zone (
    id               bigserial PRIMARY KEY,
    credential_id    bigint      NOT NULL REFERENCES credential(id) ON DELETE CASCADE,
    zone             text        NOT NULL,
    provider_zone_id text,
    synced_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (credential_id, zone)
);
-- 最长后缀匹配靠应用侧完成，这里只需按 zone 快速取候选
CREATE INDEX credential_zone_zone_idx ON credential_zone (zone);

-- ---------- 服务器与其上的服务 ----------
CREATE TABLE ssh_host (
    id              bigserial PRIMARY KEY,
    name            text        NOT NULL,
    host            text        NOT NULL,
    port            integer     NOT NULL DEFAULT 22,
    username        text        NOT NULL,
    credential_id   bigint      NOT NULL REFERENCES credential(id),
    jump_host_id    bigint      REFERENCES ssh_host(id),
    -- 首次连接时确认并固化，之后不匹配即拒绝连接
    host_key_fp     text,
    last_probe_at   timestamptz,
    last_probe_ok   boolean,
    last_probe_err  text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name)
);

-- 一台主机上可能有多个服务实例（宿主机 nginx + 容器 nginx 并存）
CREATE TABLE server_service (
    id               bigserial PRIMARY KEY,
    ssh_host_id      bigint      NOT NULL REFERENCES ssh_host(id) ON DELETE CASCADE,
    -- nginx_systemd | nginx_bare | nginx_docker
    kind             text        NOT NULL,
    -- Docker 场景：用 compose 标签定位容器，容器名与 ID 都会变
    compose_project  text,
    compose_service  text,
    container_name   text,
    container_image  text,
    container_user   text,        -- 非 root 镜像需据此 chown
    -- docker inspect .Mounts 的快照：容器内路径 ↔ 宿主机路径
    mounts           jsonb       NOT NULL DEFAULT '[]'::jsonb,
    -- host | host_sudo | helper  三种写入策略，探测阶段判定
    write_strategy   text        NOT NULL DEFAULT 'host',
    host_cert_dir    text,
    test_argv        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    reload_argv      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    use_sudo         boolean     NOT NULL DEFAULT false,
    -- 自定义命令是管理员特权操作，与内置档案区分开
    is_custom        boolean     NOT NULL DEFAULT false,
    detected_at      timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT server_service_write_ck CHECK (write_strategy IN ('host', 'host_sudo', 'helper'))
);
CREATE INDEX server_service_host_idx ON server_service (ssh_host_id);

-- ---------- 证书配置与签发结果 ----------
CREATE TABLE cert_config (
    id                bigserial PRIMARY KEY,
    name              text        NOT NULL,
    domains           text[]      NOT NULL,
    key_type          text        NOT NULL DEFAULT 'EC256',
    -- dns-01 | http-01
    challenge_type    text        NOT NULL,
    -- dns-01 时指向 credential；http-01 时指向 ssh_host 或集中验证
    challenge_ref     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    acme_account_id   bigint      NOT NULL REFERENCES acme_account(id),
    renew_before_days integer     NOT NULL DEFAULT 30,
    enabled           boolean     NOT NULL DEFAULT true,
    -- 由 ID 哈希得到的固定偏移，把续期请求打散在一天之内
    schedule_offset   integer     NOT NULL DEFAULT 0,
    -- 连续失败计数，达到阈值进入冷却，避免消耗 CA 的失败配额
    fail_streak       integer     NOT NULL DEFAULT 0,
    cooldown_until    timestamptz,
    deleted_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cert_config_challenge_ck CHECK (challenge_type IN ('dns-01', 'http-01')),
    CONSTRAINT cert_config_domains_ck   CHECK (cardinality(domains) > 0)
);
CREATE UNIQUE INDEX cert_config_name_uk ON cert_config (name) WHERE deleted_at IS NULL;

-- 证书版本化保存：支持回滚，也让巡检能判断线上跑的是哪一版
CREATE TABLE certificate (
    id              bigserial PRIMARY KEY,
    cert_config_id  bigint      NOT NULL REFERENCES cert_config(id) ON DELETE CASCADE,
    serial          text        NOT NULL,
    fingerprint     text        NOT NULL,          -- sha256，巡检比对用
    cert_pem        text        NOT NULL,
    chain_pem       text        NOT NULL,          -- 中间证书，缺了会让部分客户端报错
    key_enc         jsonb       NOT NULL,
    not_before      timestamptz NOT NULL,
    not_after       timestamptz NOT NULL,
    issuer          text        NOT NULL,
    acme_order_url  text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cert_config_id, fingerprint)
);
CREATE INDEX certificate_config_idx  ON certificate (cert_config_id, not_after DESC);
CREATE INDEX certificate_expiry_idx  ON certificate (not_after);

-- ---------- 部署 ----------
CREATE TABLE deploy_target (
    id              bigserial PRIMARY KEY,
    name            text        NOT NULL,
    -- aliyun_cdn | aliyun_cas | aliyun_slb | aliyun_oss | ssh_nginx | k8s_secret | webhook
    kind            text        NOT NULL,
    credential_id   bigint      REFERENCES credential(id),
    server_service_id bigint    REFERENCES server_service(id),
    params          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enabled         boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name)
);

CREATE TABLE cert_binding (
    id                   bigserial PRIMARY KEY,
    cert_config_id       bigint      NOT NULL REFERENCES cert_config(id) ON DELETE CASCADE,
    deploy_target_id     bigint      NOT NULL REFERENCES deploy_target(id) ON DELETE CASCADE,
    last_deployed_cert_id bigint     REFERENCES certificate(id),
    -- pending | deployed | verified | failed
    last_status          text        NOT NULL DEFAULT 'pending',
    last_error           text,
    last_deployed_at     timestamptz,
    UNIQUE (cert_config_id, deploy_target_id)
);

-- ---------- 任务 ----------
-- 兼作队列：领取用 SELECT … FOR UPDATE SKIP LOCKED，无需 Redis
CREATE TABLE job (
    id            bigserial PRIMARY KEY,
    -- issue | renew | deploy | probe | sync_zones | detect_service
    kind          text        NOT NULL,
    ref_id        bigint,
    -- queued | running | succeeded | failed | canceled
    state         text        NOT NULL DEFAULT 'queued',
    -- 流水线状态机的当前位置，重启后据此断点续跑
    stage         text,
    attempt       integer     NOT NULL DEFAULT 0,
    max_attempts  integer     NOT NULL DEFAULT 5,
    run_after     timestamptz NOT NULL DEFAULT now(),
    payload       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    last_error    text,
    started_at    timestamptz,
    finished_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT job_state_ck CHECK (state IN ('queued','running','succeeded','failed','canceled'))
);
-- 队列扫描的主索引：只关心待领取的任务
CREATE INDEX job_claim_idx ON job (run_after) WHERE state = 'queued';
CREATE INDEX job_ref_idx   ON job (kind, ref_id, created_at DESC);

CREATE TABLE job_log (
    id        bigserial PRIMARY KEY,
    job_id    bigint      NOT NULL REFERENCES job(id) ON DELETE CASCADE,
    stage     text        NOT NULL,
    level     text        NOT NULL DEFAULT 'info',
    message   text        NOT NULL,
    at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX job_log_job_idx ON job_log (job_id, id);

-- ---------- 巡检 ----------
CREATE TABLE health_check (
    id             bigserial PRIMARY KEY,
    cert_config_id bigint      REFERENCES cert_config(id) ON DELETE CASCADE,
    -- 仅监控、不由本系统签发的域名，cert_config_id 为空
    domain         text        NOT NULL,
    port           integer     NOT NULL DEFAULT 443,
    sni            text,
    observed_fp    text,
    not_after      timestamptz,
    chain_ok       boolean,
    name_match     boolean,
    -- 与库内最新版指纹是否一致：签了没生效只有这一项能发现
    fp_match       boolean,
    issues         text[]      NOT NULL DEFAULT '{}',
    checked_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX health_check_domain_idx ON health_check (domain, checked_at DESC);
CREATE INDEX health_check_time_idx   ON health_check (checked_at);

-- ---------- 通知与审计 ----------
CREATE TABLE notify_channel (
    id         bigserial PRIMARY KEY,
    name       text        NOT NULL,
    -- dingtalk | wecom | feishu | email | webhook
    kind       text        NOT NULL,
    config_enc jsonb       NOT NULL,
    events     text[]      NOT NULL DEFAULT '{}',
    enabled    boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name)
);

CREATE TABLE app_user (
    id            bigserial PRIMARY KEY,
    username      text        NOT NULL UNIQUE,
    password_hash text        NOT NULL,
    -- viewer | operator | admin
    role          text        NOT NULL DEFAULT 'viewer',
    disabled      boolean     NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT app_user_role_ck CHECK (role IN ('viewer','operator','admin'))
);

-- 记录谁做了什么；绝不记录凭据本身
CREATE TABLE audit_log (
    id         bigserial PRIMARY KEY,
    actor      text        NOT NULL,
    action     text        NOT NULL,
    target     text,
    detail     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    ip         inet,
    at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_time_idx ON audit_log (at DESC);

COMMIT;
