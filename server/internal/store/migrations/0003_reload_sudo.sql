-- 重载提权标记。
--
-- 写入权限与重载权限是两件独立的事：证书目录常属于运维用户，
-- 而 nginx 主进程由 root 启动。探测时分别判定，这里保存后者。
BEGIN;

ALTER TABLE server_service
    ADD COLUMN IF NOT EXISTS reload_needs_sudo boolean NOT NULL DEFAULT false;

COMMIT;
