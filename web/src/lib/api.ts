/** 与后端交互的薄封装。错误消息直接来自后端，面向使用者而非开发者。 */

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

type UnauthorizedHandler = () => void;
let onUnauthorized: UnauthorizedHandler = () => {};

/** 注册会话失效时的回调，由 App 统一切回登录页。 */
export function setUnauthorizedHandler(fn: UnauthorizedHandler) {
  onUnauthorized = fn;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    if (res.status === 401) onUnauthorized();
    let msg = `请求失败（${res.status}）`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {
      // 响应不是 JSON，保留默认消息
    }
    throw new ApiError(msg, res.status);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  get: <T>(p: string) => request<T>(p),
  post: <T>(p: string, body?: unknown) =>
    request<T>(p, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  del: <T>(p: string) => request<T>(p, { method: "DELETE" }),
};

// ---------- 类型 ----------

export interface Credential {
  id: number;
  name: string;
  kind: string;
  origin: "auto" | "manual";
  ram_user_name?: string;
  region?: string;
  last_checked_at?: string;
  last_check_ok?: boolean;
  last_check_err?: string;
  zone_count: number;
  created_at: string;
}

export interface CertConfig {
  id: number;
  name: string;
  domains: string[];
  key_type: string;
  challenge_type: string;
  acme_account_id: number;
  renew_before_days: number;
  enabled: boolean;
  fail_streak: number;
  cooldown_until?: string;
  not_after?: string;
  fingerprint?: string;
  days_left?: number;
  created_at: string;
}

export interface Job {
  id: number;
  kind: string;
  ref_id?: number;
  state: "queued" | "running" | "succeeded" | "failed" | "canceled";
  stage?: string;
  attempt: number;
  max_attempts: number;
  last_error?: string;
  started_at?: string;
  finished_at?: string;
  created_at: string;
}

export interface JobLog {
  id: number;
  job_id: number;
  stage: string;
  level: string;
  message: string;
  at: string;
}

export interface Binding {
  id: number;
  cert_config_id: number;
  deploy_target_id: number;
  target_name: string;
  target_kind: string;
  last_status: string;
  last_error?: string;
  last_deployed_at?: string;
}

export interface DeployTarget {
  id: number;
  name: string;
  kind: string;
  credential_id?: number;
  params: Record<string, unknown>;
  enabled: boolean;
}

export interface ACMEAccount {
  id: number;
  name: string;
  email: string;
  directory_url: string;
  is_staging: boolean;
}

export interface CertVersion {
  id: number;
  serial: string;
  fingerprint: string;
  not_before: string;
  not_after: string;
  issuer: string;
  created_at: string;
}

export interface Overview {
  cert_count: number;
  domain_count: number;
  expiring_soon: number;
  expired: number;
  never_issued: number;
  failed_jobs: number;
  buckets: number[];
  certs: CertConfig[];
  recent_jobs: Job[];
}

export interface DomainResolution {
  domain: string;
  ok: boolean;
  zone?: string;
  record?: string;
  credential?: string;
  reason?: string;
}

export interface SSHHost {
  id: number;
  name: string;
  host: string;
  port: number;
  username: string;
  credential_id: number;
  host_key_fp?: string;
  last_probe_at?: string;
  last_probe_ok?: boolean;
  last_probe_err?: string;
  service_count: number;
  created_at: string;
}

export interface Mount {
  Type: string;
  Source: string;
  Destination: string;
  RW: boolean;
  Name?: string;
}

export interface CertUsage {
  CertPath: string;
  KeyPath: string;
  Domains: string[];
}

export interface ServerService {
  id: number;
  ssh_host_id: number;
  host_name?: string;
  kind: "nginx_systemd" | "nginx_bare" | "nginx_docker";
  compose_project?: string;
  compose_service?: string;
  container_name?: string;
  container_image?: string;
  container_user?: string;
  mounts: Mount[];
  write_strategy: "host" | "host_sudo" | "helper";
  strategy_reason?: string;
  test_argv: string[];
  reload_argv: string[];
  reload_needs_sudo?: boolean;
  use_sudo: boolean;
  is_custom: boolean;
  discovered_certs: CertUsage[];
  notes: string[];
  enabled: boolean;
  detected_at?: string;
}

export interface DetectResult {
  detection: {
    docker_available: boolean;
    sudo_available: boolean;
    port_443?: string;
    notes?: string[];
  };
  services: ServerService[];
}

export interface DryRunResult {
  ok: boolean;
  exit_code?: number;
  command?: string[];
  output: string;
}

export interface Finding {
  code: string;
  text: string;
  severity: "info" | "warn" | "danger";
}

export interface HealthCheck {
  id: number;
  cert_config_id?: number;
  domain: string;
  port: number;
  observed_fp?: string;
  subject?: string;
  issuer?: string;
  not_after?: string;
  days_left?: number;
  chain_ok?: boolean;
  chain_len?: number;
  name_match?: boolean;
  fp_match?: boolean;
  tls_version?: string;
  severity: "" | "info" | "warn" | "danger";
  findings: Finding[];
  probe_error?: string;
  checked_at: string;
}

export interface MonitorDomain {
  id: number;
  domain: string;
  port: number;
  sni?: string;
  note?: string;
  enabled: boolean;
}

export interface NotifyChannel {
  id: number;
  name: string;
  kind: string;
  events: string[];
  enabled: boolean;
}

export interface NotifyChannelsResponse {
  channels: NotifyChannel[];
  kinds: string[];
  events: { value: string; label: string }[];
}

export interface ProbeResult {
  fingerprint: string;
  subject: string;
  issuer: string;
  not_after: string;
  days_left: number;
  sans: string[];
  chain_len: number;
  chain_ok: boolean;
  name_match: boolean;
  tls_version: string;
  issues: Finding[];
}
