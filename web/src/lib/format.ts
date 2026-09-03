import type { CertConfig, Job } from "./api";
import type { CertState } from "./utils";

/** 把证书配置映射成一个可直接渲染的状态。 */
export function certStatus(c: CertConfig): { state: CertState; text: string } {
  if (c.days_left == null) return { state: "busy", text: "尚未签发" };
  if (c.fail_streak >= 3) return { state: "danger", text: `连续失败 ${c.fail_streak} 次` };
  if (c.days_left < 0) return { state: "danger", text: "已过期" };
  if (c.days_left < 7) return { state: "danger", text: "即将过期" };
  if (c.days_left <= 30) return { state: "warn", text: "待续期" };
  return { state: "ok", text: "有效" };
}

const jobStates: Record<Job["state"], { state: CertState; text: string }> = {
  queued: { state: "busy", text: "排队中" },
  running: { state: "busy", text: "执行中" },
  succeeded: { state: "ok", text: "成功" },
  failed: { state: "danger", text: "失败" },
  canceled: { state: "warn", text: "已取消" },
};

export function jobStatus(j: Job) {
  return jobStates[j.state] ?? { state: "warn" as CertState, text: j.state };
}

/** 流水线阶段的中文名。终点是 verified 而不是 issued——签发成功不等于线上生效。 */
export const stageNames: Record<string, string> = {
  pending: "等待调度",
  preflight: "前置检查",
  ordering: "创建 Order",
  challenging: "投放验证",
  validating: "等待 CA 校验",
  finalizing: "下载证书",
  issued: "已签发",
  deploying: "部署中",
  verified: "已生效",
  failed: "失败",
  running: "执行中",
  queued: "排队中",
  succeeded: "成功",
};

export function stageName(s?: string) {
  return s ? (stageNames[s] ?? s) : "—";
}

export function formatTime(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("zh-CN", { hour12: false });
}

export function formatDate(iso?: string) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("zh-CN");
}
