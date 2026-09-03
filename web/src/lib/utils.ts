import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** 剩余天数 → 证书状态。指纹不一致归入 danger：线上跑的不是你以为的那张证书。 */
export type CertState = "ok" | "warn" | "danger" | "busy";

export function certState(daysLeft: number, fingerprintMatch = true): CertState {
  if (!fingerprintMatch || daysLeft < 7) return "danger";
  if (daysLeft <= 30) return "warn";
  return "ok";
}
