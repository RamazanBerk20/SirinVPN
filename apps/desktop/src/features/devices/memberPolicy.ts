import type { MemberPolicy } from "../../types";

export const defaultMemberPolicy = (): MemberPolicy => ({
  device_limit: null, expires_at_unix: null, weekly_access: [],
  invite_members: false, add_own_devices: false,
  manage_own_peer_communication: false, manage_own_port_forwards: false,
});

export interface PolicyDraft {
  policy: MemberPolicy;
  limit: string;
  expires: string;
  schedule: string;
}

const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const time = (minute: number) => `${String(Math.floor(minute / 60)).padStart(2, "0")}:${String(minute % 60).padStart(2, "0")}`;

export function policyDraft(value?: MemberPolicy): PolicyDraft {
  const policy = { ...defaultMemberPolicy(), ...value };
  const rows: string[] = [];
  for (const window of policy.weekly_access) {
    for (let day = Math.floor(window.start_minute / 1440); day <= Math.floor((window.end_minute - 1) / 1440); day++) {
      rows.push(`${days[day]} ${time(Math.max(0, window.start_minute - day * 1440))}-${time(Math.min(1440, window.end_minute - day * 1440))}`);
    }
  }
  return {
    policy,
    limit: policy.device_limit?.toString() ?? "",
    expires: policy.expires_at_unix ? new Date(policy.expires_at_unix * 1000).toISOString().slice(0, 16) : "",
    schedule: rows.join("\n"),
  };
}

export function policyFromDraft(draft: PolicyDraft): MemberPolicy {
  const policy = { ...draft.policy };
  const limit = draft.limit.trim() ? Number(draft.limit) : null;
  if (limit != null && (!Number.isInteger(limit) || limit < 1 || limit > 222)) throw new Error("Choose a device limit from 1 to 222, or leave it empty.");
  policy.device_limit = limit;
  const expires = draft.expires ? Date.parse(`${draft.expires}Z`) / 1000 : null;
  if (expires != null && (!Number.isFinite(expires) || expires <= 0)) throw new Error("Enter a valid UTC expiration date.");
  policy.expires_at_unix = expires;
  policy.weekly_access = draft.schedule.split("\n").filter((line) => line.trim()).map((line) => {
    const match = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\d{2}):(\d{2})\s*[-–]\s*(\d{2}):(\d{2})$/i.exec(line.trim());
    if (!match) throw new Error("Use one UTC window per line, for example Mon 09:00-17:00.");
    const day = days.findIndex((value) => value.toLowerCase() === match[1].toLowerCase());
    const [startHour, startMinute, endHour, endMinute] = match.slice(2).map(Number);
    const start = startHour * 60 + startMinute, end = endHour * 60 + endMinute;
    if (startHour > 23 || startMinute > 59 || endHour > 24 || endMinute > 59 || end > 1440 || start >= end) throw new Error("Windows must end after they start on the same UTC day. Use 24:00 for midnight.");
    return { start_minute: day * 1440 + start, end_minute: day * 1440 + end };
  }).sort((a, b) => a.start_minute - b.start_minute);
  if (policy.weekly_access.length > 28 || policy.weekly_access.some((window, i, windows) => i > 0 && windows[i - 1].end_minute > window.start_minute)) throw new Error("Use up to 28 non-overlapping access windows.");
  return policy;
}

export function policyFieldErrors(draft: PolicyDraft): Partial<Record<"limit" | "expires" | "schedule", string>> {
  const errors: Partial<Record<"limit" | "expires" | "schedule", string>> = {};
  for (const field of ["limit", "expires", "schedule"] as const) {
    try { policyFromDraft({ ...policyDraft(), [field]: draft[field] }); }
    catch (error) { errors[field] = error instanceof Error ? error.message : "Check this value."; }
  }
  return errors;
}
