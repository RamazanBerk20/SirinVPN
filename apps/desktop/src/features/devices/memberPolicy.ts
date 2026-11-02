import { t } from "../../i18n";
import type { MemberPolicy } from "../../types";

export const defaultMemberPolicy = (): MemberPolicy => ({
  device_limit: null, expires_at_unix: null, weekly_access: [],
  invite_members: false, add_own_devices: false,
  manage_own_peer_communication: false, manage_own_port_forwards: false,
});

export interface PolicyDraft {
  policy: MemberPolicy;
  limit: string;
  /** A datetime-local value in this device's time zone. */
  expires: string;
  /** One UTC window per line, the form the server stores. */
  schedule: string;
}

export const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
/** Schedule text uses fixed English day codes in every language, so the example is not translated. */
export const SCHEDULE_EXAMPLE = "Mon 09:00-17:00";
const DAY = 1440, WEEK = 7 * DAY;
const pad = (value: number) => String(value).padStart(2, "0");
const time = (minute: number) => `${pad(Math.floor(minute / 60))}:${pad(minute % 60)}`;
const weekMinute = (minute: number) => ((minute % WEEK) + WEEK) % WEEK;

export function localDateTime(unix: number) {
  const date = new Date(unix * 1000);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** A datetime-local value without an offset is local time. */
export const expiryUnix = (value: string) => new Date(value).getTime() / 1000;

export function policyDraft(value?: MemberPolicy): PolicyDraft {
  const policy = { ...defaultMemberPolicy(), ...value };
  const rows: string[] = [];
  for (const window of policy.weekly_access) {
    for (let day = Math.floor(window.start_minute / DAY); day <= Math.floor((window.end_minute - 1) / DAY); day++) {
      rows.push(`${DAYS[day]} ${time(Math.max(0, window.start_minute - day * DAY))}-${time(Math.min(DAY, window.end_minute - day * DAY))}`);
    }
  }
  return {
    policy,
    limit: policy.device_limit?.toString() ?? "",
    expires: policy.expires_at_unix ? localDateTime(policy.expires_at_unix) : "",
    schedule: rows.join("\n"),
  };
}

export function policyFromDraft(draft: PolicyDraft): MemberPolicy {
  const policy = { ...draft.policy };
  const limit = draft.limit.trim() ? Number(draft.limit) : null;
  if (limit != null && (!Number.isInteger(limit) || limit < 1 || limit > 222)) throw new Error(t("devices.policy.error.limit"));
  policy.device_limit = limit;
  const expires = draft.expires ? expiryUnix(draft.expires) : null;
  if (expires != null && (!Number.isFinite(expires) || expires <= 0)) throw new Error(t("devices.policy.error.expires"));
  policy.expires_at_unix = expires == null ? null : Math.floor(expires);
  policy.weekly_access = draft.schedule.split("\n").filter((line) => line.trim()).map((line) => {
    const match = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\d{2}):(\d{2})\s*[-–]\s*(\d{2}):(\d{2})$/i.exec(line.trim());
    if (!match) throw new Error(t("devices.policy.error.format", { example: SCHEDULE_EXAMPLE }));
    const day = DAYS.findIndex((value) => value.toLowerCase() === match[1].toLowerCase());
    const [startHour, startMinute, endHour, endMinute] = match.slice(2).map(Number);
    const start = startHour * 60 + startMinute, end = endHour * 60 + endMinute;
    if (startHour > 23 || startMinute > 59 || endHour > 24 || endMinute > 59 || end > DAY || start >= end) throw new Error(t("devices.policy.error.order"));
    return { start_minute: day * DAY + start, end_minute: day * DAY + end };
  }).sort((a, b) => a.start_minute - b.start_minute);
  if (policy.weekly_access.length > 28 || policy.weekly_access.some((window, i, windows) => i > 0 && windows[i - 1].end_minute > window.start_minute)) throw new Error(t("devices.policy.error.overlap"));
  return policy;
}

export function policyFieldErrors(draft: PolicyDraft): Partial<Record<"limit" | "expires" | "schedule", string>> {
  const errors: Partial<Record<"limit" | "expires" | "schedule", string>> = {};
  for (const field of ["limit", "expires", "schedule"] as const) {
    try { policyFromDraft({ ...policyDraft(), [field]: draft[field] }); }
    catch (error) { errors[field] = error instanceof Error ? error.message : t("devices.policy.error.invalid"); }
  }
  return errors;
}

/** A weekly interval in local time; an end at or before the start runs past midnight. */
export type WeeklyRow = { day: number; start: string; end: string };
const minutes = (value: string) => Number(value.slice(0, 2)) * 60 + Number(value.slice(3, 5));
const complete = (value: string) => /^\d\d:\d\d$/.test(value);

/** Why a row can't be saved, or null. "00:00" to "00:00" is the whole day. */
export function rowProblem(row: WeeklyRow, number: number): string | null {
  if (!complete(row.start) || !complete(row.end)) return t("devices.schedule.incomplete", { number });
  if (row.start === row.end && row.start !== "00:00") return t("devices.schedule.sameTime", { number });
  return null;
}

/**
 * UTC schedule lines for local rows, split at UTC midnight as the server stores them.
 * `offset` is Date#getTimezoneOffset(): the minutes to add to local time to get UTC.
 */
export function rowsToSchedule(rows: WeeklyRow[], offset: number): string {
  return rows.flatMap((row) => {
    if (rowProblem(row, 1)) return [`${DAYS[row.day]} ${row.start}-${row.end}`];
    const start = minutes(row.start), end = minutes(row.end);
    let at = weekMinute(row.day * DAY + start + offset), left = end > start ? end - start : DAY - start + end;
    const lines: string[] = [];
    while (left > 0) {
      const from = at % DAY, span = Math.min(left, DAY - from);
      lines.push(`${DAYS[Math.floor(at / DAY)]} ${time(from)}-${time(from + span)}`);
      left -= span;
      at = weekMinute(at + span);
    }
    return lines;
  }).join("\n");
}

/** Local rows for UTC windows. Touching windows join, so an overnight interval stays one row. */
export function scheduleToRows(windows: MemberPolicy["weekly_access"], offset: number): WeeklyRow[] {
  const spans: [number, number][] = [];
  for (const window of [...windows].sort((a, b) => a.start_minute - b.start_minute)) {
    const last = spans.at(-1);
    if (last && last[0] + last[1] === window.start_minute) last[1] += window.end_minute - window.start_minute;
    else spans.push([window.start_minute, window.end_minute - window.start_minute]);
  }
  const last = spans.at(-1);
  if (spans.length > 1 && spans[0][0] === 0 && last && last[0] + last[1] === WEEK) last[1] += spans.shift()![1];
  return spans.flatMap(([start, length]) => {
    const rows: WeeklyRow[] = [];
    let at = weekMinute(start - offset), left = length;
    while (left > 0) {
      // One row can run past midnight, but never back to the time it started.
      const from = at % DAY, toMidnight = DAY - from;
      const span = left <= toMidnight || left - toMidnight < from ? left : toMidnight;
      rows.push({ day: Math.floor(at / DAY), start: time(from), end: time((from + span) % DAY) });
      left -= span;
      at = weekMinute(at + span);
    }
    return rows;
  });
}
