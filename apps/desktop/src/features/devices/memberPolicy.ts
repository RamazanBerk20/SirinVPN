import { t } from "../../i18n";
import type { MemberPolicy } from "../../types";
import { cellsToWindows, HOURS, MAX_WINDOWS, windowsToCells } from "./weekGrid";

export const defaultMemberPolicy = (): MemberPolicy => ({
  device_limit: null, expires_at_unix: null, weekly_access: [],
  invite_members: false, add_own_devices: false,
  manage_own_peer_communication: false, manage_own_port_forwards: false,
});

/** "Limits and permissions" as edited: the same draft in the add-device wizard and the person panel. */
export interface PolicyDraft {
  policy: MemberPolicy;
  limit: string;
  /** A datetime-local value in this device's time zone. */
  expires: string;
  /** Whether access is limited to certain hours. */
  hoursLimited: boolean;
  /** Local hour cells, Monday 00:00 first. */
  hours: boolean[];
  /** Saved windows stay exactly as they were until the grid is edited. */
  hoursEdited: boolean;
  /** Some saved time doesn't fall on a local hour; editing rounds it. */
  hoursInexact: boolean;
  /** Date#getTimezoneOffset() when the draft was made. */
  offset: number;
}

const pad = (value: number) => String(value).padStart(2, "0");

export function localDateTime(unix: number) {
  const date = new Date(unix * 1000);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** A datetime-local value without an offset is local time. */
export const expiryUnix = (value: string) => new Date(value).getTime() / 1000;

export function policyDraft(value?: Partial<MemberPolicy>, offset = new Date().getTimezoneOffset()): PolicyDraft {
  const policy = { ...defaultMemberPolicy(), ...value };
  const { cells, exact } = windowsToCells(policy.weekly_access, offset);
  return {
    policy,
    limit: policy.device_limit?.toString() ?? "",
    expires: policy.expires_at_unix ? localDateTime(policy.expires_at_unix) : "",
    hoursLimited: policy.weekly_access.length > 0,
    hours: policy.weekly_access.length > 0 ? cells : Array.from({ length: HOURS }, () => false),
    hoursEdited: false,
    hoursInexact: !exact,
    offset,
  };
}

type Problem = "limit" | "expires" | "hours";

export function policyProblems(draft: PolicyDraft): Partial<Record<Problem, string>> {
  const problems: Partial<Record<Problem, string>> = {};
  const limit = draft.limit.trim() ? Number(draft.limit) : null;
  if (limit != null && (!Number.isInteger(limit) || limit < 1 || limit > 222)) problems.limit = t("devices.policy.error.limit");
  const expires = draft.expires ? expiryUnix(draft.expires) : null;
  if (expires != null && (!Number.isFinite(expires) || expires <= 0)) problems.expires = t("devices.policy.error.expires");
  if (draft.hoursLimited && draft.hoursEdited) {
    if (!draft.hours.some(Boolean)) problems.hours = t("devices.policy.error.noHours");
    else if (cellsToWindows(draft.hours, draft.offset).length > MAX_WINDOWS) problems.hours = t("devices.policy.error.tooManyRanges", { count: MAX_WINDOWS });
  }
  return problems;
}

/** The policy to send. Call only when `policyProblems` is empty. */
export function policyFromDraft(draft: PolicyDraft): MemberPolicy {
  const limit = draft.limit.trim() ? Number(draft.limit) : null;
  const expires = draft.expires ? expiryUnix(draft.expires) : null;
  return {
    ...draft.policy,
    device_limit: limit,
    expires_at_unix: expires == null ? null : Math.floor(expires),
    weekly_access: !draft.hoursLimited ? [] : draft.hoursEdited ? cellsToWindows(draft.hours, draft.offset) : draft.policy.weekly_access,
  };
}
