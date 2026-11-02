import { expect, it } from "vitest";
import { expiryUnix, localDateTime, policyDraft, policyFieldErrors, policyFromDraft, rowProblem, rowsToSchedule, scheduleToRows } from "./memberPolicy";
import { t } from "../../i18n";

const windows = (schedule: string) => policyFromDraft({ ...policyDraft(), schedule }).weekly_access;

it("splits overnight UTC intervals across the week boundary without changing their meaning", () => {
  const schedule = rowsToSchedule([{ day: 6, start: "23:00", end: "02:00" }], 0);
  expect(windows(schedule)).toEqual([{ start_minute: 0, end_minute: 120 }, { start_minute: 10020, end_minute: 10080 }]);
  // Read back, the two UTC windows are one overnight interval again.
  expect(scheduleToRows(windows(schedule), 0)).toEqual([{ day: 6, start: "23:00", end: "02:00" }]);
});

it("enters intervals in local time and stores them in UTC", () => {
  // UTC+3 (getTimezoneOffset -180): Monday 01:00–09:00 local is Sunday 22:00 to Monday 06:00 UTC.
  const schedule = rowsToSchedule([{ day: 0, start: "01:00", end: "09:00" }], -180);
  expect(schedule).toBe("Sun 22:00-24:00\nMon 00:00-06:00");
  expect(scheduleToRows(windows(schedule), -180)).toEqual([{ day: 0, start: "01:00", end: "09:00" }]);
  // UTC−5: Friday 22:00 to Saturday 06:00 local.
  const overnight = rowsToSchedule([{ day: 4, start: "22:00", end: "06:00" }], 300);
  expect(overnight).toBe("Sat 03:00-11:00");
  expect(scheduleToRows(windows(overnight), 300)).toEqual([{ day: 4, start: "22:00", end: "06:00" }]);
});

it("keeps every local row under a day, so long UTC windows come back as whole days", () => {
  const twoDays = [{ start_minute: 0, end_minute: 2880 }];
  expect(scheduleToRows(twoDays, 0)).toEqual([{ day: 0, start: "00:00", end: "00:00" }, { day: 1, start: "00:00", end: "00:00" }]);
  expect(rowsToSchedule(scheduleToRows(twoDays, 0), 0)).toBe("Mon 00:00-24:00\nTue 00:00-24:00");
  expect(scheduleToRows([{ start_minute: 540, end_minute: 2340 }], 0)).toEqual([{ day: 0, start: "09:00", end: "00:00" }, { day: 1, start: "00:00", end: "15:00" }]);
});

it("flags incomplete rows and a start equal to the end, except the whole day", () => {
  expect(rowProblem({ day: 0, start: "09:00", end: "" }, 2)).toBe(t("devices.schedule.incomplete", { number: 2 }));
  expect(rowProblem({ day: 0, start: "09:00", end: "09:00" }, 1)).toBe(t("devices.schedule.sameTime", { number: 1 }));
  expect(rowProblem({ day: 0, start: "00:00", end: "00:00" }, 1)).toBeNull();
  expect(policyFieldErrors({ ...policyDraft(), schedule: rowsToSchedule([{ day: 0, start: "09:00", end: "" }], 0) }).schedule).toBeTruthy();
});

it("preserves unrestricted schedules and reports each invalid field independently", () => {
  expect(policyFromDraft(policyDraft()).weekly_access).toEqual([]);
  const errors = policyFieldErrors({ ...policyDraft(), limit: "223", expires: "bad date", schedule: "not a time range" });
  expect(Object.keys(errors)).toEqual(["limit", "expires", "schedule"]);
});

it("rejects overlapping and empty windows while accepting midnight endpoints", () => {
  expect(() => policyFromDraft({ ...policyDraft(), schedule: "Mon 09:00-12:00\nMon 11:00-14:00" })).toThrow(t("devices.policy.error.overlap"));
  expect(() => policyFromDraft({ ...policyDraft(), schedule: "Mon 09:00-09:00" })).toThrow(t("devices.policy.error.order"));
  expect(windows("Mon 00:00-24:00")).toEqual([{ start_minute: 0, end_minute: 1440 }]);
  expect(rowsToSchedule([{ day: 1, start: "00:00", end: "00:00" }], 0)).toBe("Tue 00:00-24:00");
});

it("edits the expiry in local time and round-trips it", () => {
  const unix = 1_900_000_000;
  const draft = policyDraft({ ...policyDraft().policy, expires_at_unix: unix });
  expect(expiryUnix(draft.expires)).toBe(unix - (unix % 60));
  expect(localDateTime(unix)).toBe(draft.expires);
});
