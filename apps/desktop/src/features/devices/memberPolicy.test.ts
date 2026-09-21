import { expect, it } from "vitest";
import { policyDraft, policyFieldErrors, policyFromDraft } from "./memberPolicy";
import { serializeWeeklyRows } from "./WeeklyAccessFields";
it("splits overnight UTC intervals across the week boundary without changing their meaning", () => {
  const schedule = serializeWeeklyRows([{ day: "Sun", start: "23:00", end: "02:00" }]);
  expect(policyFromDraft({ ...policyDraft(), schedule }).weekly_access).toEqual([
    { start_minute: 0, end_minute: 120 }, { start_minute: 10020, end_minute: 10080 },
  ]);
});
it("preserves unrestricted schedules and reports each invalid field independently", () => {
  expect(policyFromDraft(policyDraft()).weekly_access).toEqual([]);
  const errors = policyFieldErrors({ ...policyDraft(), limit: "223", expires: "bad date", schedule: "not a time range" });
  expect(Object.keys(errors)).toEqual(["limit", "expires", "schedule"]);
});
it("rejects overlapping and empty windows while accepting midnight endpoints", () => {
  expect(() => policyFromDraft({ ...policyDraft(), schedule: "Mon 09:00-12:00\nMon 11:00-14:00" })).toThrow(/non-overlapping/);
  expect(() => policyFromDraft({ ...policyDraft(), schedule: "Mon 09:00-09:00" })).toThrow(/end after/);
  expect(policyFromDraft({ ...policyDraft(), schedule: "Mon 00:00-24:00" }).weekly_access).toEqual([{ start_minute: 0, end_minute: 1440 }]);
});
