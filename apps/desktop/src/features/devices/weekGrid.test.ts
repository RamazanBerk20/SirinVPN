import { describe, expect, it } from "vitest";
import { cellsToWindows, DAY, HOURS, WEEK, windowsToCells } from "./weekGrid";
import { policyDraft, policyFromDraft, policyProblems } from "./memberPolicy";

const cells = (...hours: number[]) => Array.from({ length: HOURS }, (_, hour) => hours.includes(hour));
const range = (from: number, to: number) => Array.from({ length: to - from }, (_, index) => from + index);
// Date#getTimezoneOffset: UTC+3 is -180, UTC-2 is 120.
const ISTANBUL = -180, BRAZIL = 120, INDIA = -330;

describe("week grid in local time ↔ UTC windows", () => {
  it("shifts local hours to UTC", () => {
    // Monday 09:00–17:00 in UTC+3 is Monday 06:00–14:00 UTC.
    expect(cellsToWindows(cells(...range(9, 17)), ISTANBUL)).toEqual([{ start_minute: 6 * 60, end_minute: 14 * 60 }]);
  });

  it("wraps Monday morning east of UTC back to the end of the week", () => {
    // Monday 00:00–02:00 in UTC+3 is Sunday 21:00–23:00 UTC.
    expect(cellsToWindows(cells(0, 1), ISTANBUL)).toEqual([{ start_minute: WEEK - 3 * 60, end_minute: WEEK - 60 }]);
  });

  it("wraps Sunday night west of UTC into Monday and splits at the week boundary", () => {
    // Sunday 21:00–23:00 in UTC-2 is Sunday 23:00 to Monday 01:00 UTC: two windows.
    expect(cellsToWindows(cells(6 * 24 + 21, 6 * 24 + 22), BRAZIL)).toEqual([
      { start_minute: 0, end_minute: 60 },
      { start_minute: WEEK - 60, end_minute: WEEK },
    ]);
  });

  it("splits a window at UTC midnight, as the VPS has always stored them", () => {
    // Monday 22:00 to Tuesday 02:00 UTC.
    expect(cellsToWindows(cells(22, 23, 24, 25), 0)).toEqual([
      { start_minute: 22 * 60, end_minute: DAY },
      { start_minute: DAY, end_minute: DAY + 2 * 60 },
    ]);
  });

  it("treats no hours and every hour as no limit", () => {
    expect(cellsToWindows(cells(), ISTANBUL)).toEqual([]);
    expect(cellsToWindows(Array.from({ length: HOURS }, () => true), ISTANBUL)).toEqual([]);
  });

  it("round-trips through UTC in every offset, including half-hour ones", () => {
    const local = cells(0, 1, ...range(30, 40), 6 * 24 + 23);
    for (const offset of [ISTANBUL, BRAZIL, INDIA, 0, 600]) {
      const { cells: back, exact } = windowsToCells(cellsToWindows(local, offset), offset);
      expect(back).toEqual(local);
      expect(exact).toBe(true);
    }
  });

  it("reports saved times that don't fall on a local hour", () => {
    const { cells: shown, exact } = windowsToCells([{ start_minute: 9 * 60 + 30, end_minute: 12 * 60 }], 0);
    expect(exact).toBe(false);
    expect(shown.filter(Boolean)).toHaveLength(2); // 10:00 and 11:00 are fully inside
  });

  it("keeps saved windows untouched until the grid is edited", () => {
    const windows = [{ start_minute: 9 * 60 + 30, end_minute: 12 * 60 }];
    const draft = policyDraft({ weekly_access: windows }, 0);
    expect(policyFromDraft(draft).weekly_access).toEqual(windows);
    const edited = { ...draft, hours: cells(10), hoursEdited: true };
    expect(policyFromDraft(edited).weekly_access).toEqual([{ start_minute: 600, end_minute: 660 }]);
    expect(policyFromDraft({ ...edited, hoursLimited: false }).weekly_access).toEqual([]);
  });

  it("asks for at least one hour and at most 28 ranges", () => {
    const draft = { ...policyDraft(undefined, 0), hoursLimited: true, hoursEdited: true };
    expect(policyProblems(draft).hours).toBeTruthy();
    const scattered = Array.from({ length: HOURS }, (_, hour) => hour % 2 === 0 && hour < 60);
    expect(policyProblems({ ...draft, hours: scattered }).hours).toBeTruthy();
    expect(policyProblems({ ...draft, hours: cells(3) }).hours).toBeUndefined();
  });
});
