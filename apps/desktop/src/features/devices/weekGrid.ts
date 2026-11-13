import type { MemberPolicy } from "../../types";

/**
 * Weekly hours as the viewer sees them: 7 × 24 one-hour cells in local time, Monday 00:00 first.
 * The VPS stores UTC minute windows from Monday 00:00 UTC (0) to the end of the week (10080).
 * `offset` is Date#getTimezoneOffset(): the minutes to add to local time to get UTC.
 */
export type Windows = MemberPolicy["weekly_access"];
export const DAY = 1440;
export const WEEK = 7 * DAY;
export const HOURS = 7 * 24;
/** The VPS accepts at most this many windows. */
export const MAX_WINDOWS = 28;

const wrap = (minute: number) => ((minute % WEEK) + WEEK) % WEEK;

function coverage(windows: Windows): Uint8Array {
  const minutes = new Uint8Array(WEEK);
  for (const window of windows) minutes.fill(1, Math.max(0, window.start_minute), Math.min(WEEK, window.end_minute));
  return minutes;
}

/** Local hour cells for UTC windows; `exact` is false when some saved time doesn't fall on a local hour. */
export function windowsToCells(windows: Windows, offset: number): { cells: boolean[]; exact: boolean } {
  const minutes = coverage(windows);
  const cells = Array.from({ length: HOURS }, (_, hour) => {
    for (let minute = 0; minute < 60; minute++) if (!minutes[wrap(hour * 60 + minute + offset)]) return false;
    return true;
  });
  const rebuilt = coverage(cellsToWindows(cells, offset));
  return { cells, exact: minutes.every((value, index) => value === rebuilt[index]) };
}

/**
 * UTC windows for local cells, split at UTC midnight as the VPS has always stored them, so a
 * delegated grant still fits inside its issuer's windows. A window may wrap past the week's end,
 * which becomes two windows. No cells, or every cell, is no limit: an empty list.
 */
export function cellsToWindows(cells: readonly boolean[], offset: number): Windows {
  if (cells.every(Boolean) || !cells.some(Boolean)) return [];
  const minutes = new Uint8Array(WEEK);
  cells.forEach((on, hour) => {
    if (!on) return;
    for (let minute = 0; minute < 60; minute++) minutes[wrap(hour * 60 + minute + offset)] = 1;
  });
  const windows: Windows = [];
  let start = -1;
  for (let minute = 0; minute <= WEEK; minute++) {
    const on = minute < WEEK && minutes[minute] === 1 && !(start >= 0 && minute % DAY === 0);
    if (on && start < 0) start = minute;
    if (!on && start >= 0) {
      windows.push({ start_minute: start, end_minute: minute });
      start = minute < WEEK && minutes[minute] === 1 ? minute : -1;
    }
  }
  return windows;
}
