import { useRef, useState, type KeyboardEvent } from "react";
import { formatDateTime, t } from "../../i18n";
import { HOURS } from "./weekGrid";

/** 1 January 2024 is a Monday. */
const dayName = (day: number, weekday: "long" | "short") =>
  formatDateTime(new Date(Date.UTC(2024, 0, 1 + day)), { weekday, timeZone: "UTC" });
const hourName = (hour: number) => formatDateTime(new Date(Date.UTC(2024, 0, 1, hour)), { hour: "numeric", timeZone: "UTC" });
const DAYS = [0, 1, 2, 3, 4, 5, 6];
const DAY_HOURS = Array.from({ length: 24 }, (_, hour) => hour);

/**
 * Weekly hours on a grid in the viewer's local time: days are columns, hours are rows. Drag or
 * click to paint; arrow keys move, Space or Enter toggles. A day or hour heading toggles its line.
 */
export function WeekGrid({ cells, onChange, disabled, label }: {
  cells: boolean[]; onChange: (cells: boolean[]) => void; disabled?: boolean; label: string;
}) {
  const [focus, setFocus] = useState(9 * 7);
  /** A mouse drag paints the rectangle from where it started, over the cells as they were then. */
  const painting = useRef<{ value: boolean; day: number; hour: number; base: boolean[] } | null>(null);
  const grid = useRef<HTMLDivElement>(null);
  // Cells are stored day-major (Monday 00:00 first); the grid shows them hour by hour.
  const index = (day: number, hour: number) => day * 24 + hour;
  const set = (indexes: number[], value: boolean) => {
    const next = [...cells];
    for (const at of indexes) next[at] = value;
    onChange(next);
  };
  const toggleLine = (indexes: number[]) => set(indexes, !indexes.every((at) => cells[at]));
  const move = (event: KeyboardEvent, day: number, hour: number) => {
    const keys: Record<string, [number, number]> = { ArrowUp: [0, -1], ArrowDown: [0, 1], ArrowLeft: [-1, 0], ArrowRight: [1, 0] };
    if (event.key === " " || event.key === "Enter") { event.preventDefault(); set([index(day, hour)], !cells[index(day, hour)]); return; }
    const step = keys[event.key];
    if (!step) return;
    event.preventDefault();
    // Left and right follow reading direction.
    const rtl = getComputedStyle(event.currentTarget).direction === "rtl";
    const nextDay = Math.min(6, Math.max(0, day + (rtl ? -step[0] : step[0]))), nextHour = Math.min(23, Math.max(0, hour + step[1]));
    setFocus(nextHour * 7 + nextDay);
    grid.current?.querySelector<HTMLElement>(`[data-cell="${nextHour * 7 + nextDay}"]`)?.focus();
  };
  return (
    <div className="week-grid" role="grid" aria-label={label} aria-disabled={disabled || undefined} ref={grid}
      onPointerUp={() => { painting.current = null; }} onPointerLeave={() => { painting.current = null; }}>
      <div role="row" className="week-grid-row week-grid-days">
        <span role="columnheader" className="week-grid-corner" />
        {DAYS.map((day) => <button key={day} type="button" role="columnheader" disabled={disabled} title={dayName(day, "long")}
          aria-label={t("devices.hours.toggleDay", { day: dayName(day, "long") })}
          onClick={() => toggleLine(DAY_HOURS.map((hour) => index(day, hour)))}>{dayName(day, "short")}</button>)}
      </div>
      {DAY_HOURS.map((hour) => (
        <div role="row" className="week-grid-row" key={hour}>
          <button type="button" role="rowheader" disabled={disabled} aria-label={t("devices.hours.toggleHour", { hour: hourName(hour) })}
            onClick={() => toggleLine(DAYS.map((day) => index(day, hour)))}>{hourName(hour)}</button>
          {DAYS.map((day) => {
            const at = index(day, hour), on = cells[at], position = hour * 7 + day;
            return <span key={day} role="gridcell" aria-selected={on} data-on={on || undefined} data-cell={position}
              tabIndex={disabled ? -1 : position === focus ? 0 : -1}
              aria-label={t("devices.hours.cell", { day: dayName(day, "long"), hour: hourName(hour) })}
              onKeyDown={disabled ? undefined : (event) => move(event, day, hour)}
              onFocus={() => setFocus(position)}
              // A mouse paints by dragging; a touch taps one cell, so a swipe still scrolls the panel.
              onPointerDown={disabled ? undefined : (event) => {
                if (event.pointerType !== "mouse") return;
                event.preventDefault();
                painting.current = { value: !on, day, hour, base: cells };
                set([at], !on);
              }}
              onClick={disabled ? undefined : (event) => { if (event.nativeEvent instanceof PointerEvent && event.nativeEvent.pointerType === "mouse") return; set([at], !on); }}
              onPointerEnter={disabled ? undefined : () => {
                const drag = painting.current;
                if (!drag) return;
                const next = [...drag.base];
                for (let d = Math.min(day, drag.day); d <= Math.max(day, drag.day); d++)
                  for (let h = Math.min(hour, drag.hour); h <= Math.max(hour, drag.hour); h++) next[index(d, h)] = drag.value;
                onChange(next);
              }} />;
          })}
        </div>
      ))}
    </div>
  );
}

export const emptyWeek = () => Array.from({ length: HOURS }, () => false);
