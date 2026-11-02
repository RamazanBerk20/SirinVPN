import { Plus, Trash } from "@phosphor-icons/react";
import { useState } from "react";
import { Field } from "../../components/ui";
import { DAYS, policyDraft, policyFromDraft, rowProblem, rowsToSchedule, scheduleToRows, SCHEDULE_EXAMPLE, type WeeklyRow } from "./memberPolicy";
import { formatDateTime, t } from "../../i18n";

/** Day codes stay fixed in the schedule text; the picker shows the localized weekday. 1 January 2024 is a Monday. */
const dayName = (index: number) => formatDateTime(new Date(Date.UTC(2024, 0, 1 + index)), { weekday: "long", timeZone: "UTC" });
const offset = () => new Date().getTimezoneOffset();
const zone = () => Intl.DateTimeFormat().resolvedOptions().timeZone ?? "";

function rowsFrom(value: string): WeeklyRow[] | null {
  try { return scheduleToRows(policyFromDraft({ ...policyDraft(), schedule: value }).weekly_access, offset()); }
  catch { return null; }
}

/** Weekly access entered in local time, one card per interval; the text form is the UTC schedule the server keeps. */
export function WeeklyAccessFields({ value, onChange, error }: { value: string; onChange: (value: string) => void; error?: string }) {
  const [rows, setRows] = useState<WeeklyRow[]>(() => rowsFrom(value) ?? []);
  const [advanced, setAdvanced] = useState(() => rowsFrom(value) === null);
  const update = (next: WeeklyRow[]) => { setRows(next); onChange(rowsToSchedule(next, offset())); };
  const change = (index: number, patch: Partial<WeeklyRow>) => update(rows.map((row, at) => at === index ? { ...row, ...patch } : row));
  const problems = rows.map((row, index) => rowProblem(row, index + 1));
  const message = problems.find(Boolean) ?? error;
  return <fieldset className="policy-group weekly-access" aria-label={t("devices.schedule.label")}>
    <legend>{t("devices.schedule.title")}</legend>
    {/* The text form states its own time zone (UTC) in its label. */}
    {!advanced && <p className="policy-group-note">
      {rows.length === 0 ? t("devices.schedule.allWeek") : t("devices.schedule.localTime", { zone: zone() })}
    </p>}
    {!advanced && rows.map((row, index) => {
      const utc = offset() !== 0 && !problems[index] ? rowsToSchedule([row], offset()).split("\n").join(", ") : null;
      return <fieldset className="weekly-interval" key={index} data-invalid={Boolean(problems[index])}>
        <legend>{t("devices.schedule.interval", { number: index + 1 })}</legend>
        <div className="weekly-interval-heading">
          <button type="button" className="icon-button" aria-label={t("devices.schedule.remove", { number: index + 1 })}
            onClick={() => update(rows.filter((_, at) => at !== index))}><Trash size={17} /></button>
        </div>
        <div className="weekly-interval-fields">
          <Field label={t("devices.schedule.day")}>
            <select value={row.day} onChange={(event) => change(index, { day: Number(event.target.value) })}>
              {DAYS.map((day, at) => <option key={day} value={at}>{dayName(at)}</option>)}
            </select>
          </Field>
          <Field label={t("devices.schedule.start")}>
            <input type="time" value={row.start} aria-invalid={Boolean(problems[index])} onChange={(event) => change(index, { start: event.target.value })} />
          </Field>
          <Field label={t("devices.schedule.end")}>
            <input type="time" value={row.end} aria-invalid={Boolean(problems[index])} onChange={(event) => change(index, { end: event.target.value })} />
          </Field>
        </div>
        {!problems[index] && (row.end <= row.start) && <small className="weekly-interval-note">
          {row.end === "00:00" && row.start === "00:00" ? t("devices.schedule.wholeDay") : row.end === "00:00" ? t("devices.schedule.midnight") : t("devices.schedule.nextDay")}
        </small>}
        {utc && <small className="weekly-interval-note">{t("devices.schedule.utc", { windows: utc })}</small>}
      </fieldset>;
    })}
    {!advanced && message && <p className="field-error" role="alert">{message}</p>}
    {advanced && <Field label={t("devices.schedule.textLabel")} error={error} hint={t("devices.schedule.textHint", { example: SCHEDULE_EXAMPLE })}>
      <textarea rows={3} value={value} onChange={(event) => onChange(event.target.value)} />
    </Field>}
    <div className="weekly-access-actions">
      {!advanced && <button type="button" className="secondary-button" onClick={() => update([...rows, { day: 0, start: "09:00", end: "17:00" }])}>
        <Plus size={16} /> {t("devices.schedule.add")}
      </button>}
      <button type="button" className="text-button" disabled={advanced && Boolean(error)} onClick={() => {
        if (advanced) setRows(rowsFrom(value) ?? []);
        setAdvanced(!advanced);
      }}>{t(advanced ? "devices.schedule.useControls" : "devices.schedule.editText")}</button>
    </div>
  </fieldset>;
}
