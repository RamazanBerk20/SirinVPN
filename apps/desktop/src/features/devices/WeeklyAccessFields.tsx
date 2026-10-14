import { useId, useState } from "react";
import { Field } from "../../components/ui";
import { policyDraft, policyFromDraft, SCHEDULE_EXAMPLE } from "./memberPolicy";
import { formatDateTime, t } from "../../i18n";

const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
/** Day codes stay fixed in the schedule text; the picker shows the localized weekday. 1 January 2024 is a Monday. */
const dayName = (index: number) => formatDateTime(new Date(Date.UTC(2024, 0, 1 + index)), { weekday: "short", timeZone: "UTC" });
type Row = { day: string; start: string; end: string };
function rowsFrom(value: string): Row[] {
  return value.split("\n").filter(Boolean).map(line => {
    const match = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\d\d:\d\d)\s*[-–]\s*(\d\d:\d\d)$/i.exec(line.trim());
    return match ? { day: days.find(day => day.toLowerCase() === match[1].toLowerCase())!, start: match[2], end: match[3] } : { day: "Mon", start: "", end: "" };
  });
}
export function serializeWeeklyRows(rows: Row[]) {
  return rows.flatMap(row => {
    const day = days.indexOf(row.day);
    // A time control cannot enter 24:00, so an end of 00:00 always means midnight at the end of the day.
    if (row.start && row.end && (row.end < row.start || row.end === "00:00")) {
      return [`${row.day} ${row.start}-24:00`, ...(row.end === "00:00" ? [] : [`${days[(day + 1) % 7]} 00:00-${row.end}`])];
    }
    return [`${row.day} ${row.start}-${row.end}`];
  }).join("\n");
}
export function WeeklyAccessFields({ value, onChange, error }: { value: string; onChange: (value: string) => void; error?: string }) {
  const [rows, setRows] = useState(() => rowsFrom(value));
  const [advanced, setAdvanced] = useState(false);
  const errorId = useId();
  const invalid = { "aria-invalid": Boolean(error), "aria-describedby": error ? errorId : undefined } as const;
  const update = (next: Row[]) => { setRows(next); onChange(serializeWeeklyRows(next)); };
  let preview: string[] = [];
  try {
    const policy = policyFromDraft({ ...policyDraft(), schedule: value });
    const monday = new Date();
    monday.setUTCDate(monday.getUTCDate() - (monday.getUTCDay() + 6) % 7); monday.setUTCHours(0, 0, 0, 0);
    const local = (minute: number) => formatDateTime(new Date(monday.getTime() + minute * 60000), { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" });
    preview = policy.weekly_access.map(window => t("devices.schedule.range", { start: local(window.start_minute), end: local(window.end_minute) }));
  } catch { /* Field validation supplies the actionable error. */ }
  return <section className="weekly-access-rows" aria-label={t("devices.schedule.label")}>
    <h3>{t("devices.schedule.title")}</h3><p className="settings-note">{t("devices.schedule.allWeek")}</p>
    {!advanced && rows.map((row, index) => <div className="weekly-access-row" key={index}>
      <Field label={t("devices.schedule.day", { number: index + 1 })}><select {...invalid} value={row.day} onChange={event => update(rows.map((item, at) => at === index ? { ...item, day: event.target.value } : item))}>{days.map((day, at) => <option key={day} value={day}>{dayName(at)}</option>)}</select></Field>
      <Field label={t("devices.schedule.start", { number: index + 1 })}><input {...invalid} type="time" value={row.start} onChange={event => update(rows.map((item, at) => at === index ? { ...item, start: event.target.value } : item))} /></Field>
      <Field label={t("devices.schedule.end", { number: index + 1 })} hint={row.end === "24:00" ? t("devices.schedule.midnight") : undefined}><input {...invalid} type="time" value={row.end === "24:00" ? "00:00" : row.end} onChange={event => update(rows.map((item, at) => at === index ? { ...item, end: event.target.value } : item))} /></Field>
      <button type="button" className="text-button" onClick={() => update(rows.filter((_, at) => at !== index))}>{t("devices.schedule.remove", { number: index + 1 })}</button>
    </div>)}
    {!advanced && <button type="button" className="secondary-button" onClick={() => update([...rows, { day: "Mon", start: "09:00", end: "17:00" }])}>{t("devices.schedule.add")}</button>}
    <button type="button" className="text-button" onClick={() => { if (advanced) { if (error) return; setRows(rowsFrom(value)); } setAdvanced(!advanced); }}>{t(advanced ? "devices.schedule.useControls" : "devices.schedule.editText")}</button>
    {advanced && <Field label={t("devices.schedule.title")} error={error} hint={t("devices.schedule.textHint", { example: SCHEDULE_EXAMPLE })}><textarea rows={3} value={value} onChange={event => onChange(event.target.value)} /></Field>}
    {!advanced && error && <p id={errorId} className="field-error" role="alert">{error}</p>}
    {!!preview.length && <details><summary>{t("devices.schedule.preview")}</summary><p>{t("devices.schedule.previewNote")}</p>{preview.map((line, index) => <p key={index}>{line}</p>)}</details>}
  </section>;
}
