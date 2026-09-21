import { useId, useState } from "react";
import { Field } from "../../components/ui";
import { policyDraft, policyFromDraft } from "./memberPolicy";

const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
type Row = { day: string; start: string; end: string };
function rowsFrom(value: string): Row[] {
  return value.split("\n").filter(Boolean).map(line => {
    const match = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\d\d:\d\d)[-–](\d\d:\d\d)$/i.exec(line.trim());
    return match ? { day: days.find(day => day.toLowerCase() === match[1].toLowerCase())!, start: match[2], end: match[3] } : { day: "Mon", start: "", end: "" };
  });
}
export function serializeWeeklyRows(rows: Row[]) {
  return rows.flatMap(row => {
    const day = days.indexOf(row.day);
    if (row.start && row.end && row.end < row.start) {
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
    preview = policy.weekly_access.map(window => [window.start_minute, window.end_minute].map(minute => new Date(monday.getTime() + minute * 60000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" })).join(" → "));
  } catch { /* Field validation supplies the actionable error. */ }
  return <section className="weekly-access-rows" aria-label="Weekly access schedule">
    <h3>Weekly access (UTC)</h3><p className="settings-note">No intervals means access all week. Times are stored in UTC; overnight intervals are split automatically.</p>
    {!advanced && rows.map((row, index) => <div className="weekly-access-row" key={index}>
      <Field label={`Day ${index + 1}`}><select {...invalid} value={row.day} onChange={event => update(rows.map((item, at) => at === index ? { ...item, day: event.target.value } : item))}>{days.map(day => <option key={day}>{day}</option>)}</select></Field>
      <Field label={`Start ${index + 1} (UTC)`}><input {...invalid} type="time" value={row.start} onChange={event => update(rows.map((item, at) => at === index ? { ...item, start: event.target.value } : item))} /></Field>
      <Field label={`End ${index + 1} (UTC)`} hint={row.end === "24:00" ? "Midnight at the end of this day." : undefined}><input {...invalid} type="time" value={row.end === "24:00" ? "00:00" : row.end} onChange={event => update(rows.map((item, at) => at === index ? { ...item, end: event.target.value } : item))} /></Field>
      <button type="button" className="text-button" onClick={() => update(rows.filter((_, at) => at !== index))}>Remove interval {index + 1}</button>
    </div>)}
    {!advanced && <button type="button" className="secondary-button" onClick={() => update([...rows, { day: "Mon", start: "09:00", end: "17:00" }])}>Add interval</button>}
    <button type="button" className="text-button" onClick={() => { if (advanced) { if (error) return; setRows(rowsFrom(value)); } setAdvanced(!advanced); }}>{advanced ? "Use day and time controls" : "Edit UTC text"}</button>
    {advanced && <Field label="Weekly access (UTC)" error={error} hint="One UTC window per line, for example Mon 09:00-17:00. Up to 28 non-overlapping windows."><textarea rows={3} value={value} onChange={event => onChange(event.target.value)} /></Field>}
    {!advanced && error && <p id={errorId} className="field-error" role="alert">{error}</p>}
    {!!preview.length && <details><summary>Local time preview for this week</summary><p>UTC intervals stay fixed. Local times can change with daylight saving.</p>{preview.map((line, index) => <p key={index}>{line}</p>)}</details>}
  </section>;
}
