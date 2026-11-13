import { ArrowClockwise } from "@phosphor-icons/react";
import { useState } from "react";
import { Field, InlineError } from "../../components/ui";
import { t } from "../../i18n";
import { MAX_NAME } from "./names";

/** A name edited in place, with its own Save. `onSave` resolves to the error to show, or null. */
export function NameField({ label, value, problem, busy, disabled, onSave, testId }: {
  label: string; value: string; problem: (name: string) => string | null; busy: boolean; disabled: boolean;
  onSave: (name: string) => Promise<string | null>; testId: string;
}) {
  const [name, setName] = useState(value);
  const [error, setError] = useState<string | null>(null);
  const issue = problem(name);
  const unchanged = name.trim() === value;
  return <form className="name-field" onSubmit={async (event) => {
    event.preventDefault();
    if (issue || unchanged || busy) return;
    setError(await onSave(name.trim()));
  }}>
    <Field label={label} error={unchanged ? undefined : issue ?? undefined}>
      <input value={name} maxLength={MAX_NAME * 2} autoComplete="off" disabled={disabled || busy}
        onChange={(event) => { setName(event.target.value); setError(null); }} />
    </Field>
    {!unchanged && <button type="submit" className="secondary-button" data-testid={testId} disabled={disabled || busy || Boolean(issue)}>
      {busy && <ArrowClockwise className="spin" size={16} aria-hidden="true" />}{busy ? t("common.state.saving") : t("devices.name.save")}
    </button>}
    {error && <InlineError message={error} />}
  </form>;
}
