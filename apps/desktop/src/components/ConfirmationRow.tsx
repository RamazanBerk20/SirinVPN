import { useId, type ReactNode } from "react";

/** A consent checkbox. `danger` marks consent to something that can't be undone. */
export function ConfirmationRow({ checked, onChange, disabled, danger = false, children }: {
  checked: boolean; onChange: (checked: boolean) => void; disabled?: boolean; danger?: boolean; children: ReactNode;
}) {
  const id = useId();
  return <label className={`confirmation-row${danger ? " danger" : ""}`} htmlFor={id}>
    <input id={id} type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
    <span>{children}</span>
  </label>;
}
