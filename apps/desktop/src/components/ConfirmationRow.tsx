import { useId, type ReactNode } from "react";

export function ConfirmationRow({ checked, onChange, disabled, children }: {
  checked: boolean; onChange: (checked: boolean) => void; disabled?: boolean; children: ReactNode;
}) {
  const id = useId();
  return <label className="confirmation-row" htmlFor={id}>
    <input id={id} type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
    <span>{children}</span>
  </label>;
}
