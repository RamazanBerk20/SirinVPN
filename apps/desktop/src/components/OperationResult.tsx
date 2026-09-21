import { useEffect, useRef, type ReactNode } from "react";
export function OperationResult({ title, target, children, actions }: { title: string; target: string; children: ReactNode; actions?: ReactNode }) {
  const result = useRef<HTMLElement>(null);
  useEffect(() => { result.current?.focus(); }, []);
  return <section className="operation-result" role="status" aria-label="Operation result" tabIndex={-1} ref={result}>
    <h3>{title}</h3><p>{target}</p>{children}<div className="dialog-actions">{actions}</div>
  </section>;
}
