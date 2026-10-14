import type { ReactNode } from "react";

/**
 * The single row pattern on Android: a 40px icon tile, a title with an optional eyebrow and
 * subtitle, and one trailing element. Rows sit in a `.mobile-choice-list` group card.
 */
export function ListRow({ icon, eyebrow, title, subtitle, trailing, onClick, label, className = "", current }: {
  icon: ReactNode;
  eyebrow?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  trailing?: ReactNode;
  onClick?: () => void;
  label?: string;
  className?: string;
  current?: boolean;
}) {
  const content = <>
    <span className="mobile-row-icon">{icon}</span>
    <span>{eyebrow && <small className="mobile-row-eyebrow">{eyebrow}</small>}<strong>{title}</strong>{subtitle && <small>{subtitle}</small>}</span>
    {trailing}
  </>;
  return onClick
    ? <button type="button" className={`mobile-list-row ${className}`} aria-label={label} aria-current={current || undefined} onClick={onClick}>{content}</button>
    : <div className={`mobile-list-row ${className}`}>{content}</div>;
}
