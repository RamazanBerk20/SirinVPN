import { Copy, Check } from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
export function CopyValue({
  value,
  label,
  shorten = false,
  showCopyLabel = false,
}: {
  value: string;
  label: string;
  shorten?: boolean;
  showCopyLabel?: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const [feedback, setFeedback] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  return (
    <span className="copy-value">
      <span className="mono">
        {shorten && !expanded && value.length > 26
          ? `${value.slice(0, 12)}…${value.slice(-8)}`
          : value}
      </span>
      <button
        type="button"
        className={showCopyLabel ? "text-button copy-value-button" : "icon-button"}
        aria-label={`Copy ${label}`}
        onClick={() => {
          void navigator.clipboard
            .writeText(value)
            .then(() => {
              setFeedback("Copied");
              clearTimeout(timer.current);
              timer.current = setTimeout(() => setFeedback(""), 2000);
            })
            .catch(() => setFeedback("Copy failed"));
        }}
      >
        {feedback === "Copied" ? <Check size={17} /> : <Copy size={17} />}
        {showCopyLabel && "Copy"}
      </button>
      {shorten && (
        <button
          type="button"
          className="text-button"
          onClick={() => setExpanded(!expanded)}
          aria-expanded={expanded}
        >
          {expanded ? "Shorten" : "Show full"}
        </button>
      )}
      <span className="copy-feedback" role="status">
        {feedback}
      </span>
    </span>
  );
}
