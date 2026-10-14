import { t } from "../i18n";
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
  const [feedback, setFeedback] = useState<"" | "copied" | "failed">("");
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
        aria-label={t("app.copy.label", { label })}
        onClick={() => {
          void navigator.clipboard
            .writeText(value)
            .then(() => {
              setFeedback("copied");
              clearTimeout(timer.current);
              timer.current = setTimeout(() => setFeedback(""), 2000);
            })
            .catch(() => setFeedback("failed"));
        }}
      >
        {feedback === "copied" ? <Check size={17} /> : <Copy size={17} />}
        {showCopyLabel && t("common.action.copy")}
      </button>
      {shorten && (
        <button
          type="button"
          className="text-button"
          onClick={() => setExpanded(!expanded)}
          aria-expanded={expanded}
        >
          {expanded ? t("app.copy.showLess") : t("app.copy.showAll")}
        </button>
      )}
      <span className="copy-feedback" role="status">
        {feedback === "copied" ? t("common.action.copied") : feedback === "failed" ? t("app.copy.failed") : ""}
      </span>
    </span>
  );
}
