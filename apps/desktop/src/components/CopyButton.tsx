import { Check, Copy, Warning } from "@phosphor-icons/react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { copyText } from "../lib/clipboard";

/** Copy control whose icon reports the outcome, so a denied clipboard is never silent. */
export function CopyButton({
  value,
  label,
  className = "icon-button",
  children,
}: {
  value: string;
  label?: string;
  className?: string;
  children?: ReactNode;
}) {
  const [result, setResult] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const copy = async () => {
    let next: "copied" | "failed" = "copied";
    try {
      await copyText(value);
    } catch {
      next = "failed";
    }
    setResult(next);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setResult("idle"), 4000);
  };
  const Icon = result === "copied" ? Check : result === "failed" ? Warning : Copy;
  return (
    <>
      <button
        type="button"
        className={className}
        aria-label={label}
        title={result === "failed" ? "Copy failed. Check clipboard access, or select the text and copy it manually." : undefined}
        onClick={() => void copy()}
      >
        <Icon size={17} />
        {children}
      </button>
      {/* Positioned out of flow, so grid rows that pair a value with this button keep their layout. */}
      <span className="sr-only" role="status">
        {result === "copied" ? "Copied" : result === "failed" ? "Copy failed. Select the text and copy it manually." : ""}
      </span>
    </>
  );
}
