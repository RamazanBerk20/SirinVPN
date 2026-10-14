import { Info } from "@phosphor-icons/react";
import { useId, useState, type ReactNode } from "react";
import { t } from "../i18n";

/**
 * Keeps a one-line summary on screen and moves the longer explanation behind an ⓘ button.
 * Returns the button and its panel separately so the panel can sit under the summary text.
 */
export function useInfoHint(text: ReactNode, label = t("common.action.moreInfo")): [ReactNode, ReactNode] {
  const [open, setOpen] = useState(false);
  const id = useId();
  const button = (
    <button
      type="button"
      className="info-button"
      aria-label={label}
      aria-expanded={open}
      aria-controls={id}
      onClick={(event) => { event.preventDefault(); event.stopPropagation(); setOpen(value => !value); }}
    >
      <Info size={17} weight={open ? "fill" : "regular"} />
    </button>
  );
  const panel = <p id={id} className="info-panel" hidden={!open}>{text}</p>;
  return [button, panel];
}

/** The ⓘ button followed by its panel, for block containers. */
export function InfoHint({ text, label }: { text: ReactNode; label?: string }) {
  const [button, panel] = useInfoHint(text, label);
  return <>{button}{panel}</>;
}
