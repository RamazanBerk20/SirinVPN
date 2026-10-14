import * as dialog from "./nativeDialog";
import { t } from "../i18n";

export interface Confirmation {
  /** A short question that names the action, e.g. “Revoke Android phone?”. */
  title: string;
  /** At most two short sentences about the consequence. */
  message: string;
  /** The button that commits, named after the action, e.g. “Revoke”. */
  confirm: string;
}

/** Native confirmations name the committed action; browser previews retain their host dialog. */
let showing = false;
export async function confirmAction({ title, message, confirm }: Confirmation): Promise<boolean> {
  if (showing) return false;
  showing = true;
  try {
    if (!("__TAURI_INTERNALS__" in window)) return await Promise.resolve(window.confirm(`${title}\n\n${message}`));
    return await dialog.confirm(message, { title, kind: "warning", okLabel: confirm, cancelLabel: t("common.action.cancel") });
  } catch { return false; }
  finally { showing = false; }
}
