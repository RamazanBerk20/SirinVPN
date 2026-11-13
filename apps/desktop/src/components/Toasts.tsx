import { CheckCircle, Info, Warning, X } from "@phosphor-icons/react";
import { useSyncExternalStore } from "react";
import { createPortal } from "react-dom";
import { t } from "../i18n";
import { ErrorText } from "./ui";

export type ToastTone = "success" | "info" | "error";
type Toast = { id: number; message: string; tone: ToastTone };

let toasts: Toast[] = [];
let next = 0;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((listener) => listener());

export function dismissToast(id: number) {
  toasts = toasts.filter((toast) => toast.id !== id);
  emit();
}

/** Drops every toast, e.g. when the whole app remounts. */
export function clearToasts() {
  toasts = [];
  emit();
}

/** Confirms the result of an action whose own control may have gone away or be off screen. */
export function notify(message: string, tone: ToastTone = "success") {
  const id = ++next;
  toasts = [...toasts.filter((toast) => toast.message !== message), { id, message, tone }].slice(-3);
  emit();
  // Errors stay longer: they may need reading twice.
  setTimeout(() => dismissToast(id), tone === "error" ? 12000 : 5000);
}

export function ToastRegion() {
  const current = useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, () => toasts);
  // Portaled to body: inside the app shell's stacking context a toast would sit under any dialog's backdrop.
  return createPortal(<div className="toast-region" role="status" aria-live="polite">
    {current.map((toast) => <div key={toast.id} className={`toast ${toast.tone}`}>
      {toast.tone === "success" ? <CheckCircle size={20} weight="fill" /> : toast.tone === "error" ? <Warning size={20} weight="fill" /> : <Info size={20} weight="fill" />}
      <p><ErrorText message={toast.message} /></p>
      <button type="button" className="icon-button" aria-label={t("common.action.dismiss")} onClick={() => dismissToast(toast.id)}><X size={16} /></button>
    </div>)}
  </div>, document.body);
}
