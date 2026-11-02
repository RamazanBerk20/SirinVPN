import { CheckCircle, Info, Warning, X } from "@phosphor-icons/react";
import { useSyncExternalStore } from "react";
import { t } from "../i18n";

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

/** Confirms the result of an action whose own control may have gone away or be off screen. */
export function notify(message: string, tone: ToastTone = "success") {
  const id = ++next;
  toasts = [...toasts.filter((toast) => toast.message !== message), { id, message, tone }].slice(-3);
  emit();
  // Errors stay until dismissed: they may need reading twice.
  if (tone !== "error") setTimeout(() => dismissToast(id), 5000);
}

export function ToastRegion() {
  const current = useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, () => toasts);
  return <div className="toast-region" role="status" aria-live="polite">
    {current.map((toast) => <div key={toast.id} className={`toast ${toast.tone}`}>
      {toast.tone === "success" ? <CheckCircle size={20} weight="fill" /> : toast.tone === "error" ? <Warning size={20} weight="fill" /> : <Info size={20} weight="fill" />}
      <p>{toast.message}</p>
      <button type="button" className="icon-button" aria-label={t("common.action.dismiss")} onClick={() => dismissToast(toast.id)}><X size={16} /></button>
    </div>)}
  </div>;
}
