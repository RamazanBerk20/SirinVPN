import { t } from "../i18n";
import type { ChangeEvent, InputHTMLAttributes, TextareaHTMLAttributes } from "react";
import { useState } from "react";
import { invoke, isAndroid } from "../platform";
import { errorMessage } from "../lib/errors";
import { QrCode } from "@phosphor-icons/react";

/** Android returns an opaque native handle. The secret never enters React state. */
export function SecretInput(props: InputHTMLAttributes<HTMLInputElement>) {
  const [error, setError] = useState("");
  if (!isAndroid) return <input {...props} />;
  const label = props["aria-label"] ?? t("app.secret.value");
  return <span className="native-secret-input">
    <button type="button" className="secondary-button" disabled={props.disabled} aria-label={t("app.secret.enterLabel", { label })}
      id={props.id} aria-describedby={props["aria-describedby"]} aria-invalid={props["aria-invalid"]}
      onClick={() => { void invoke<string>("android_secret_input", { label, minimumLength: props.minLength ?? (props.autoComplete === "new-password" ? 12 : 0) }).then(reference => {
        setError("");
        props.onChange?.({ target: { value: reference }, currentTarget: { value: reference } } as ChangeEvent<HTMLInputElement>);
      }).catch(() => setError(t("app.secret.unchanged"))); }}>
      {props.value ? t("app.secret.entered") : t("app.secret.enter")}
    </button>
    {error && <small role="alert">{error}</small>}
  </span>;
}

export function SecretTextarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const [scanError, setScanError] = useState("");
  if (!isAndroid) return <textarea {...props} />;
  const change = (value: string) => props.onChange?.({ target: { value }, currentTarget: { value } } as ChangeEvent<HTMLTextAreaElement>);
  return <span className="native-code-input">
    <button type="button" className="primary-button scan-code-button" disabled={props.disabled} onClick={() => void invoke<string>("android_scan_code")
      .then(value => { setScanError(""); change(value); })
      .catch(reason => setScanError(errorMessage(reason, t("app.secret.scanFailed"))))}><QrCode size={24} />{t("app.secret.scan")}</button>
    <SecretInput disabled={props.disabled} value={props.value} id={props.id} aria-describedby={props["aria-describedby"]} aria-invalid={props["aria-invalid"]} aria-label={props["aria-label"] ?? t("app.secret.code")} onChange={event => { setScanError(""); change(event.target.value); }} />
    {props.value && <small className="code-ready" role="status">{t("app.secret.codeReady")}</small>}
    {scanError && <small role="alert">{scanError}</small>}</span>;
}
