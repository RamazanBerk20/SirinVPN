import { t } from "../i18n";
import { useEffect, useState } from "react";
import { invoke, isAndroid, watchAndroidStatus } from "../platform";
import type { LocalStatusEvent } from "../types";
import { errorMessage } from "../lib/errors";
import { InlineError } from "./ui";

export function AndroidOperation() {
  const [operation,setOperation] = useState<LocalStatusEvent["operation"]>();
  const [dismissError,setDismissError] = useState("");
  useEffect(() => isAndroid ? watchAndroidStatus(event => setOperation(event.operation)) : undefined, []);
  if (!isAndroid || !operation) return null;
  const running=operation.phase==="running";
  const message=t(running ? "app.operation.running" : operation.phase==="completed" ? "app.operation.completed" : "app.operation.interrupted");
  return <div role="status" className="notice-banner">
    <p>{message}</p>
    {!running && <button type="button" className="secondary-button" onClick={() => {
      setDismissError("");
      void invoke("android_dismiss_operation").then(() => setOperation(null)).catch((reason) => setDismissError(errorMessage(reason, t("app.operation.dismissFailed"))));
    }}>{t("app.operation.dismiss")}</button>}
    <InlineError message={dismissError} />
  </div>;
}
