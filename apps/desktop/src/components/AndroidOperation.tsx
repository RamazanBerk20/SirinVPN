import { useEffect, useState } from "react";
import { invoke, isAndroid, watchAndroidStatus } from "../platform";
import type { LocalStatusEvent } from "../types";

export function AndroidOperation() {
  const [operation,setOperation] = useState<LocalStatusEvent["operation"]>();
  useEffect(() => isAndroid ? watchAndroidStatus(event => setOperation(event.operation)) : undefined, []);
  if (!isAndroid || !operation) return null;
  const running=operation.phase==="running";
  const message=running ? "An operation is running. You can leave this screen and return to its result."
    : operation.phase==="completed" ? "The operation completed. Reopen its page to review the current state."
    : "The operation was interrupted or did not finish. Check the current server or file before retrying the same operation.";
  return <div role="status" className="notice-banner">
    <p>{message}</p>
    {!running && <button type="button" className="secondary-button" onClick={() => {
      void invoke("android_dismiss_operation").then(() => setOperation(null));
    }}>Dismiss</button>}
  </div>;
}
