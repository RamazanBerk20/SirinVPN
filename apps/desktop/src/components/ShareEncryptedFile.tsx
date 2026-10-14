import { t } from "../i18n";
import { useState } from "react";
import { invoke, isAndroid } from "../platform";
import { errorMessage } from "../lib/errors";

export function ShareEncryptedFile({ uri }: { uri: string }) {
  const [error, setError] = useState<string | null>(null);
  if (!isAndroid || !uri) return null;
  return <>
    <button type="button" className="secondary-button" onClick={() => {
      setError(null);
      void invoke("android_share_document", { uri }).catch(reason => setError(errorMessage(reason, t("app.share.failed"))));
    }}>{t("app.share.button")}</button>
    {error && <p role="alert">{error}</p>}
  </>;
}
