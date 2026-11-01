import { useEffect, useId, useRef, useState } from "react";
import { open } from "../../lib/nativeDialog";
import { api } from "../../api";
import { errorMessage } from "../../lib/errors";
import type { LocalTunnelStatus } from "../../types";
import { t } from "../../i18n";
import { useInfoHint } from "../../components/InfoHint";

export function ApplicationLauncher({ serverId, local, busy }: {
  serverId: string;
  local: LocalTunnelStatus;
  busy: boolean;
}) {
  const [executable, setExecutable] = useState("");
  const [argumentsText, setArgumentsText] = useState("");
  const [launching, setLaunching] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const argumentsHelpId = useId();
  const windows = local.application_routing_backend === "windows_bind_redirect";
  const [infoButton, infoPanel] = useInfoHint(
    windows ? t("connection.launcher.infoWindows") : t("connection.launcher.infoLinux"),
    t("connection.launcher.infoLabel"),
  );
  useEffect(() => {
    ++generation.current;
    setExecutable("");
    setArgumentsText("");
    setNotice("");
    setError(null);
    return () => { ++generation.current; };
  }, [serverId]);
  const ready = local.server_id === serverId && local.state === "connected" &&
    local.routing_mode === "selected_applications" && local.application_routing_ready === true &&
    local.supervisor_status_known === true;
  const choose = async () => {
    const current = generation.current;
    try {
      const path = await open({ title: t("connection.launcher.dialogTitle"), ...(windows
        ? { filters: [{ name: t("connection.launcher.dialogFilter"), extensions: ["exe"] }] }
        : { defaultPath: "/usr/bin" }), multiple: false, directory: false });
      if (current === generation.current && typeof path === "string") setExecutable(path);
    } catch (reason) {
      if (current === generation.current) setError(errorMessage(reason, t("connection.launcher.chooserError")));
    }
  };
  const launch = async () => {
    if (!ready || busy || launching || !executable.trim()) return;
    const current = generation.current;
    setLaunching(true);
    setNotice("");
    setError(null);
    try {
      const result = await api.launchVpnApplication(serverId, executable.trim(), argumentsText.split("\n").filter((arg) => arg.length > 0));
      if (current === generation.current) setNotice(result.completed
        ? t("connection.launcher.exited")
        : t("connection.launcher.launched"));
    } catch (reason) {
      if (current === generation.current) setError(errorMessage(reason, t("connection.launcher.launchError")));
    } finally {
      setLaunching(false);
    }
  };
  return (
    <fieldset className="choice-fieldset application-launcher">
      <legend>{t("connection.launcher.legend")}</legend>
      <p>{windows ? t("connection.launcher.summaryWindows") : t("connection.launcher.summaryLinux")}{infoButton}</p>
      {infoPanel}
      {!ready && <p className="settings-note">{t("connection.launcher.notReady")}</p>}
      <label className="field">
        <span>{t("connection.launcher.executable")}</span>
        <input value={executable} onChange={(event) => setExecutable(event.target.value)} placeholder={windows ? t("connection.launcher.placeholderWindows") : t("connection.launcher.placeholderLinux")} disabled={launching || busy} autoComplete="off" spellCheck={false} />
      </label>
      <button type="button" className="secondary-button" onClick={() => void choose()} disabled={launching || busy}>{t("connection.launcher.browse")}</button>
      <details className="inline-disclosure">
        <summary>{t("connection.launcher.arguments.summary")}</summary>
        <label className="route-list-field">
          <span>{t("connection.launcher.arguments.label")}</span>
          <textarea value={argumentsText} onChange={(event) => setArgumentsText(event.target.value)} rows={3} disabled={launching || busy} spellCheck={false} aria-describedby={argumentsHelpId} />
        </label>
        <small id={argumentsHelpId}>{t("connection.launcher.arguments.hint")}</small>
      </details>
      <p className="settings-note">{windows ? t("connection.launcher.safetyWindows") : t("connection.launcher.safetyLinux")}</p>
      <button type="button" className="primary-button" onClick={() => void launch()} disabled={!ready || busy || launching || !executable.trim()}>{launching ? t("connection.launcher.launching") : t("connection.launcher.launch")}</button>
      {notice && <p role="status">{notice}</p>}
      {error && <p role="alert">{error}</p>}
    </fieldset>
  );
}
