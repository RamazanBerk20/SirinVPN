import { useEffect, useId, useRef, useState } from "react";
import { open } from "../../lib/nativeDialog";
import { api } from "../../api";
import { errorMessage } from "../../lib/errors";
import type { LocalTunnelStatus } from "../../types";
import { t } from "../../i18n";
import { useInfoHint } from "../../components/InfoHint";
import { InlineError } from "../../components/ui";
import { SettingsDisclosure, SettingsNotice } from "../settings/SettingsParts";

/** The file name of a program path, for "Firefox started in the VPN." */
const programName = (path: string) => path.trim().split(/[\\/]/).filter(Boolean).pop()?.replace(/\.exe$/i, "") ?? path;

export function ApplicationLauncher({ serverId, local, busy, onConnect }: {
  serverId: string;
  local: LocalTunnelStatus;
  busy: boolean;
  /** Present when Selected apps is saved and this server can connect in place. */
  onConnect?: () => void;
}) {
  const [executable, setExecutable] = useState("");
  const [argumentsText, setArgumentsText] = useState("");
  const [launching, setLaunching] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const argumentsHelpId = useId();
  const programId = useId();
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
    const name = programName(executable);
    setLaunching(true);
    setNotice("");
    setError(null);
    try {
      const result = await api.launchVpnApplication(serverId, executable.trim(), argumentsText.split("\n").filter((arg) => arg.length > 0));
      if (current === generation.current) setNotice(result.completed
        ? t("connection.launcher.exited", { name })
        : t("connection.launcher.launched", { name }));
    } catch (reason) {
      if (current === generation.current) setError(errorMessage(reason, t("connection.launcher.launchError")));
    } finally {
      setLaunching(false);
    }
  };
  const editing = launching || busy;
  return (
    <fieldset className="choice-fieldset application-launcher">
      <legend>{t("connection.launcher.legend")}</legend>
      <p>{windows ? t("connection.launcher.summaryWindows") : t("connection.launcher.summaryLinux")}{infoButton}</p>
      {infoPanel}
      {!ready && <SettingsNotice action={onConnect && { label: t("settings.parts.connect"), onClick: onConnect, disabled: busy }}>{t("connection.launcher.notReady")}</SettingsNotice>}
      {/* Browse sits beside the input, outside the label, so the label names only the path field. */}
      <div className="field">
        <span><label htmlFor={programId}>{t("connection.launcher.executable")}</label></span>
        <div className="field-with-button">
          <input id={programId} value={executable} onChange={(event) => setExecutable(event.target.value)} placeholder={windows ? t("connection.launcher.placeholderWindows") : t("connection.launcher.placeholderLinux")} disabled={editing} autoComplete="off" spellCheck={false} />
          <button type="button" className="secondary-button" onClick={() => void choose()} disabled={editing}>{t("connection.launcher.browse")}</button>
        </div>
      </div>
      <SettingsDisclosure summary={t("connection.launcher.arguments.summary")}>
        <label className="route-list-field">
          <span>{t("connection.launcher.arguments.label")}</span>
          <textarea value={argumentsText} onChange={(event) => setArgumentsText(event.target.value)} rows={3} disabled={editing} spellCheck={false} aria-describedby={argumentsHelpId} />
        </label>
        <small id={argumentsHelpId} className="field-hint">{t("connection.launcher.arguments.hint")}</small>
      </SettingsDisclosure>
      <p className="settings-note">{windows ? t("connection.launcher.safetyWindows") : t("connection.launcher.safetyLinux")}</p>
      <div className="launcher-actions">
        <button type="button" className="primary-button" onClick={() => void launch()} disabled={!ready || editing || !executable.trim()}>{launching ? t("connection.launcher.launching") : t("connection.launcher.launch")}</button>
        {ready && !executable.trim() && <small>{t("connection.launcher.needsProgram")}</small>}
        {notice && <p role="status">{notice}</p>}
      </div>
      {error && <InlineError message={error} onRetry={executable.trim() && ready ? () => void launch() : undefined} retryDisabled={editing} />}
    </fieldset>
  );
}
