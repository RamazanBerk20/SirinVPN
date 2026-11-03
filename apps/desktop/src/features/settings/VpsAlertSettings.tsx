import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { Field, InlineError } from "../../components/ui";
import { formatDateTime, t } from "../../i18n";
import { errorMessage } from "../../lib/errors";
import type { AlertFailure, AlertPolicy, AlertSettings, ServerProfile } from "../../types";
import { CardSaveRow, ConnectFirst, SettingsNotice } from "./SettingsParts";

const formats = ["ntfy", "webhook"] as const;
const httpsAddress = (value: string) => /^https:\/\/[^\s/?#@]+([/?][^\s#]*)?$/.test(value);
const failureText = (failure: AlertFailure, status?: number | null) =>
  failure === "rejected" && status
    ? `${t("vps.alerts.failure.rejectedStatus", { status })}${status >= 400 && status < 500 ? ` ${t("settings.alerts.rejectedHint")}` : ""}`
    : t(`vps.alerts.failure.${failure}`);
const time = (unix: number) => formatDateTime(new Date(unix * 1000), { dateStyle: "medium", timeStyle: "short" });

/** Owner-only VPS alerts. The VPS sends only fixed text; see docs/vps-alerts.md. */
export function VpsAlertSettings({ profile, connected, onConnect, onRepair }: {
  profile: Pick<ServerProfile, "id" | "role">;
  connected: boolean;
  /** Connects to this server in place; without it the card only says to connect. */
  onConnect?: () => void;
  /** Opens Repair VPS for a server too old for alerts. */
  onRepair?: () => void;
}) {
  const owner = profile.role === "owner";
  const [settings, setSettings] = useState<AlertSettings | null>(null);
  const [supported, setSupported] = useState<boolean | null>(null);
  const [format, setFormat] = useState<AlertPolicy["format"]>("ntfy");
  const [alertUrl, setAlertUrl] = useState(""), [heartbeatUrl, setHeartbeatUrl] = useState(""), [allowPrivate, setAllowPrivate] = useState(false);
  const [busy, setBusy] = useState<"save" | "test" | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  // Each result sits by the control that caused it.
  const [saveResult, setSaveResult] = useState<{ error?: string; notice?: string } | null>(null);
  const [testResult, setTestResult] = useState<{ error?: string; notice?: string } | null>(null);
  const generation = useRef(0);
  const show = useCallback((next: AlertSettings) => {
    setSettings(next);
    setFormat(next.policy.format);
    setAlertUrl(next.policy.alert_url ?? "");
    setHeartbeatUrl(next.policy.heartbeat_url ?? "");
    setAllowPrivate(Boolean(next.policy.allow_private_addresses));
  }, []);
  const refresh = useCallback(async () => {
    const request = ++generation.current;
    setSettings(null); setSupported(null); setLoadError(null); setSaveResult(null); setTestResult(null);
    if (!connected || !owner) return;
    try {
      const configuration = await api.serverConfiguration(profile.id);
      if (request !== generation.current) return;
      setSupported(Boolean(configuration.alerts_enabled));
      if (!configuration.alerts_enabled) return;
      const next = await api.alertSettings(profile.id);
      if (request === generation.current) show(next);
    } catch (reason) { if (request === generation.current) setLoadError(errorMessage(reason, t("vps.alerts.loadFailed"))); }
  }, [profile.id, connected, owner, show]);
  useEffect(() => { void refresh(); }, [refresh]);
  if (!owner) return null;

  const policy: AlertPolicy = { format, alert_url: alertUrl.trim() || undefined, heartbeat_url: heartbeatUrl.trim() || undefined, allow_private_addresses: allowPrivate };
  const alertInvalid = Boolean(policy.alert_url) && !httpsAddress(policy.alert_url ?? "");
  const heartbeatInvalid = Boolean(policy.heartbeat_url) && !httpsAddress(policy.heartbeat_url ?? "");
  const saved = settings?.policy;
  const changed = Boolean(saved) && (saved!.format !== format || (saved!.alert_url ?? "") !== (policy.alert_url ?? "")
    || (saved!.heartbeat_url ?? "") !== (policy.heartbeat_url ?? "") || Boolean(saved!.allow_private_addresses) !== allowPrivate);
  const edit = <T,>(set: (value: T) => void) => (value: T) => { set(value); setSaveResult(null); setTestResult(null); };
  const run = async (kind: "save" | "test", action: () => Promise<{ error?: string; notice?: string }>, failure: string) => {
    const request = generation.current;
    const report = kind === "save" ? setSaveResult : setTestResult;
    setBusy(kind); report(null);
    try {
      const result = await action();
      if (request === generation.current) report(result);
    } catch (reason) { if (request === generation.current) report({ error: errorMessage(reason, failure) }); }
    finally { if (request === generation.current) setBusy(null); }
  };
  const save = () => run("save", async () => {
    const next = await api.updateAlerts(profile.id, policy);
    show(next);
    return { notice: t("vps.alerts.saved") };
  }, t("vps.alerts.saveFailed"));
  const test = () => run("test", async () => {
    const result = await api.sendTestAlert(profile.id);
    return result.failure ? { error: failureText(result.failure, result.http_status) } : { notice: t("vps.alerts.testSent") };
  }, t("vps.alerts.testFailed"));
  const status = settings?.status;

  return <section className="settings-card" aria-label={t("vps.alerts.title")}>
    <h2>{t("vps.alerts.title")}</h2>
    <p>{t("vps.alerts.summary")}</p>
    {!connected ? <ConnectFirst onConnect={onConnect} />
      : supported === false ? <SettingsNotice action={onRepair && { label: t("settings.parts.repair"), onClick: onRepair }}>{t("vps.alerts.unsupported")}</SettingsNotice>
      : settings && status ? <>
        <fieldset className="choice-fieldset">
          <legend>{t("vps.alerts.format")}</legend>
          <div className="condition-choices">
            {formats.map((value) => <label className="choice-row" key={value}>
              <input type="radio" name="vps-alert-format" checked={format === value} disabled={Boolean(busy)} onChange={() => edit(setFormat)(value)} />
              <span><strong>{t(`vps.alerts.formats.${value}.label`)}</strong><small>{t(`vps.alerts.formats.${value}.hint`)}</small></span>
            </label>)}
          </div>
        </fieldset>
        <div className="invite-form">
          <Field label={t("vps.alerts.alertUrl")} hint={t("vps.alerts.alertUrlHint")} error={alertInvalid ? t("vps.alerts.invalid") : undefined}>
            <input type="url" spellCheck={false} autoComplete="off" value={alertUrl} disabled={Boolean(busy)} onChange={(event) => edit(setAlertUrl)(event.target.value)} />
          </Field>
          <Field label={t("vps.alerts.heartbeatUrl")} hint={t("vps.alerts.heartbeatHint")} error={heartbeatInvalid ? t("vps.alerts.invalid") : undefined}>
            <input type="url" spellCheck={false} autoComplete="off" value={heartbeatUrl} disabled={Boolean(busy)} onChange={(event) => edit(setHeartbeatUrl)(event.target.value)} />
          </Field>
        </div>
        <label className="preference-row">
          <span><strong>{t("vps.alerts.allowPrivate")}</strong><small>{t("settings.alerts.allowPrivateSummary")}</small></span>
          <input type="checkbox" role="switch" aria-label={t("vps.alerts.allowPrivate")} checked={allowPrivate} disabled={Boolean(busy)} onChange={(event) => edit(setAllowPrivate)(event.target.checked)} />
        </label>
        <div className="alert-status">
          <p>{status.checked_at_unix ? t("vps.alerts.status.checked", { time: time(status.checked_at_unix) }) : t("vps.alerts.status.notChecked")}</p>
          {!status.heartbeat_failure && status.heartbeat_sent_at_unix ? <p>{t("vps.alerts.status.heartbeat", { time: time(status.heartbeat_sent_at_unix) })}</p> : null}
        </div>
        {status.alert_failure && <SettingsNotice tone="warning">{t("vps.alerts.status.alertFailed", { reason: failureText(status.alert_failure) })}</SettingsNotice>}
        {status.heartbeat_failure && <SettingsNotice tone="warning">{t("vps.alerts.status.heartbeatFailed", { reason: failureText(status.heartbeat_failure) })}</SettingsNotice>}
        <CardSaveRow dirty={changed} saving={busy === "save"} problem={alertInvalid || heartbeatInvalid ? t("connection.saveBar.invalid") : undefined}
          saved={saveResult?.notice} saveLabel={t("vps.alerts.save")} onSave={() => void save()} onDiscard={() => { show(settings); setSaveResult(null); }}>
          {/* Only a saved address can be tested, so the test sits where Save was. */}
          {saved?.alert_url
            ? <button className="secondary-button" onClick={() => void test()} disabled={Boolean(busy)}>{busy === "test" ? t("settings.alerts.testing") : t("vps.alerts.test")}</button>
            : <small>{t("settings.alerts.testNeedsAddress")}</small>}
        </CardSaveRow>
        {saveResult?.error && <InlineError message={saveResult.error} />}
        {testResult?.notice && <p className="card-result" role="status">{testResult.notice}</p>}
        {testResult?.error && <InlineError message={testResult.error} />}
      </> : loadError ? <InlineError message={loadError} onRetry={() => void refresh()} />
      : <p role="status">{t("common.state.loading")}</p>}
  </section>;
}
