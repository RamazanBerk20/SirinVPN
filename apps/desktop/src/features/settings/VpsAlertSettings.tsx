import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { Field, InlineError } from "../../components/ui";
import { formatDateTime, t, type MessageKey } from "../../i18n";
import { errorMessage } from "../../lib/errors";
import type { AlertFailure, AlertPolicy, AlertSettings, ServerProfile } from "../../types";

const formats = ["ntfy", "webhook"] as const;
const httpsAddress = (value: string) => /^https:\/\/[^\s/?#@]+([/?][^\s#]*)?$/.test(value);
const failureText = (failure: AlertFailure, status?: number | null) =>
  failure === "rejected" && status ? t("vps.alerts.failure.rejectedStatus", { status }) : t(`vps.alerts.failure.${failure}`);
const time = (unix: number) => formatDateTime(new Date(unix * 1000), { dateStyle: "medium", timeStyle: "short" });

/** Owner-only VPS alerts. The VPS sends only fixed text; see docs/vps-alerts.md. */
export function VpsAlertSettings({ profile, connected }: { profile: Pick<ServerProfile, "id" | "role">; connected: boolean }) {
  const owner = profile.role === "owner";
  const [settings, setSettings] = useState<AlertSettings | null>(null);
  const [supported, setSupported] = useState<boolean | null>(null);
  const [format, setFormat] = useState<AlertPolicy["format"]>("ntfy");
  const [alertUrl, setAlertUrl] = useState(""), [heartbeatUrl, setHeartbeatUrl] = useState(""), [allowPrivate, setAllowPrivate] = useState(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null), [notice, setNotice] = useState<string | null>(null);
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
    setSettings(null); setSupported(null); setError(null); setNotice(null);
    if (!connected || !owner) return;
    try {
      const configuration = await api.serverConfiguration(profile.id);
      if (request !== generation.current) return;
      setSupported(Boolean(configuration.alerts_enabled));
      if (!configuration.alerts_enabled) return;
      const next = await api.alertSettings(profile.id);
      if (request === generation.current) show(next);
    } catch (reason) { if (request === generation.current) setError(errorMessage(reason, t("vps.alerts.loadFailed"))); }
  }, [profile.id, connected, owner, show]);
  useEffect(() => { void refresh(); }, [refresh]);
  if (!owner) return null;

  const policy: AlertPolicy = { format, alert_url: alertUrl.trim() || undefined, heartbeat_url: heartbeatUrl.trim() || undefined, allow_private_addresses: allowPrivate };
  const alertInvalid = Boolean(policy.alert_url) && !httpsAddress(policy.alert_url ?? "");
  const heartbeatInvalid = Boolean(policy.heartbeat_url) && !httpsAddress(policy.heartbeat_url ?? "");
  const saved = settings?.policy;
  const changed = !saved || saved.format !== format || (saved.alert_url ?? "") !== (policy.alert_url ?? "")
    || (saved.heartbeat_url ?? "") !== (policy.heartbeat_url ?? "") || Boolean(saved.allow_private_addresses) !== allowPrivate;
  const run = async (action: () => Promise<void>, failure: MessageKey) => {
    const request = generation.current;
    setBusy(true); setError(null); setNotice(null);
    try { await action(); } catch (reason) { if (request === generation.current) setError(errorMessage(reason, t(failure))); }
    finally { if (request === generation.current) setBusy(false); }
  };
  const save = () => run(async () => {
    const next = await api.updateAlerts(profile.id, policy);
    show(next);
    setNotice(t("vps.alerts.saved"));
  }, "vps.alerts.saveFailed");
  const test = () => run(async () => {
    const result = await api.sendTestAlert(profile.id);
    if (result.failure) setError(failureText(result.failure, result.http_status));
    else setNotice(t("vps.alerts.testSent"));
  }, "vps.alerts.testFailed");
  const status = settings?.status;

  return <section className="settings-card" aria-label={t("vps.alerts.title")}>
    <h2>{t("vps.alerts.title")}</h2>
    <p>{t("vps.alerts.summary")}</p>
    {!connected ? <p>{t("common.error.needsConnection")}</p> : supported === false ? <p>{t("vps.alerts.unsupported")}</p> : settings && status ? <>
      <fieldset className="choice-fieldset">
        <legend>{t("vps.alerts.format")}</legend>
        {formats.map((value) => <label className="choice-row" key={value}>
          <input type="radio" name="vps-alert-format" checked={format === value} onChange={() => setFormat(value)} />
          <span><strong>{t(`vps.alerts.formats.${value}.label`)}</strong><small>{t(`vps.alerts.formats.${value}.hint`)}</small></span>
        </label>)}
      </fieldset>
      <div className="invite-form">
        <Field label={t("vps.alerts.alertUrl")} hint={t("vps.alerts.alertUrlHint")} error={alertInvalid ? t("vps.alerts.invalid") : undefined}>
          <input type="url" spellCheck={false} autoComplete="off" value={alertUrl} onChange={(event) => setAlertUrl(event.target.value)} />
        </Field>
        <Field label={t("vps.alerts.heartbeatUrl")} hint={t("vps.alerts.heartbeatHint")} error={heartbeatInvalid ? t("vps.alerts.invalid") : undefined}>
          <input type="url" spellCheck={false} autoComplete="off" value={heartbeatUrl} onChange={(event) => setHeartbeatUrl(event.target.value)} />
        </Field>
        <label className="preference-checkbox"><input type="checkbox" checked={allowPrivate} onChange={(event) => setAllowPrivate(event.target.checked)} /><span>{t("vps.alerts.allowPrivate")}</span></label>
        <p>{status.checked_at_unix ? t("vps.alerts.status.checked", { time: time(status.checked_at_unix) }) : t("vps.alerts.status.notChecked")}</p>
        {status.alert_failure && <p>{t("vps.alerts.status.alertFailed", { reason: failureText(status.alert_failure) })}</p>}
        {status.heartbeat_failure ? <p>{t("vps.alerts.status.heartbeatFailed", { reason: failureText(status.heartbeat_failure) })}</p>
          : status.heartbeat_sent_at_unix && <p>{t("vps.alerts.status.heartbeat", { time: time(status.heartbeat_sent_at_unix) })}</p>}
      </div>
      <div className="settings-action-row">
        <button className="secondary-button" onClick={() => void test()} disabled={busy || changed || !saved?.alert_url}>{t("vps.alerts.test")}</button>
        <button className="primary-button" onClick={() => void save()} disabled={busy || !changed || alertInvalid || heartbeatInvalid}>
          {busy ? t("common.state.working") : t("vps.alerts.save")}
        </button>
      </div>
    </> : !error && <p>{t("common.state.loading")}</p>}
    {notice && <p role="status">{notice}</p>}
    {error && <InlineError message={error} />}
  </section>;
}
