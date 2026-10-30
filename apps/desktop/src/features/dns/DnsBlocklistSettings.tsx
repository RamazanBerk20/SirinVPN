import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { Field, InlineError } from "../../components/ui";
import { privateDnsNameIsValid } from "../../dns";
import { formatDateTime, formatNumber, t } from "../../i18n";
import { errorMessage } from "../../lib/errors";
import type { DnsBlocklistSettings as Settings, ServerProfile } from "../../types";

const lines = (value: string) => [...new Set(value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))];
const allowedName = (value: string) => value.toLowerCase().replace(/\.$/, "");

/** Owner and Admin control of the VPS-wide blocklist. The VPS keeps no query history. */
export function DnsBlocklistSettings({ profile, connected, canManage }: { profile: Pick<ServerProfile, "id">; connected: boolean; canManage: boolean }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [supported, setSupported] = useState<boolean | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [presets, setPresets] = useState<string[]>([]);
  const [custom, setCustom] = useState(""), [allow, setAllow] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null), [notice, setNotice] = useState<string | null>(null);
  const generation = useRef(0);
  const show = useCallback((next: Settings) => {
    const presetUrls = next.presets.map((preset) => preset.url);
    setSettings(next);
    setEnabled(next.policy.enabled);
    setPresets(next.policy.sources?.filter((url) => presetUrls.includes(url)) ?? []);
    setCustom((next.policy.sources ?? []).filter((url) => !presetUrls.includes(url)).join("\n"));
    setAllow((next.policy.allowlist ?? []).join("\n"));
  }, []);
  const refresh = useCallback(async () => {
    const request = ++generation.current;
    setSettings(null); setSupported(null); setError(null); setNotice(null);
    if (!connected || !canManage) return;
    try {
      const configuration = await api.serverConfiguration(profile.id);
      if (request !== generation.current) return;
      setSupported(Boolean(configuration.dns_blocklist_management_enabled));
      if (!configuration.dns_blocklist_management_enabled) return;
      const next = await api.dnsBlocklistSettings(profile.id);
      if (request === generation.current) show(next);
    } catch (reason) { if (request === generation.current) setError(errorMessage(reason, t("dns.blocklist.loadFailed"))); }
  }, [profile.id, connected, canManage, show]);
  useEffect(() => { void refresh(); }, [refresh]);
  if (!canManage) return null;

  const sources = [...presets, ...lines(custom).filter((url) => !presets.includes(url))];
  const allowlist = [...new Set(lines(allow).map(allowedName))];
  const customInvalid = lines(custom).some((url) => !/^https:\/\/[^\s/@#]+(\/[^\s#]*)?$/.test(url)) || sources.length > 8;
  const allowInvalid = allowlist.length > 512 || !allowlist.every(privateDnsNameIsValid);
  const save = async () => {
    const request = generation.current;
    setBusy(true); setError(null); setNotice(null);
    try {
      const next = await api.updateDnsBlocklist(profile.id, { enabled, sources, allowlist });
      if (request !== generation.current) return;
      show(next);
      setNotice(t("dns.blocklist.saved"));
    } catch (reason) { if (request === generation.current) setError(errorMessage(reason, t("dns.blocklist.saveFailed"))); }
    finally { if (request === generation.current) setBusy(false); }
  };
  const status = settings?.status;
  const statusText = !settings || !status ? null
    : status.failure ? t(`dns.blocklist.failure.${status.failure}`)
    : settings.pending ? t("dns.blocklist.status.pending")
    : status.active ? t("dns.blocklist.status.active", {
      count: formatNumber(status.domain_count),
      time: formatDateTime(new Date((status.updated_at_unix ?? 0) * 1000), { dateStyle: "medium", timeStyle: "short" }),
    })
    : t("dns.blocklist.status.off");

  return <section className="settings-card" aria-label={t("dns.blocklist.title")}>
    <h2>{t("dns.blocklist.title")}</h2>
    <p>{t("dns.blocklist.summary")}</p>
    {!connected ? <p>{t("common.error.needsConnection")}</p> : supported === false ? <p>{t("dns.blocklist.unsupported")}</p> : settings ? <>
      <label className="preference-checkbox"><input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} /><span>{t("dns.blocklist.enable")}</span></label>
      <fieldset className="choice-fieldset">
        <legend>{t("dns.blocklist.lists")}</legend>
        {settings.presets.map((preset) => <label className="preference-checkbox" key={preset.url}>
          <input type="checkbox" checked={presets.includes(preset.url)} onChange={(event) => setPresets(event.target.checked ? [...presets, preset.url] : presets.filter((url) => url !== preset.url))} />
          <span>{preset.name}</span>
        </label>)}
      </fieldset>
      <div className="invite-form">
        <Field label={t("dns.blocklist.custom")} hint={t("dns.blocklist.customHint")} error={customInvalid ? t("dns.blocklist.customInvalid") : undefined}>
          <textarea rows={2} spellCheck={false} value={custom} onChange={(event) => setCustom(event.target.value)} />
        </Field>
        <Field label={t("dns.blocklist.allowlist")} hint={t("dns.blocklist.allowlistHint")} error={allowInvalid ? t("dns.blocklist.allowlistInvalid") : undefined}>
          <textarea rows={3} spellCheck={false} value={allow} onChange={(event) => setAllow(event.target.value)} />
        </Field>
        {statusText && <p>{statusText}</p>}
      </div>
      <div className="settings-action-row">
        <button className="secondary-button" onClick={() => void refresh()} disabled={busy}>{t("dns.blocklist.refresh")}</button>
        <button className="primary-button" onClick={() => void save()} disabled={busy || customInvalid || allowInvalid || (enabled && sources.length === 0)}>
          {busy ? t("common.state.working") : t("dns.blocklist.save")}
        </button>
      </div>
    </> : !error && <p>{t("common.state.loading")}</p>}
    {notice && <p role="status">{notice}</p>}
    {error && <InlineError message={error} />}
  </section>;
}
