import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { Field, InlineError } from "../../components/ui";
import { privateDnsNameIsValid } from "../../dns";
import { formatDateTime, formatList, formatNumber, t } from "../../i18n";
import { errorMessage } from "../../lib/errors";
import type { DnsBlocklistSettings as Settings, ServerProfile } from "../../types";
import { CardSaveRow, ConnectFirst, SettingsNotice } from "../settings/SettingsParts";

const lines = (value: string) => [...new Set(value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))];
const allowedName = (value: string) => value.toLowerCase().replace(/\.$/, "");
const httpsList = (url: string) => /^https:\/\/[^\s/@#]+(\/[^\s#]*)?$/.test(url);
// Order doesn't change what is blocked, so it doesn't count as an edit.
const sameList = (a: string[], b: string[]) => a.length === b.length && [...a].sort().join("\n") === [...b].sort().join("\n");

/** Owner and Admin control of the VPS-wide blocklist. The VPS keeps no query history. */
export function DnsBlocklistSettings({ profile, connected, canManage, onConnect, onRepair }: {
  profile: Pick<ServerProfile, "id">;
  connected: boolean;
  canManage: boolean;
  /** Connects to this server in place; without it the card only says to connect. */
  onConnect?: () => void;
  /** Opens Repair VPS for a server too old for blocking (Owner only). */
  onRepair?: () => void;
}) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [supported, setSupported] = useState<boolean | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [presets, setPresets] = useState<string[]>([]);
  const [custom, setCustom] = useState(""), [allow, setAllow] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null), [notice, setNotice] = useState<string | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
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
    setSettings(null); setSupported(null); setError(null); setNotice(null); setLoadFailed(false);
    if (!connected || !canManage) return;
    try {
      const configuration = await api.serverConfiguration(profile.id);
      if (request !== generation.current) return;
      setSupported(Boolean(configuration.dns_blocklist_management_enabled));
      if (!configuration.dns_blocklist_management_enabled) return;
      const next = await api.dnsBlocklistSettings(profile.id);
      if (request === generation.current) show(next);
    } catch (reason) {
      if (request === generation.current) { setLoadFailed(true); setError(errorMessage(reason, t("dns.blocklist.loadFailed"))); }
    }
  }, [profile.id, connected, canManage, show]);
  useEffect(() => { void refresh(); }, [refresh]);
  if (!canManage) return null;

  const customLines = lines(custom);
  const sources = [...presets, ...customLines.filter((url) => !presets.includes(url))];
  const allowlist = [...new Set(lines(allow).map(allowedName))];
  const badSources = customLines.filter((url) => !httpsList(url));
  const badDomains = allowlist.filter((name) => !privateDnsNameIsValid(name));
  const sourceError = badSources.length ? t("settings.dnsBlocking.invalidSources", { values: formatList(badSources) })
    : sources.length > 8 ? t("dns.blocklist.customInvalid") : undefined;
  const allowError = badDomains.length ? t("settings.dnsBlocking.invalidDomains", { values: formatList(badDomains) })
    : allowlist.length > 512 ? t("dns.blocklist.allowlistInvalid") : undefined;
  const saved = settings?.policy;
  const dirty = Boolean(saved) && (enabled !== saved!.enabled || !sameList(sources, saved!.sources ?? []) || !sameList(allowlist, saved!.allowlist ?? []));
  const problem = sourceError || allowError ? t("connection.saveBar.invalid")
    : enabled && sources.length === 0 ? t("settings.dnsBlocking.needsList") : undefined;
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
  const edit = <T,>(set: (value: T) => void) => (value: T) => { set(value); setNotice(null); };
  const status = settings?.status;
  // What the server runs now; a refresh failure is reported separately because the last good list stays in effect.
  const serverText = !settings || !status ? null
    : settings.pending ? t("dns.blocklist.status.pending")
    : status.active ? t("dns.blocklist.status.active", {
      count: formatNumber(status.domain_count),
      time: formatDateTime(new Date((status.updated_at_unix ?? 0) * 1000), { dateStyle: "medium", timeStyle: "short" }),
    })
    : t("dns.blocklist.status.off");

  return <section className="settings-card" aria-label={t("dns.blocklist.title")}>
    <h2>{t("dns.blocklist.title")}</h2>
    <p>{t("dns.blocklist.summary")}</p>
    {!connected ? <ConnectFirst onConnect={onConnect} />
      : supported === false ? <SettingsNotice action={onRepair && { label: t("settings.parts.repair"), onClick: onRepair }}>{t("dns.blocklist.unsupported")}</SettingsNotice>
      : settings ? <>
        <label className="preference-row">
          <span><strong>{t("dns.blocklist.enable")}</strong>
            {serverText && <small>{t("common.separator.pair", { first: t("settings.dnsBlocking.serverStatus"), second: serverText })}</small>}</span>
          <input type="checkbox" role="switch" aria-label={t("dns.blocklist.enable")} checked={enabled} disabled={busy} onChange={(event) => edit(setEnabled)(event.target.checked)} />
        </label>
        {status?.failure && <SettingsNotice tone="warning">{t(`dns.blocklist.failure.${status.failure}`)}</SettingsNotice>}
        <fieldset className="choice-fieldset">
          <legend>{t("dns.blocklist.lists")}</legend>
          {settings.presets.map((preset) => <label className="preference-checkbox" key={preset.url}>
            <input type="checkbox" checked={presets.includes(preset.url)} disabled={busy} onChange={(event) => edit(setPresets)(event.target.checked ? [...presets, preset.url] : presets.filter((url) => url !== preset.url))} />
            <span>{preset.name}</span>
          </label>)}
        </fieldset>
        <div className="invite-form">
          <Field label={t("dns.blocklist.custom")} hint={t("dns.blocklist.customHint")} error={sourceError}>
            <textarea rows={2} spellCheck={false} value={custom} disabled={busy} onChange={(event) => edit(setCustom)(event.target.value)} />
          </Field>
          <Field label={t("dns.blocklist.allowlist")} hint={t("dns.blocklist.allowlistHint")} error={allowError}>
            <textarea rows={3} spellCheck={false} value={allow} disabled={busy} onChange={(event) => edit(setAllow)(event.target.value)} />
          </Field>
        </div>
        <CardSaveRow dirty={dirty} saving={busy} problem={problem} saved={notice} saveLabel={t("dns.blocklist.save")}
          onSave={() => void save()} onDiscard={() => { show(settings); setError(null); }}>
          <button className="secondary-button" onClick={() => void refresh()} disabled={busy}>{t("dns.blocklist.refresh")}</button>
        </CardSaveRow>
        {error && <InlineError message={error} onRetry={dirty && !problem ? () => void save() : undefined} retryDisabled={busy} />}
      </> : loadFailed ? <InlineError message={error ?? ""} onRetry={() => void refresh()} />
      : <p role="status">{t("common.state.loading")}</p>}
  </section>;
}
