import { Field } from "../../components/ui";
import { validateHost } from "../../format";
import type { ServerProfile, TransportSetup } from "../../types";
import { useInfoHint } from "../../components/InfoHint";
import { t } from "../../i18n";

export interface TransportDraft {
  publicHost: string;
  alternateHosts: string;
  wireguard: string;
  obfuscated: string;
  tcpTls: string;
  https: boolean;
  hostname: string;
  path: string;
  certificate: string;
  privateKey: string;
}

export function newTransportDraft(profile?: ServerProfile): TransportDraft {
  return {
    publicHost: profile?.endpoint.host ?? "",
    alternateHosts: profile?.alternate_endpoint_hosts?.join("\n") ?? "",
    wireguard: String(profile?.endpoint.wireguard_port ?? 51820),
    obfuscated: String(profile?.obfuscated_udp?.port ?? 443),
    tcpTls: String(profile?.tcp_fallback?.port ?? 443),
    https: Boolean(profile?.tls_like?.https),
    hostname: profile?.tls_like?.https?.server_name ?? "",
    path: profile?.tls_like?.https?.path ?? "/connect",
    certificate: "", privateKey: "",
  };
}

export function transportDraftIsValid(draft: TransportDraft): boolean {
  const alternatives = draft.alternateHosts.split(/[\s,]+/).filter(Boolean).map((host) => host.toLowerCase());
  if ((draft.publicHost.trim() && !validateHost(draft.publicHost.trim())) || alternatives.length > 3 || new Set(alternatives).size !== alternatives.length || alternatives.some((host) => !validateHost(host) || host === draft.publicHost.trim().toLowerCase())) return false;
  const ports = [draft.wireguard, draft.obfuscated, draft.tcpTls];
  if (ports.some((port) => !/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535 || [53, 5053, 8443].includes(Number(port)))) return false;
  if (Number(draft.wireguard) === Number(draft.obfuscated) || Number(draft.wireguard) === Number(draft.tcpTls)) return false;
  if (!draft.https) return true;
  const hostname = draft.hostname.trim();
  if (!validateHost(hostname) || !hostname.includes(".") || hostname.includes(":") || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return false;
  if (!/^\/[a-zA-Z0-9/_.-]{1,127}$/.test(draft.path) || draft.path.includes("..") || draft.path.includes("//")) return false;
  if (Boolean(draft.certificate) !== Boolean(draft.privateKey)) return false;
  return [draft.certificate, draft.privateKey].every((path) => !path || (path.startsWith("/") && path.length <= 4096 && !/[\x00-\x1f\x7f]/.test(path)));
}

export function transportSetupFromDraft(draft: TransportDraft, profile?: ServerProfile): TransportSetup {
  return {
    public_host: draft.publicHost.trim() || null,
    alternate_endpoint_hosts: draft.alternateHosts.split(/[\s,]+/).filter(Boolean).map((host) => host.toLowerCase()),
    wireguard_port: Number(draft.wireguard), obfuscated_udp_port: Number(draft.obfuscated), tcp_tls_port: Number(draft.tcpTls),
    https: draft.https ? { server_name: draft.hostname.trim().toLowerCase(), path: draft.path } : null,
    https_certificate_path: draft.https && draft.certificate ? draft.certificate : null,
    https_private_key_path: draft.https && draft.privateKey ? draft.privateKey : null,
    disable_https: Boolean(profile?.tls_like?.https) && !draft.https,
  };
}

export function TransportSetupFields({ value, onChange, existing = false }: {
  value: TransportDraft; onChange: (value: TransportDraft) => void; existing?: boolean;
}) {
  const update = <K extends keyof TransportDraft>(key: K, next: TransportDraft[K]) => onChange({ ...value, [key]: next });
  const [portsHint, portsPanel] = useInfoHint(t("ssh.transport.portsInfo"), t("ssh.transport.portsInfoLabel"));
  const [httpsHint, httpsPanel] = useInfoHint(t("ssh.transport.httpsInfo"), t("ssh.transport.httpsInfoLabel"));
  return <details className="advanced-fields">
    <summary>{t("ssh.transport.summary")}</summary>
    <Field label={t("ssh.transport.publicHost")}><input placeholder={t("ssh.transport.publicHostPlaceholder")} value={value.publicHost} onChange={(event) => update("publicHost", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
    <Field label={t("ssh.transport.alternateHosts")}><textarea rows={3} placeholder={t("ssh.transport.alternateHostsPlaceholder")} value={value.alternateHosts} onChange={(event) => update("alternateHosts", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
    <p className="settings-note">{t("ssh.transport.alternateNote")}</p>
    <div className="field-grid">
      <Field label={t("ssh.transport.directPort")}><input inputMode="numeric" value={value.wireguard} onChange={(event) => update("wireguard", event.target.value)} /></Field>
      <Field label={t("ssh.transport.obfuscatedPort")}><input inputMode="numeric" value={value.obfuscated} onChange={(event) => update("obfuscated", event.target.value)} /></Field>
      <Field label={t("ssh.transport.tcpTlsPort")}><input inputMode="numeric" value={value.tcpTls} onChange={(event) => update("tcpTls", event.target.value)} /></Field>
    </div>
    <p className="settings-note">{t("ssh.transport.portsNote")}{portsHint}</p>
    {portsPanel}
    <label className="checkbox-row"><input type="checkbox" checked={value.https} onChange={(event) => update("https", event.target.checked)} />{t("ssh.transport.https")}</label>
    {value.https && <>
      <div className="field-grid">
        <Field label={t("ssh.transport.hostname")}><input placeholder={t("ssh.transport.hostnamePlaceholder")} value={value.hostname} onChange={(event) => update("hostname", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
        <Field label={t("ssh.transport.path")}><input value={value.path} onChange={(event) => update("path", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
      </div>
      <p className="settings-note">{t("ssh.transport.httpsNote")}{httpsHint}</p>
      {httpsPanel}
      <Field label={t("ssh.transport.certificate")}><input placeholder={t("ssh.transport.certificatePlaceholder")} value={value.certificate} onChange={(event) => update("certificate", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
      <Field label={t("ssh.transport.privateKey")}><input placeholder={t("ssh.transport.privateKeyPlaceholder")} value={value.privateKey} onChange={(event) => update("privateKey", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
    </>}
    {existing && <p className="settings-note">{t("ssh.transport.existingNote")}</p>}
    {!transportDraftIsValid(value) && <p className="settings-note" role="status">{t("ssh.transport.invalid")}</p>}
  </details>;
}
