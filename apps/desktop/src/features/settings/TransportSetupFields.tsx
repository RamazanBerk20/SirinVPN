import { Field } from "../../components/ui";
import { validateHost } from "../../format";
import type { ServerProfile, TransportSetup } from "../../types";

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
  return <details className="advanced-fields">
    <summary>Public addresses, transport ports and HTTPS</summary>
    <Field label="Public VPN address (optional)"><input placeholder="Defaults to the SSH address" value={value.publicHost} onChange={(event) => update("publicHost", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
    <Field label="Alternate addresses (optional)"><textarea rows={3} placeholder="Up to three hostnames or IP addresses" value={value.alternateHosts} onChange={(event) => update("alternateHosts", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
    <p className="settings-note">Every address must reach this same VPS and use the same transport ports. Clients verify the server’s identity at each address.</p>
    <div className="field-grid">
      <Field label="Direct UDP port"><input inputMode="numeric" value={value.wireguard} onChange={(event) => update("wireguard", event.target.value)} /></Field>
      <Field label="Obfuscated UDP port"><input inputMode="numeric" value={value.obfuscated} onChange={(event) => update("obfuscated", event.target.value)} /></Field>
      <Field label="TCP and TLS port"><input inputMode="numeric" value={value.tcpTls} onChange={(event) => update("tcpTls", event.target.value)} /></Field>
    </div>
    <p className="settings-note">TCP fallback and TLS share one listener. Open the chosen ports in your VPS provider’s firewall. Private DNS and management ports are reserved.</p>
    <p className="settings-note">The original TLS port stays open for authenticated endpoint updates when you change the transport port. Keep that port allowed in the provider firewall.</p>
    <label className="checkbox-row"><input type="checkbox" checked={value.https} onChange={(event) => update("https", event.target.checked)} />Use HTTPS mode</label>
    {value.https && <>
      <div className="field-grid">
        <Field label="HTTPS hostname"><input placeholder="vpn.example.org" value={value.hostname} onChange={(event) => update("hostname", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
        <Field label="HTTPS path"><input value={value.path} onChange={(event) => update("path", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
      </div>
      <p className="settings-note">Use a hostname you control. A pinned certificate is generated by default. To present a certificate from your certificate authority, enter both PEM paths already on the VPS.</p>
      <Field label="Certificate chain path on VPS (optional)"><input placeholder="/etc/letsencrypt/live/vpn.example.org/fullchain.pem" value={value.certificate} onChange={(event) => update("certificate", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
      <Field label="Certificate private key path on VPS (optional)"><input placeholder="/etc/letsencrypt/live/vpn.example.org/privkey.pem" value={value.privateKey} onChange={(event) => update("privateKey", event.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
      <p className="settings-note">The VPS keeps its own copy of the certificate. Import renewals through this screen so clients receive the new pin. HTTPS behavior does not guarantee access through every restrictive network.</p>
    </>}
    {existing && <p className="settings-note">Before changing ports or certificates, cancel active invitations and finish any enrollment or key rotation. Changes take effect after the guarded repair commits.</p>}
    {!transportDraftIsValid(value) && <p className="settings-note" role="status">Check the port numbers, hostname, path, and matching certificate paths.</p>}
  </details>;
}
