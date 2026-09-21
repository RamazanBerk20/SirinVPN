import { Field } from "../../components/ui";
import type { LocalTunnelStatus } from "../../types";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

export function mtuDescription(mtu: NonNullable<LocalTunnelStatus["mtu"]>): string {
  switch (mtu.outcome) {
    case "pending": return "Waiting for a VPN handshake before checking packet delivery.";
    case "measured": return mtu.suggested === null ? "The measurement is incomplete. Waiting for a usable recommendation." : mtu.policy.mode === "automatic" ? mtu.suggested === mtu.configured ? `Packet delivery verified at MTU ${mtu.configured}.` : "A smaller packet size was measured. Automatic adjustment waits for traffic to be quiet and protection to be ready." : "The measured recommendation is available. Manual MTU stays fixed for this connection.";
    case "icmp_unavailable": return "The VPS did not answer the small ICMP probe. MTU could not be measured; the configured value remains active.";
    case "no_usable_mtu": return "Small packets work, but larger probes failed within the supported MTU range. Try TLS or TCP transport on a constrained path.";
    case "apply_failed": return `The local component could not apply the measured value. MTU ${mtu.configured} remains configured.`;
  }
}

export function MtuSettings({ model }: { model: ServerWorkspaceModel }) {
  const manual = model.preferences.draft.manual_mtu ?? null;
  const mtu = model.localStatus.server_id === model.profile.id && model.localStatus.state === "connected" ? model.localStatus.mtu : null;
  const minimum = model.profile.ipv6_tunnel_enabled ? 1280 : 576;
  const disabled = model.busy || model.preferences.saving || !model.preferences.ready;
  return <section className="settings-card" aria-label="Tunnel packet size">
    <h2>Tunnel MTU</h2>
    <label className="preference-row"><span><strong>Determine a safe packet size</strong><small>While connected, probe the private VPN path. Automatic mode can reduce the current tunnel’s MTU when protection is ready and traffic is quiet.</small></span>
      <input type="checkbox" role="switch" aria-label="Determine a safe packet size" checked={manual === null} disabled={disabled}
        onChange={(event) => model.preferences.change({ manual_mtu: event.target.checked ? null : mtu?.configured ?? 1420 })} />
    </label>
    {manual !== null && <Field label="Manual MTU" hint={`${minimum}–1420 bytes. This value applies to every selected transport and stays fixed during the connection.`}>
      <input aria-label="Manual MTU" type="number" min={minimum} max={1420} step={1} value={manual} disabled={disabled}
        onChange={(event) => model.preferences.change({ manual_mtu: event.target.value ? Number(event.target.value) : null })} />
    </Field>}
    {manual !== null && (!Number.isInteger(manual) || manual < minimum || manual > 1420) && <p className="warning-note">Choose a whole number between {minimum} and 1420{minimum === 1280 ? " while tunneled IPv6 is enabled" : ""}.</p>}
    <p className="settings-note">Changes to this preference apply on the next connection.</p>
    {mtu && <MtuDetails mtu={mtu} />}
    <p className="settings-note">{mtu ? mtuDescription(mtu) : "The current measurement appears after connecting."}</p>
    {model.localStatus.mtu_detection_supported === false && <p className="settings-note">Update the local VPN component to enable MTU measurements.</p>}
  </section>;
}

export function MtuDetails({ mtu }: { mtu: NonNullable<LocalTunnelStatus["mtu"]> }) {
  const pending = mtu.policy.mode === "automatic" && mtu.outcome === "measured" && mtu.suggested !== null && mtu.suggested < mtu.configured;
  return <dl className="result-facts mtu-details">
    <div><dt>Current MTU</dt><dd>{mtu.configured} bytes</dd></div>
    <div><dt>Detected recommendation</dt><dd>{mtu.suggested !== null ? `${mtu.suggested} bytes` : "Not yet available"}</dd></div>
    {pending && <div><dt>Pending change</dt><dd>{mtu.suggested} bytes · waiting for protection and idle traffic</dd></div>}
  </dl>;
}
