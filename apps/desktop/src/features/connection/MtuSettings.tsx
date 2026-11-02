import { useEffect, useState } from "react";
import { Field } from "../../components/ui";
import type { LocalTunnelStatus } from "../../types";
import type { ServerWorkspaceModel } from "./useServerWorkspace";
import { t } from "../../i18n";
import { formatTransport } from "../../format";
import { formatMtu, IPV6_MIN_MTU, MAX_MTU, MIN_MTU, OBFUSCATED_UDP_MAX_MTU, QUIC_MAX_MTU } from "./connectionPreferences";
import { SettingsNotice } from "../settings/SettingsParts";

export function mtuDescription(mtu: NonNullable<LocalTunnelStatus["mtu"]>): string {
  switch (mtu.outcome) {
    case "pending": return t("connection.mtu.outcome.pending");
    case "measured": return mtu.suggested === null ? t("connection.mtu.outcome.incomplete") : mtu.policy.mode === "automatic" ? mtu.suggested === mtu.configured ? t("connection.mtu.outcome.verified", { value: formatMtu(mtu.configured) }) : t("connection.mtu.outcome.smaller") : t("connection.mtu.outcome.manual");
    case "icmp_unavailable": return t("connection.mtu.outcome.noReply");
    case "no_usable_mtu": return t("connection.mtu.outcome.noUsable", { tls: formatTransport("tls_like"), tcp: formatTransport("tcp_fallback") });
    case "apply_failed": return t("connection.mtu.outcome.applyFailed", { value: formatMtu(mtu.configured) });
  }
}

/** Measurements that didn't work read as warnings, not as ordinary notes. */
const failedOutcomes = new Set(["icmp_unavailable", "no_usable_mtu", "apply_failed"]);

export function MtuSettings({ model }: { model: ServerWorkspaceModel }) {
  const manual = model.preferences.draft.manual_mtu ?? null;
  // An empty field is an edit in progress, not a request for automatic MTU.
  const [manualText, setManualText] = useState(manual === null ? "" : String(manual));
  useEffect(() => {
    setManualText(current => current !== "" && Number(current) === manual ? current : manual === null ? "" : String(manual));
  }, [manual]);
  const minimum = model.profile.ipv6_tunnel_enabled ? IPV6_MIN_MTU : MIN_MTU;
  const { setMtuMinimum } = model.preferences;
  useEffect(() => setMtuMinimum(minimum), [minimum, setMtuMinimum]);
  const mtu = model.localStatus.server_id === model.profile.id && model.localStatus.state === "connected" ? model.localStatus.mtu : null;
  const disabled = model.busy || model.preferences.saving || !model.preferences.ready;
  const range = { min: formatMtu(minimum), max: formatMtu(MAX_MTU) };
  const shown = mtu && manual !== null ? { ...mtu, policy: { mode: "manual" as const, value: manual } } : mtu;
  const unsupported = model.localStatus.mtu_detection_supported === false;
  return <section className="settings-card" aria-label={t("connection.mtu.title")}>
    <h2>{t("connection.mtu.title")}</h2>
    <p>{t("connection.nextConnection")}</p>
    {unsupported && <SettingsNotice tone="warning">{t("connection.mtu.unsupported")}</SettingsNotice>}
    <label className="preference-row"><span><strong>{t("connection.mtu.automatic.label")}</strong><small>{t("connection.mtu.automatic.summary")}</small></span>
      <input type="checkbox" role="switch" aria-label={t("connection.mtu.automatic.label")} checked={manual === null} disabled={disabled}
        onChange={(event) => model.preferences.change({ manual_mtu: event.target.checked ? null : mtu?.configured ?? MAX_MTU })} />
    </label>
    {manual !== null && <Field label={t("connection.mtu.manual.label")} hint={t("connection.mtu.manual.hint", { ...range, obfuscatedMax: formatMtu(OBFUSCATED_UDP_MAX_MTU), quicMax: formatMtu(QUIC_MAX_MTU) })}
      error={model.preferences.mtuInvalid ? t(minimum === IPV6_MIN_MTU ? "connection.mtu.manual.invalidIpv6" : "connection.mtu.manual.invalid", range) : undefined}>
      <input aria-label={t("connection.mtu.manual.label")} type="number" min={minimum} max={MAX_MTU} step={1} value={manualText} disabled={disabled}
        onChange={(event) => { setManualText(event.target.value); if (event.target.value) model.preferences.change({ manual_mtu: Number(event.target.value) }); }}
        onBlur={() => { if (!manualText) setManualText(String(manual)); }} />
    </Field>}
    {/* With a manual size chosen, describe the live measurement as manual: nothing will be applied automatically. */}
    {shown && <MtuDetails mtu={shown} />}
    {shown && failedOutcomes.has(shown.outcome)
      ? <SettingsNotice tone="warning">{mtuDescription(shown)}</SettingsNotice>
      : !unsupported && <p className="settings-note">{shown ? mtuDescription(shown) : t("connection.mtu.notConnected")}</p>}
  </section>;
}

export function MtuDetails({ mtu }: { mtu: NonNullable<LocalTunnelStatus["mtu"]> }) {
  const pending = mtu.policy.mode === "automatic" && mtu.outcome === "measured" && mtu.suggested !== null && mtu.suggested < mtu.configured;
  return <dl className="result-facts mtu-details">
    <div><dt>{t("connection.mtu.details.current")}</dt><dd>{t("connection.mtu.details.bytes", { value: formatMtu(mtu.configured) })}</dd></div>
    <div><dt>{t("connection.mtu.details.recommended")}</dt><dd>{mtu.suggested !== null ? t("connection.mtu.details.bytes", { value: formatMtu(mtu.suggested) }) : t("connection.mtu.details.notMeasured")}</dd></div>
    {pending && mtu.suggested !== null && <div><dt>{t("connection.mtu.details.pending")}</dt><dd>{t("connection.mtu.details.pendingValue", { value: formatMtu(mtu.suggested) })}</dd></div>}
  </dl>;
}
