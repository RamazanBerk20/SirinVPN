import { t } from "../../i18n";

export type HealthState = "unknown" | "reconnecting" | "connected" | "disconnected";
export type Reachability = "notChecked" | "replied" | "noReply";

/** Shared presentation contract. Handshake inactivity and management outages do
 * not imply a reconnect. A probe describes only the last observed measurement. */
export function connectionHealth(input: {
  known: boolean; established: boolean; reconnecting: boolean;
  handshakeRecent?: boolean; managementAvailable?: boolean;
  probe?: { probes_sent: number; probes_received: number } | null;
}) {
  const state: HealthState = !input.known ? "unknown" : input.reconnecting ? "reconnecting" : input.established ? "connected" : "disconnected";
  const reachabilityState: Reachability = !input.known || !input.established || !input.probe?.probes_sent
    ? "notChecked"
    : input.probe.probes_received > 0 ? "replied" : "noReply";
  const detail = input.handshakeRecent === false
    ? t("home.health.idle")
    : input.managementAvailable === false ? t("home.health.managementUnavailable") : null;
  return {
    state,
    status: t(`home.status.${state}`),
    reachabilityState,
    reachability: t(`home.health.reachability.${reachabilityState}`),
    detail,
  };
}
