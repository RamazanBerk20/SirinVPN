/** Shared presentation contract. Handshake inactivity and management outages do
 * not imply a reconnect. A probe describes only the last observed measurement. */
export function connectionHealth(input: {
  known: boolean; established: boolean; reconnecting: boolean;
  handshakeRecent?: boolean; managementAvailable?: boolean;
  probe?: { probes_sent: number; probes_received: number } | null;
}) {
  const status = !input.known ? "Connection status unknown" : input.reconnecting ? "Reconnecting" : input.established ? "Connected" : "Disconnected";
  const reachability = !input.known || !input.established || !input.probe?.probes_sent
    ? "Reachability not verified"
    : input.probe.probes_received > 0 ? "Last path probe replied" : "Last path probe unanswered";
  const detail = input.handshakeRecent === false
    ? "The tunnel may be idle. Handshake inactivity alone does not establish a connection failure."
    : input.managementAvailable === false ? "VPS management is unavailable; tunnel reachability is assessed separately." : null;
  return { status, reachability, detail };
}
