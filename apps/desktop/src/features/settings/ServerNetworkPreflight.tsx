import type { NetworkPreflight } from "../../types";

const exposureLabels: Record<NetworkPreflight["exposure"], string> = {
  public_interface: "Public connection address",
  nat_or_proxy: "NAT or proxy may be involved",
  private_endpoint: "Private network address",
  unresolved: "VPN address did not resolve",
};

export function ServerNetworkPreflight({ report }: { report: NetworkPreflight }) {
  const blocked = report.issues.some((issue) => issue.blocking);
  const conflicts = report.issues.filter((issue) => issue.blocking);
  const notes = report.issues.filter((issue) => !issue.blocking);
  return <section className="settings-section network-preflight" aria-label="VPS network preflight">
    <h3>{blocked ? "Resolve these network conflicts" : "VPS network inspection"}</h3>
    <div className="network-address"><span>{exposureLabels[report.exposure]}</span><code>{report.public_endpoint}</code></div>
    <p>Required incoming ports on your provider firewall or NAT mapping:</p>
    <ul className="network-port-list" aria-label="Required incoming ports">{report.required_ports.map(({ protocol, port }) => <li key={`${protocol}:${port}`} aria-label={`${protocol.toUpperCase()} port ${port}`}><span>{protocol.toUpperCase()}</span><strong>{port}</strong></li>)}</ul>
    {conflicts.length > 0 && <ul className="network-conflicts">{conflicts.map((issue, index) => <li key={`${issue.code}:${index}`}>
      {issue.message}
    </li>)}</ul>}
    {notes.length > 0 && <details><summary>Other network configuration</summary><ul className="network-notes">{notes.map((issue, index) => <li key={`${issue.code}:${index}`}>{issue.message}</li>)}</ul></details>}
    <details><summary>Assigned VPS addresses</summary><ul className="network-address-list">{report.assigned_addresses.map((entry) => <li key={`${entry.interface}:${entry.address}`}>
      <code>{entry.address}/{entry.prefix_length}</code> on {entry.interface}
    </li>)}</ul></details>
  </section>;
}
