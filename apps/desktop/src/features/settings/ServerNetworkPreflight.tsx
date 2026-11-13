import type { NetworkPreflight } from "../../types";
import { t, type MessageKey } from "../../i18n";
import { Rich } from "../../i18n/Rich";
import { SettingsDisclosure } from "./SettingsParts";

const exposureLabels: Record<NetworkPreflight["exposure"], MessageKey> = {
  public_interface: "ssh.network.exposure.publicInterface",
  nat_or_proxy: "ssh.network.exposure.natOrProxy",
  private_endpoint: "ssh.network.exposure.privateEndpoint",
  unresolved: "ssh.network.exposure.unresolved",
};

const issueLabels: Partial<Record<string, MessageKey>> = {
  endpoint_resolution: "ssh.network.issue.endpointResolution",
  nat_or_proxy: "ssh.network.issue.natOrProxy",
  private_endpoint: "ssh.network.issue.privateEndpoint",
  ipv6_only: "ssh.network.issue.ipv6Only",
};
// Issues whose backend text names something specific (a service, an interface): the translated
// summary comes first and the backend's English text follows as secondary detail.
const summaryLabels: Partial<Record<string, MessageKey>> = {
  reserved_interface: "ssh.network.issue.reservedInterface",
  existing_vpn: "ssh.network.issue.existingVpn",
  existing_firewall: "ssh.network.issue.existingFirewall",
  firewall_drop_policy: "ssh.network.issue.firewallDropPolicy",
  firewall_service: "ssh.network.issue.firewallService",
};
// Issues that name ports, interfaces or routes; without `params` (an older native layer) the backend's own text is shown.
const valueLabels: Partial<Record<string, MessageKey>> = {
  tunnel_address_conflict: "ssh.network.issue.tunnelAddressConflict",
  private_service_port: "ssh.network.issue.privateServicePort",
  ssh_port_conflict: "ssh.network.issue.sshPortConflict",
  port_in_use: "ssh.network.issue.portInUse",
  tunnel_route_conflict: "ssh.network.issue.tunnelRouteConflict",
};

/** A known issue in the catalog's words, keeping the backend's text as its detail. */
function Issue({ issue }: { issue: NetworkPreflight["issues"][number] }) {
  const label = issueLabels[issue.code] ?? (issue.params ? valueLabels[issue.code] : undefined);
  if (label) return <li title={issue.message}>{t(label, { ...issue.params, protocol: issue.params?.protocol?.toUpperCase() ?? "" })}</li>;
  return <li>{t(summaryLabels[issue.code] ?? "ssh.network.issue.other")}<br /><small className="error-detail" lang="en" dir="auto">{issue.message}</small></li>;
}

export function ServerNetworkPreflight({ report }: { report: NetworkPreflight }) {
  const blocked = report.issues.some((issue) => issue.blocking);
  const conflicts = report.issues.filter((issue) => issue.blocking);
  const notes = report.issues.filter((issue) => !issue.blocking);
  return <section className="settings-section network-preflight" aria-label={t("ssh.network.title")}>
    <h3>{blocked ? t("ssh.network.titleConflicts") : t("ssh.network.title")}</h3>
    <div className="network-address"><span>{t(exposureLabels[report.exposure])}</span><code>{report.public_endpoint}</code></div>
    <p>{t("ssh.network.ports")}</p>
    <ul className="network-port-list" aria-label={t("ssh.network.portsLabel")}>{report.required_ports.map(({ protocol, port }) => <li key={`${protocol}:${port}`} aria-label={t("ssh.network.port", { protocol: protocol.toUpperCase(), port: String(port) })}><span>{protocol.toUpperCase()}</span><strong>{port}</strong></li>)}</ul>
    {conflicts.length > 0 && <ul className="network-conflicts">{conflicts.map((issue, index) => <Issue key={`${issue.code}:${index}`} issue={issue} />)}</ul>}
    {notes.length > 0 && <SettingsDisclosure summary={t("ssh.network.otherNotes")}><ul className="network-notes">{notes.map((issue, index) => <Issue key={`${issue.code}:${index}`} issue={issue} />)}</ul></SettingsDisclosure>}
    {report.assigned_addresses.length > 0 && <SettingsDisclosure summary={t("ssh.network.addresses")}><ul className="network-address-list">{report.assigned_addresses.map((entry) => <li key={`${entry.interface}:${entry.address}`}>
      <Rich id="ssh.network.address" params={{ address: entry.address, prefix: String(entry.prefix_length), interface: entry.interface }} tags={{ code: (content) => <code>{content}</code> }} />
    </li>)}</ul></SettingsDisclosure>}
  </section>;
}
