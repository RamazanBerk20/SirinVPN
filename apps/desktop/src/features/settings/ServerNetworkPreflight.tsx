import type { NetworkPreflight } from "../../types";
import { t, type MessageKey } from "../../i18n";
import { Rich } from "../../i18n/Rich";

const exposureLabels: Record<NetworkPreflight["exposure"], MessageKey> = {
  public_interface: "ssh.network.exposure.publicInterface",
  nat_or_proxy: "ssh.network.exposure.natOrProxy",
  private_endpoint: "ssh.network.exposure.privateEndpoint",
  unresolved: "ssh.network.exposure.unresolved",
};

export function ServerNetworkPreflight({ report }: { report: NetworkPreflight }) {
  const blocked = report.issues.some((issue) => issue.blocking);
  const conflicts = report.issues.filter((issue) => issue.blocking);
  const notes = report.issues.filter((issue) => !issue.blocking);
  return <section className="settings-section network-preflight" aria-label={t("ssh.network.title")}>
    <h3>{blocked ? t("ssh.network.titleConflicts") : t("ssh.network.title")}</h3>
    <div className="network-address"><span>{t(exposureLabels[report.exposure])}</span><code>{report.public_endpoint}</code></div>
    <p>{t("ssh.network.ports")}</p>
    <ul className="network-port-list" aria-label={t("ssh.network.portsLabel")}>{report.required_ports.map(({ protocol, port }) => <li key={`${protocol}:${port}`} aria-label={t("ssh.network.port", { protocol: protocol.toUpperCase(), port })}><span>{protocol.toUpperCase()}</span><strong>{port}</strong></li>)}</ul>
    {conflicts.length > 0 && <ul className="network-conflicts">{conflicts.map((issue, index) => <li key={`${issue.code}:${index}`}>
      {issue.message}
    </li>)}</ul>}
    {notes.length > 0 && <details><summary>{t("ssh.network.otherNotes")}</summary><ul className="network-notes">{notes.map((issue, index) => <li key={`${issue.code}:${index}`}>{issue.message}</li>)}</ul></details>}
    <details><summary>{t("ssh.network.addresses")}</summary><ul className="network-address-list">{report.assigned_addresses.map((entry) => <li key={`${entry.interface}:${entry.address}`}>
      <Rich id="ssh.network.address" params={{ address: entry.address, prefix: entry.prefix_length, interface: entry.interface }} tags={{ code: (content) => <code>{content}</code> }} />
    </li>)}</ul></details>
  </section>;
}
