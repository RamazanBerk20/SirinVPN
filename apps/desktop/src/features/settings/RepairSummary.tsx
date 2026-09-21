import { Check } from "@phosphor-icons/react";
import { CopyValue } from "../../components/CopyValue";
import { formatDnsPolicy } from "../../format";
import type { RepairResult, ServerProfile } from "../../types";
import { ServerNetworkPreflight } from "./ServerNetworkPreflight";

export function RepairSummary({ profile, result, dnsPreserved, recordsPreserved }: {
  profile: ServerProfile;
  result: RepairResult;
  dnsPreserved: boolean;
  recordsPreserved: boolean;
}) {
  const fingerprint = result.server_identity_fingerprint;
  return <div className="repair-result">
    <div className="repair-result-heading">
      <span className="result-check"><Check size={26} weight="bold" /></span>
      <h3>{profile.name} is ready to reconnect</h3>
      <p>The server component and VPN configuration were repaired and checked.</p>
    </div>
    <section className="result-section" aria-labelledby="repair-completed-heading">
      <h3 id="repair-completed-heading">Completed</h3>
      <dl className="result-facts">
        <div><dt>Server software</dt><dd>Installed and verified</dd></div>
        <div><dt>VPN services</dt><dd>Restarted and checked</dd></div>
        <div><dt>Private DNS</dt><dd>Verification passed · {formatDnsPolicy(result.dns_upstream)}</dd></div>
        <div><dt>Private records</dt><dd>{result.private_dns_records.length === 0 ? "None configured" : `${result.private_dns_records.length} configured and verified`}</dd></div>
      </dl>
    </section>
    <section className="result-section" aria-labelledby="repair-preserved-heading">
      <h3 id="repair-preserved-heading">Preserved</h3>
      <ul className="result-list">
        <li>Server and device identities and existing access</li>
        {dnsPreserved && <li>Private DNS policy</li>}
        {recordsPreserved && <li>Private DNS records</li>}
      </ul>
      <div className="result-identity">
        <span>Server identity fingerprint</span>
        {fingerprint ? <CopyValue value={fingerprint} label="server identity fingerprint" shorten showCopyLabel />
          : <span className="settings-note">The preserved identity is pinned in this server’s saved profile.</span>}
      </div>
    </section>
    {result.network_preflight && <details className="result-disclosure">
      <summary>Network requirements · review if needed</summary>
      <p className="settings-note">Provider firewall access was not verified by this inspection. Review these requirements if a connection or transport fails.</p>
      <ServerNetworkPreflight report={result.network_preflight} />
    </details>}
    <details className="result-disclosure">
      <summary>Installed software details</summary>
      <div className="result-identity"><span>Server software SHA-256</span>
        <CopyValue value={result.artifact_sha256} label="server software checksum" shorten showCopyLabel />
      </div>
    </details>
    <p className="result-next-step">Return to Home, connect to {profile.name}, and run diagnostics to check this device’s connection.</p>
  </div>;
}
