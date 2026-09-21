import type { DnsEndpointDraft, DnsPolicyChoice, PrivateDnsRecordChoice } from "./DnsFields";

export function DnsChangeReview({ choice, endpoints, privateChoice, records, splitDns }: {
  choice: DnsPolicyChoice; endpoints: DnsEndpointDraft[]; privateChoice: PrivateDnsRecordChoice; records: string; splitDns: string;
}) {
  return <section className="dns-change-review" aria-label="DNS change review">
    <h3>Review DNS changes</h3>
    <p>The current VPS policy is read during the SSH operation. A live DNS snapshot is unavailable while disconnected.</p>
    <dl>
      <dt>Resolver</dt><dd>{choice === "preserve" ? "Keep the current resolver and split DNS zones." : choice === "recursive" ? "Replace with recursive DNS and DNSSEC validation." : `Replace with authenticated ${choice === "dns_over_tls" ? "DNS over TLS" : "DNS over HTTPS"}. No plaintext fallback.`}</dd>
      {(choice === "dns_over_tls" || choice === "dns_over_https") && <><dt>Upstreams</dt><dd>{endpoints.filter(endpoint => endpoint.address.trim()).map((endpoint, index) => <div key={index}>{endpoint.address} · {endpoint.authenticationName}{choice === "dns_over_https" ? ` · ${endpoint.path}` : ""}</div>)}</dd></>}
      {choice !== "preserve" && <><dt>Split DNS zones</dt><dd>{splitDns.trim() ? <pre>{splitDns}</pre> : "Remove existing split zones; use the selected resolver for all domains."}</dd></>}
      <dt>Private records</dt><dd>{privateChoice === "preserve" ? "Keep all current records." : privateChoice === "clear" ? "Remove all current private records." : <>Replace all current records with:<pre>{records}</pre></>}</dd>
    </dl>
    <p>All devices using this VPS are affected. Bundled VPS software is reapplied and services briefly restart. Addresses, transport ports, identities and member access are preserved.</p>
  </section>;
}
