import { t } from "../../i18n";
import type { DnsEndpointDraft, DnsPolicyChoice, PrivateDnsRecordChoice } from "./DnsFields";

const resolverText = {
  preserve: "dns.review.resolver.preserve",
  recursive: "dns.review.resolver.recursive",
  dns_over_tls: "dns.review.resolver.dnsOverTls",
  dns_over_https: "dns.review.resolver.dnsOverHttps",
} as const;

export function DnsChangeReview({ choice, endpoints, privateChoice, records, splitDns }: {
  choice: DnsPolicyChoice; endpoints: DnsEndpointDraft[]; privateChoice: PrivateDnsRecordChoice; records: string; splitDns: string;
}) {
  return <section className="dns-change-review" aria-label={t("dns.review.label")}>
    <h3>{t("dns.review.title")}</h3>
    <dl>
      <dt>{t("dns.review.resolver.term")}</dt><dd>{t(resolverText[choice])}</dd>
      {(choice === "dns_over_tls" || choice === "dns_over_https") && <><dt>{t("dns.review.addresses")}</dt><dd>{endpoints.filter(endpoint => endpoint.address.trim()).map((endpoint, index) => <div key={index}>{choice === "dns_over_https"
        ? t("common.separator.triple", { first: endpoint.address, second: endpoint.authenticationName, third: endpoint.path })
        : t("common.separator.pair", { first: endpoint.address, second: endpoint.authenticationName })}</div>)}</dd></>}
      {choice !== "preserve" && <><dt>{t("dns.review.split.term")}</dt><dd>{splitDns.trim() ? <pre>{splitDns}</pre> : t("dns.review.split.none")}</dd></>}
      <dt>{t("dns.review.records.term")}</dt><dd>{privateChoice === "preserve" ? t("dns.review.records.preserve") : privateChoice === "clear" ? t("dns.review.records.clear") : <>{t("dns.review.records.replace")}<pre>{records}</pre></>}</dd>
    </dl>
    <p>{t("dns.review.impact")}</p>
  </section>;
}
