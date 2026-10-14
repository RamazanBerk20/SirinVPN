import { Check } from "@phosphor-icons/react";
import { CopyValue } from "../../components/CopyValue";
import { formatDnsPolicy } from "../../format";
import { t } from "../../i18n";
import type { RepairResult, ServerProfile } from "../../types";
import { ServerNetworkPreflight } from "./ServerNetworkPreflight";

export function RepairSummary({ profile, result, dnsPreserved, recordsPreserved }: {
  profile: ServerProfile;
  result: RepairResult;
  dnsPreserved: boolean;
  recordsPreserved: boolean;
}) {
  const fingerprint = result.server_identity_fingerprint;
  const records = result.private_dns_records.length;
  return <div className="repair-result">
    <div className="repair-result-heading">
      <span className="result-check"><Check size={26} weight="bold" /></span>
      <h3>{t("vps.summary.title", { name: profile.name })}</h3>
    </div>
    <section className="result-section" aria-labelledby="repair-completed-heading">
      <h3 id="repair-completed-heading">{t("vps.summary.completed")}</h3>
      <dl className="result-facts">
        <div><dt>{t("vps.summary.software")}</dt><dd>{t("vps.summary.softwareValue")}</dd></div>
        <div><dt>{t("vps.summary.services")}</dt><dd>{t("vps.summary.servicesValue")}</dd></div>
        <div><dt>{t("vps.summary.dns")}</dt><dd>{t("vps.summary.dnsValue", { policy: formatDnsPolicy(result.dns_upstream) })}</dd></div>
        <div><dt>{t("vps.summary.records")}</dt><dd>{records === 0 ? t("vps.summary.recordsNone") : t("vps.summary.recordsValue", { count: records })}</dd></div>
      </dl>
    </section>
    <section className="result-section" aria-labelledby="repair-preserved-heading">
      <h3 id="repair-preserved-heading">{t("vps.summary.preserved")}</h3>
      <ul className="result-list">
        <li>{t("vps.summary.identities")}</li>
        {dnsPreserved && <li>{t("vps.summary.dnsPolicy")}</li>}
        {recordsPreserved && <li>{t("vps.summary.dnsRecords")}</li>}
      </ul>
      <div className="result-identity">
        <span>{t("vps.summary.fingerprint")}</span>
        {fingerprint ? <CopyValue value={fingerprint} label={t("vps.summary.fingerprint")} shorten showCopyLabel />
          : <span className="settings-note">{t("vps.summary.fingerprintSaved")}</span>}
      </div>
    </section>
    {result.network_preflight && <details className="result-disclosure">
      <summary>{t("vps.summary.network")}</summary>
      <p className="settings-note">{t("vps.summary.networkNote")}</p>
      <ServerNetworkPreflight report={result.network_preflight} />
    </details>}
    <details className="result-disclosure">
      <summary>{t("vps.common.softwareDetails")}</summary>
      <div className="result-identity"><span>{t("vps.common.softwareHash")}</span>
        <CopyValue value={result.artifact_sha256} label={t("vps.common.softwareHash")} shorten showCopyLabel />
      </div>
    </details>
    <p className="result-next-step">{t("vps.summary.next")}</p>
  </div>;
}
