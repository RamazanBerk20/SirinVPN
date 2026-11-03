import { HashValue } from "../../components/CopyValue";
import { OperationResult } from "../../components/OperationResult";
import { formatDnsPolicy } from "../../format";
import { t } from "../../i18n";
import type { RepairResult, ServerProfile } from "../../types";
import { ServerNetworkPreflight } from "./ServerNetworkPreflight";
import { SettingsDisclosure } from "./SettingsParts";

export function RepairSummary({ profile, result, dnsPreserved, recordsPreserved }: {
  profile: ServerProfile;
  result: RepairResult;
  dnsPreserved: boolean;
  recordsPreserved: boolean;
}) {
  const fingerprint = result.server_identity_fingerprint;
  const records = result.private_dns_records.length;
  return <div className="repair-result">
    <OperationResult title={t("vps.summary.title", { name: profile.name })} />
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
      {fingerprint ? <HashValue label={t("vps.summary.fingerprint")} value={fingerprint} />
        : <div className="result-identity"><span>{t("vps.summary.fingerprint")}</span><span className="settings-note">{t("vps.summary.fingerprintSaved")}</span></div>}
    </section>
    {result.network_preflight && <SettingsDisclosure className="result-disclosure" summary={t("vps.summary.network")}>
      <p className="settings-note">{t("vps.summary.networkNote")}</p>
      <ServerNetworkPreflight report={result.network_preflight} />
    </SettingsDisclosure>}
    <SettingsDisclosure className="result-disclosure" summary={t("vps.common.softwareDetails")}>
      <HashValue label={t("vps.common.softwareHash")} value={result.artifact_sha256} />
    </SettingsDisclosure>
    <p className="result-next-step">{t("vps.summary.next")}</p>
  </div>;
}
