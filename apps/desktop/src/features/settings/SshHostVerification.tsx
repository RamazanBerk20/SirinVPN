import { SshVerificationGuide } from "./SshVerificationGuide";
import { Key, Warning } from "@phosphor-icons/react";
import { ConfirmationRow } from "../../components/ConfirmationRow";
import { HashValue } from "../../components/CopyValue";
import type { InspectedSshHost } from "../../hooks/useSshHostTrust";
import { t } from "../../i18n";

export function SshHostVerification({
  inspection,
  confirmed,
  onConfirmed,
}: {
  inspection: InspectedSshHost;
  confirmed: boolean;
  onConfirmed: (value: boolean) => void;
}) {
  const changed = inspection.status === "changed";
  return (
    <div className={`ssh-host-verification${changed ? " changed" : ""}`}>
      <div className="ssh-verification-heading">
        {changed ? <Warning size={24} weight="fill" /> : <Key size={24} weight="duotone" />}
        <h3>{changed ? t("ssh.verify.titleChanged") : t("ssh.verify.title")}</h3>
      </div>
      {/* A changed key may mean interception: the advice to stop comes first, not after the guide. */}
      {changed && (
        <div className="danger-note" role="alert">
          <Warning size={18} weight="fill" />
          <span>{t("ssh.verify.changedWarning")}</span>
        </div>
      )}
      <p>{changed ? t("ssh.verify.bodyChanged") : t("ssh.verify.body")}</p>
      <HashValue label={t("ssh.verify.fingerprintLabel", { host: `${inspection.host}:${inspection.port}` })} value={inspection.fingerprint} />
      <SshVerificationGuide />
      <ConfirmationRow checked={confirmed} onChange={onConfirmed} danger={changed}>
        <strong>{changed ? t("ssh.verify.confirmChanged") : t("ssh.verify.confirm")}</strong>
        <small>{changed ? t("ssh.verify.confirmChangedNote") : t("ssh.verify.confirmNote")}</small>
      </ConfirmationRow>
    </div>
  );
}
