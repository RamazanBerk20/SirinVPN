import { SshVerificationGuide } from "./SshVerificationGuide";
import { Key, Warning } from "@phosphor-icons/react";
import { CopyButton } from "../../components/CopyButton";
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
    <>
      {changed ? <Warning size={27} weight="fill" className="danger-icon" /> : <Key size={27} weight="duotone" />}
      <h3>
        {changed ? t("ssh.verify.titleChanged") : t("ssh.verify.title")}
      </h3>
      {/* A changed key may mean interception: the advice to stop comes first, not after the guide. */}
      {changed && (
        <div className="warning-note replacement-warning">
          <Warning size={18} weight="fill" />
          <span>{t("ssh.verify.changedWarning")}</span>
        </div>
      )}
      <div className="uninstall-target">
        <code>
          {inspection.host}:{inspection.port}
        </code>
      </div>
      <p>
        {changed ? t("ssh.verify.bodyChanged") : t("ssh.verify.body")}
      </p>
      <div className="fingerprint-value">
        <code>{inspection.fingerprint}</code>
        <CopyButton value={inspection.fingerprint} label={t("ssh.verify.copyFingerprint")} />
      </div>
      <SshVerificationGuide />
      <label className={`replacement-option ${confirmed ? "selected" : ""}`}>
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(event) => onConfirmed(event.target.checked)}
        />
        <span>
          <strong>
            {changed ? t("ssh.verify.confirmChanged") : t("ssh.verify.confirm")}
          </strong>
          <small>
            {changed ? t("ssh.verify.confirmChangedNote") : t("ssh.verify.confirmNote")}
          </small>
        </span>
      </label>
    </>
  );
}
