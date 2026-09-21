import { SshVerificationGuide } from "./SshVerificationGuide";
import { Copy, Key, Warning } from "@phosphor-icons/react";
import type { InspectedSshHost } from "../../hooks/useSshHostTrust";

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
      <Key size={27} weight="duotone" />
      <h3>
        {changed ? "The VPS SSH key has changed" : "Verify this VPS once"}
      </h3>
      <div className="uninstall-target">
        <code>
          {inspection.host}:{inspection.port}
        </code>
      </div>
      <p>
        {changed
          ? "This key differs from the one you saved. Verify it before replacing the saved key."
          : "SirinVPN will remember this key for future VPS actions. Verify it using your hosting provider’s console:"}
      </p>
      <div className="fingerprint-value">
        <code>{inspection.fingerprint}</code>
        <button
          className="icon-button"
          aria-label="Copy fingerprint"
          onClick={() =>
            void navigator.clipboard.writeText(inspection.fingerprint)
          }
        >
          <Copy size={17} />
        </button>
      </div>
      <SshVerificationGuide />
      {changed && (
        <div className="warning-note replacement-warning">
          <Warning size={18} weight="fill" />
          <span>
            If you did not rebuild this VPS or change its SSH keys, stop and
            check with your hosting provider.
          </span>
        </div>
      )}
      <label className={`replacement-option ${confirmed ? "selected" : ""}`}>
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(event) => onConfirmed(event.target.checked)}
        />
        <span>
          <strong>
            {changed
              ? "I verified the new SSH key"
              : "I verified this VPS fingerprint"}
          </strong>
          <small>
            {changed
              ? "Replace the saved key for this address and port."
              : "Remember this key. Ask again only if it changes."}
          </small>
        </span>
      </label>
    </>
  );
}
