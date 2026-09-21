import { SecretInput } from "../../components/SecretInput";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { ServerNetworkPreflight } from "./ServerNetworkPreflight";
import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import { open } from "../../lib/nativeDialog";
import {
  ArrowClockwise,
  Check,
  UploadSimple,
  Warning,
} from "@phosphor-icons/react";
import { useState } from "react";
import { api } from "../../api";
import {
  useSshHostTrust,
  type InspectedSshHost,
} from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { validateHost } from "../../format";
import { type ServerProfile, type ServerRestoreResult } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";

export function VpsRestoreDialog({
  profile,
  open: dialogOpen,
  onOpenChange,
  disconnected,
  onCompleted,
  onReviewAccess,
  onMoveDevices,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  disconnected: boolean;
  onCompleted: () => Promise<void>;
  onReviewAccess?: () => void;
  onMoveDevices?: () => void;
}) {
  const [step, setStep] = useState<
    "details" | "fingerprint" | "restoring" | "success"
  >("details");
  const [host, setHost] = useState(profile.endpoint.host);
  const login = useSshLogin(host, dialogOpen);
  const { port } = login;
  const [path, setPath] = useState("");
  const [backupPassword, setBackupPassword] = useState("");
  const trust = useSshHostTrust(host.trim(), Number(port), dialogOpen);
  const [replaceExisting, setReplaceExisting] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [result, setResult] = useState<ServerRestoreResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearSecrets = () => {
    login.clearSecrets();
    setBackupPassword("");
  };

  const reset = () => {
    clearSecrets();
    setStep("details");
    setHost(profile.endpoint.host);
    setPath("");
    trust.reset();
    setReplaceExisting(false);
    setConfirmed(false);
    setResult(null);
    setBusy(false);
    setError(null);
  };

  const changeOpen = (next: boolean) => {
    if (!next && (busy || step === "restoring")) return;
    onOpenChange(next);
    if (!next) reset();
  };

  const valid =
    disconnected &&
    path.length > 0 &&
    [...backupPassword].length >= 12 &&
    validateHost(host) &&
    login.valid;

  const chooseSource = async () => {
    try {
      const selected = await open({
        title: "Open encrypted SirinVPN VPS backup",
        multiple: false,
        directory: false,
        filters: [
          {
            name: "SirinVPN encrypted VPS backup",
            extensions: ["sirinvpn-server-backup"],
          },
        ],
      });
      if (typeof selected === "string") {
        setPath(selected);
        setError(null);
      }
    } catch (reason) {
      setError(
        errorMessage(reason, "The VPS backup picker could not be opened."),
      );
    }
  };

  const inspect = async () => {
    if (!valid) return;
    setBusy(true);
    setError(null);
    try {
      const checked = await trust.inspect();
      if (!checked) return;
      setConfirmed(false);
      if (checked.status === "trusted") {
        await restore(checked);
      } else {
        setStep("fingerprint");
      }
    } catch (reason) {
      setError(
        errorMessage(
          reason,
          "The destination VPS could not be reached over SSH.",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  const restore = async (
    checked: InspectedSshHost | null = trust.inspection,
  ) => {
    if (!checked || !valid || (checked.status !== "trusted" && !confirmed))
      return;
    setStep("restoring");
    setBusy(true);
    setError(null);
    try {
      const fingerprint = await trust.accept(checked, confirmed);
      const completed = await api.restoreVpsBackup({
        server_id: profile.id,
        path,
        backup_password: backupPassword,
        host: host.trim(),
        ...(await login.prepare(fingerprint)),
        replace_existing: replaceExisting,
        confirmed: true,
      });
      clearSecrets();
      setResult(completed);
      await onCompleted();
      setStep("success");
    } catch (reason) {
      clearSecrets();
      setConfirmed(false);
      setStep("details");
      setError(
        errorMessage(
          reason,
          "Restore stopped safely. The destination rollback guard restores its previous SirinVPN state, and this device keeps its previous endpoint.",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={dialogOpen} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog repair-server-dialog vps-restore-dialog"
          heading={<>{step === "restoring"
              ? "Restoring VPS state"
              : step === "success"
                ? "VPS restore complete"
                : `Restore ${profile.name}`}</>}
          description={<>Authenticate an encrypted VPS backup locally, then restore the same
            server identity onto a pinned SSH destination.</>}
          closeDisabled={busy || step === "restoring"} closeLabel="Close">

          {step === "details" ? (
            <form
              className="uninstall-form"
              onSubmit={(event) => {
                event.preventDefault();
                void inspect();
              }}
            >
              <fieldset disabled={busy} className="ssh-operation-fields">
                <div className="sensitive-backup-warning">
                  <Warning size={19} weight="fill" />
                  <p>
                    <strong>
                      A stale backup can restore access you revoked later.
                    </strong>{" "}
                    Review members and devices after recovery. The encrypted
                    file must belong to this local Owner profile.
                  </p>
                </div>
                {!disconnected ? (
                  <InlineError message="Disconnect every active SirinVPN tunnel before restoring a VPS." />
                ) : null}
                <Field
                  label="Encrypted VPS backup"
                  hint="The file is authenticated and version-checked locally before SSH changes begin."
                >
                  <div className="file-picker-row">
                    <input
                      className="mono"
                      value={path}
                      readOnly
                      placeholder="Choose a .sirinvpn-server-backup file"
                    />
                    <button
                      className="secondary-button"
                      type="button"
                      onClick={() => void chooseSource()}
                      disabled={busy}
                    >
                      Choose file
                    </button>
                  </div>
                </Field>
                <Field label="Backup password">
                  <SecretInput
                    type="password"
                    value={backupPassword}
                    onChange={(event) => setBackupPassword(event.target.value)}
                    autoComplete="off"
                  />
                </Field>
                <Field
                  label="Destination IP address or hostname"
                  hint="Use the current host for disaster recovery, or a new host for migration."
                >
                  <input
                    value={host}
                    onChange={(event) => setHost(event.target.value)}
                    autoCapitalize="none"
                    spellCheck={false}
                  />
                </Field>
                <SshLoginFields login={login} />
                <label
                  className={`replacement-option ${replaceExisting ? "selected" : ""}`}
                >
                  <input
                    type="checkbox"
                    checked={replaceExisting}
                    onChange={(event) =>
                      setReplaceExisting(event.target.checked)
                    }
                  />
                  <span>
                    <strong>
                      Replace destination SirinVPN state if occupied
                    </strong>
                    <small>
                      Only SirinVPN-owned state is replaced, after a five-minute
                      rollback guard is armed. Unrelated VPS services are
                      preserved.
                    </small>
                  </span>
                </label>
                {error ? <InlineError message={error} /> : null}
                <button
                  className="primary-button"
                  type="submit"
                  disabled={!valid || busy}
                >
                  {busy ? "Checking destination" : "Restore VPS"}
                </button>
              </fieldset>
            </form>
          ) : null}

          {step === "fingerprint" && trust.inspection ? (
            <div className="uninstall-fingerprint repair-fingerprint">
              <button
                className="back-button"
                onClick={() => setStep("details")}
              >
                Back
              </button>
              <SshHostVerification
                inspection={trust.inspection}
                confirmed={confirmed}
                onConfirmed={setConfirmed}
              />
              <button
                className="primary-button"
                disabled={!confirmed || busy}
                onClick={() => void restore()}
              >
                <UploadSimple size={18} /> Restore VPS
              </button>
            </div>
          ) : null}

          {step === "restoring" ? (
            <div className="uninstall-progress repair-progress">
              <ArrowClockwise className="spin" size={26} />
              <strong>Applying a guarded identity restore</strong>
              <p>
                Keep the app open. SirinVPN verifies keys, authorization,
                networking, DNS, services, SSH reachability, and the installed
                artifact before committing the new local endpoint.
              </p>
            </div>
          ) : null}

          {step === "success" && result ? (
            <div className="backup-success repair-success">
              <span>
                <Check size={26} weight="bold" />
              </span>
              <h3>Server identity restored</h3>
              <p>
                This Owner device now points to {result.profile.endpoint.host}.
                Connect it, then open Move devices to a new VPS address to create and distribute the
                signed endpoint handoff before retiring the old VPS.
              </p>
              {onReviewAccess && <button className="secondary-button" onClick={() => { changeOpen(false); onReviewAccess(); }}>Review members and devices</button>}
              {onMoveDevices && <button className="secondary-button" onClick={() => { changeOpen(false); onMoveDevices(); }}>Move devices to a new VPS address</button>}
              <code>{result.artifact_sha256}</code>
              {result.network_preflight && <ServerNetworkPreflight report={result.network_preflight} />}
              <button
                className="primary-button"
                onClick={() => changeOpen(false)}
              >
                Done
              </button>
            </div>
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
