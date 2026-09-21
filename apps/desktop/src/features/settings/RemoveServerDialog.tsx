import { confirmAction } from "../../lib/confirmAction";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { DialogContent } from "../../components/DialogContent";
import { forgetReleaseSource } from "./vpsRelease";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowClockwise,
  CaretRight,
  Desktop,
  GlobeHemisphereWest,
  Trash,
} from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { api } from "../../api";
import {
  useSshHostTrust,
  type InspectedSshHost,
} from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { type ServerProfile } from "../../types";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";

export function RemoveServerDialog({
  profile,
  open,
  onOpenChange,
  onRemoved,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onRemoved: () => Promise<void>;
}) {
  const owner = profile.role === "owner";
  const [step, setStep] = useState<
    "choice" | "details" | "fingerprint" | "uninstalling"
  >("choice");
  const login = useSshLogin(
    profile.endpoint.host,
    open && owner && step !== "choice",
  );
  const { port } = login;
  const trust = useSshHostTrust(profile.endpoint.host, Number(port), open);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearSecrets = () => {
    login.clearSecrets();
  };

  useEffect(() => {
    if (!open) {
      clearSecrets();
      setStep("choice");
      trust.reset();
      setError(null);
      setBusy(false);
    }
  }, [open]);

  const changeOpen = (next: boolean) => {
    if (!next && (busy || step === "uninstalling")) return;
    onOpenChange(next);
  };

  const forgetLocal = async () => {
    if (
      !await confirmAction(
        owner
          ? `Remove ${profile.name} only from this device? Its Owner key will be deleted, but the VPS remains installed and claimed.`
          : `Remove ${profile.name} and this device key locally? The Owner's VPS installation remains unchanged.`,
      )
    )
      return;
    setBusy(true);
    setError(null);
    try {
      await api.removeServer(profile.id);
      forgetReleaseSource(profile.id);
      await onRemoved();
      onOpenChange(false);
    } catch (reason) {
      setError(errorMessage(reason, "The local profile could not be removed."));
    } finally {
      setBusy(false);
    }
  };

  const sshValid = login.valid;

  const inspect = async () => {
    if (!sshValid) return;
    setBusy(true);
    setError(null);
    try {
      const checked = await trust.inspect();
      if (!checked) return;
      setConfirmed(false);
      if (checked.status === "trusted") {
        await uninstall(checked);
      } else {
        setStep("fingerprint");
      }
    } catch (reason) {
      setError(errorMessage(reason, "The VPS could not be reached over SSH."));
    } finally {
      setBusy(false);
    }
  };

  const uninstall = async (
    checked: InspectedSshHost | null = trust.inspection,
  ) => {
    if (!checked || !sshValid || (checked.status !== "trusted" && !confirmed))
      return;
    if (
      !await confirmAction(
        `Permanently uninstall SirinVPN from ${profile.endpoint.host}? All SirinVPN devices and invitations for this VPS will stop working. Docker and unrelated VPS services are preserved.`,
      )
    )
      return;
    setStep("uninstalling");
    setBusy(true);
    setError(null);
    try {
      const fingerprint = await trust.accept(checked, confirmed);
      await api.uninstallServer({
        server_id: profile.id,
        ...(await login.prepare(fingerprint)),
      });
      forgetReleaseSource(profile.id);
      clearSecrets();
      await onRemoved();
      onOpenChange(false);
    } catch (reason) {
      clearSecrets();
      setStep("details");
      setError(
        errorMessage(
          reason,
          "Uninstall did not complete. No local profile was intentionally removed; any interrupted VPS teardown is protected by rollback.",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog"
          heading={<>{step === "uninstalling"
              ? "Removing SirinVPN"
              : `Remove ${profile.name}`}</>}
          description={<>{owner
              ? "Choose whether to forget this Owner device or cleanly uninstall SirinVPN from the VPS."
              : "Admins and Members can remove only their own local profile and device key."}</>}
          closeDisabled={busy || step === "uninstalling"} closeLabel="Close">

          {step === "choice" ? (
            <div className="removal-choices">
              <button
                className="removal-choice"
                disabled={busy}
                onClick={() => void forgetLocal()}
              >
                <span>
                  <Desktop size={20} />
                </span>
                <div>
                  <strong>Remove from this device</strong>
                  <small>
                    Delete this local profile and device key. The VPS stays
                    installed.
                  </small>
                </div>
                <CaretRight size={16} />
              </button>
              {owner ? (
                <button
                  className="removal-choice destructive"
                  disabled={busy}
                  onClick={() => setStep("details")}
                >
                  <span>
                    <Trash size={20} />
                  </span>
                  <div>
                    <strong>Uninstall from VPS</strong>
                    <small>
                      Verify privileged SSH, remove SirinVPN-owned state, then
                      delete this local profile.
                    </small>
                  </div>
                  <CaretRight size={16} />
                </button>
              ) : null}
              {error ? <InlineError message={error} /> : null}
            </div>
          ) : null}

          {step === "details" ? (
            <form
              className="uninstall-form"
              onSubmit={(event) => {
                event.preventDefault();
                void inspect();
              }}
            >
              <fieldset disabled={busy} className="ssh-operation-fields">
                <button
                  type="button"
                  className="back-button"
                  onClick={() => setStep("choice")}
                >
                  Back
                </button>
                <div className="uninstall-target">
                  <GlobeHemisphereWest size={16} />
                  <code>{profile.endpoint.host}</code>
                </div>
                <SshLoginFields login={login} />
                {error ? <InlineError message={error} /> : null}
                <button
                  className="primary-button"
                  type="submit"
                  disabled={!sshValid || busy}
                >
                  {busy ? "Checking VPS" : "Review uninstall"}
                </button>
              </fieldset>
            </form>
          ) : null}

          {step === "fingerprint" && trust.inspection ? (
            <div className="uninstall-fingerprint">
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
                className="primary-button danger-action"
                disabled={!confirmed || busy}
                onClick={() => void uninstall()}
              >
                Uninstall SirinVPN
              </button>
            </div>
          ) : null}

          {step === "uninstalling" ? (
            <div className="uninstall-progress">
              <ArrowClockwise className="spin" size={26} />
              <strong>Cleaning SirinVPN-owned state</strong>
              <p>
                Keep the app open. A five-minute server rollback guard protects
                interruption.
              </p>
            </div>
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
