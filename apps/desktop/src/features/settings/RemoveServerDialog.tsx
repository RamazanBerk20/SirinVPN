import { confirmAction } from "../../lib/confirmAction";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { DialogBack, DialogContent } from "../../components/DialogContent";
import { Busy, OperationProgress } from "../../components/OperationResult";
import { notify } from "../../components/Toasts";
import { forgetReleaseSource } from "./vpsRelease";
import * as Dialog from "@radix-ui/react-dialog";
import {
  CaretRight,
  Desktop,
  GlobeHemisphereWest,
  Trash,
  Warning,
} from "@phosphor-icons/react";
import { useEffect, useId, useState } from "react";
import { api } from "../../api";
import {
  useSshHostTrust,
  type InspectedSshHost,
} from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { type ServerProfile } from "../../types";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";

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
  const formId = useId();
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
      !await confirmAction({
        title: t("vps.remove.local.confirmTitle", { name: profile.name }),
        message: owner ? t("vps.remove.local.confirmOwner") : t("vps.remove.local.confirmMember"),
        confirm: t("common.action.remove"),
      })
    )
      return;
    setBusy(true);
    setError(null);
    try {
      await api.removeServer(profile.id);
      forgetReleaseSource(profile.id);
      await onRemoved();
      onOpenChange(false);
      // The dialog and the server's page are gone; say what happened.
      notify(t("vps.remove.local.done", { name: profile.name }));
    } catch (reason) {
      setError(errorMessage(reason, t("vps.remove.local.error")));
    } finally {
      setBusy(false);
    }
  };

  const sshValid = login.valid;
  const blocker = login.missing ?? (step === "fingerprint" && !confirmed ? t("ssh.verify.confirmFirst") : null);

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
      setError(errorMessage(reason, t("vps.common.error.unreachable")));
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
      !await confirmAction({
        title: t("vps.remove.uninstall.confirmTitle", { host: profile.endpoint.host }),
        message: t("vps.remove.uninstall.confirmMessage"),
        confirm: t("vps.remove.uninstall.confirm"),
      })
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
      notify(t("vps.remove.uninstall.done", { host: profile.endpoint.host }));
    } catch (reason) {
      clearSecrets();
      setStep("details");
      setError(
        errorMessage(reason, t("vps.remove.uninstall.error")),
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
          heading={t("vps.remove.title", { name: profile.name })}
          description={step === "uninstalling" ? t("vps.remove.description.running")
            : owner ? t("vps.remove.description.owner") : t("vps.remove.description.member")}
          closeDisabled={busy || step === "uninstalling"}
          footerNote={(step === "details" || step === "fingerprint") && !busy ? blocker : null}
          footer={step === "details" || step === "fingerprint" ? <>
            <DialogBack disabled={busy} onClick={() => setStep(step === "details" ? "choice" : "details")} />
            <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
            {step === "details"
              ? <button className="primary-button" type="submit" form={formId} disabled={!sshValid || busy}>{busy ? <Busy label={t("vps.common.checking")} /> : t("vps.remove.uninstall.review")}</button>
              : <button className="primary-button danger-action" type="button" disabled={!confirmed || !sshValid || busy} onClick={() => void uninstall()}>{t("vps.remove.uninstall.action")}</button>}
          </> : null}>

          {step === "choice" ? (
            <div className="removal-choices">
              {error ? <InlineError message={error} /> : null}
              <button
                className="removal-choice"
                disabled={busy}
                onClick={() => void forgetLocal()}
              >
                <span>
                  <Desktop size={20} />
                </span>
                <div>
                  <strong>{t("vps.remove.local.title")}</strong>
                  <small>{t("vps.remove.local.summary")}</small>
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
                    <strong>{t("vps.remove.uninstall.title")}</strong>
                    <small>{t("vps.remove.uninstall.summary")}</small>
                  </div>
                  <CaretRight size={16} />
                </button>
              ) : null}
            </div>
          ) : null}

          {step === "details" ? (
            <form
              className="uninstall-form"
              id={formId}
              onSubmit={(event) => {
                event.preventDefault();
                void inspect();
              }}
            >
              {error ? <InlineError message={error} onRetry={() => void inspect()} retryDisabled={busy || !sshValid} /> : null}
              <fieldset disabled={busy} className="ssh-operation-fields">
                <div className="uninstall-target">
                  <GlobeHemisphereWest size={16} />
                  <code>{profile.endpoint.host}</code>
                </div>
                <SshLoginFields login={login} />
              </fieldset>
            </form>
          ) : null}

          {step === "fingerprint" && trust.inspection ? (
            <div className="uninstall-fingerprint">
              <SshHostVerification
                inspection={trust.inspection}
                confirmed={confirmed}
                onConfirmed={setConfirmed}
              />
              {/* The consequence is on screen before the final button, not only in the confirmation. */}
              <div className="danger-note">
                <Warning size={18} weight="fill" />
                <span>{t("vps.remove.uninstall.confirmMessage")}</span>
              </div>
            </div>
          ) : null}

          {step === "uninstalling" ? <OperationProgress title={t("vps.remove.uninstall.progress")} /> : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
