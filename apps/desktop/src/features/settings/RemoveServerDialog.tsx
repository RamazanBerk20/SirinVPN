import { confirmAction } from "../../lib/confirmAction";
import { useSshOperation } from "../../hooks/useSshOperation";
import { SshLoginFields } from "./SshLoginFields";
import { DialogBack, DialogContent } from "../../components/DialogContent";
import { Busy, OperationProgress, stepsAt } from "../../components/OperationResult";
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
import { useId, useState } from "react";
import { api } from "../../api";
import type { InspectedSshHost } from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { type ServerProfile } from "../../types";
import { InlineError } from "../../components/ui";
import { OperationPlan, ServerChangeFailure } from "../../components/ServerChange";
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
  // Removing only from this device is chosen first; uninstalling is the SSH operation behind it.
  const [uninstalling, setUninstalling] = useState(false);
  const op = useSshOperation<null>(profile.endpoint.host, open, open && owner && uninstalling);
  const { login, trust, view } = op;
  const [removingLocal, setRemovingLocal] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const busy = op.busy || removingLocal;
  const step = !uninstalling ? "choice" : view;

  // The dialog stays mounted: each opening starts at the choice.
  const [wasOpen, setWasOpen] = useState(open);
  if (wasOpen !== open) {
    setWasOpen(open);
    if (!open) { setUninstalling(false); setLocalError(null); op.reset(); }
  }

  const changeOpen = (next: boolean) => {
    if (!next && busy) return;
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
    setRemovingLocal(true);
    setLocalError(null);
    try {
      await api.removeServer(profile.id);
      forgetReleaseSource(profile.id);
      await onRemoved();
      onOpenChange(false);
      // The dialog and the server's page are gone; say what happened.
      notify(t("vps.remove.local.done", { name: profile.name }));
    } catch (reason) {
      setLocalError(errorMessage(reason, t("vps.remove.local.error")));
    } finally {
      setRemovingLocal(false);
    }
  };

  const sshValid = login.valid;
  const blocker = login.missing ?? (step === "confirmHost" && !trust.confirmed ? t("ssh.verify.confirmFirst") : null);

  const inspect = async () => {
    if (!sshValid) return;
    await op.verify(t("vps.common.error.unreachable"), checked => uninstall(checked, true));
  };

  /** `checking`: called while the host check is still under way, which a cancelled confirmation ends. */
  const uninstall = async (checked: InspectedSshHost | null = trust.inspection, checking = false) => {
    if (!checked || !sshValid || (checked.status !== "trusted" && !trust.confirmed)) return;
    if (!await confirmAction({
      title: t("vps.remove.uninstall.confirmTitle", { host: profile.endpoint.host }),
      message: t("vps.remove.uninstall.confirmMessage"),
      confirm: t("vps.remove.uninstall.confirm"),
    })) {
      if (checking) op.back();
      return;
    }
    await op.run(async (credentials, setPhase) => {
      await api.uninstallServer({ server_id: profile.id, ...credentials });
      forgetReleaseSource(profile.id);
      setPhase(2);
      await onRemoved();
      onOpenChange(false);
      notify(t("vps.remove.uninstall.done", { host: profile.endpoint.host }));
      return null;
    }, t("vps.remove.uninstall.error"), { inspection: checked, onError: login.clearSecrets });
  };

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog"
          heading={t("vps.remove.title", { name: profile.name })}
          data-operation="uninstall" data-flow-state={uninstalling ? op.state.kind : "choice"}
          description={step === "running" ? t("vps.remove.description.running")
            : owner ? t("vps.remove.description.owner") : t("vps.remove.description.member")}
          closeDisabled={busy}
          footerNote={(step === "form" || step === "confirmHost") && !busy ? blocker : null}
          footer={step === "form" || step === "confirmHost" ? <>
            <DialogBack disabled={busy} onClick={() => { if (step === "form") setUninstalling(false); op.back(); }} />
            <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
            {step === "form"
              ? <button className="primary-button" type="submit" form={formId} disabled={!sshValid || busy}>{busy ? <Busy label={t("vps.common.checking")} /> : t("vps.remove.uninstall.review")}</button>
              : <button className="primary-button danger-action" type="button" disabled={!trust.confirmed || !sshValid || busy} onClick={() => void uninstall()}>{t("vps.remove.uninstall.action")}</button>}
          </> : null}>

          {step === "choice" ? (
            <div className="removal-choices">
              {localError ? <InlineError message={localError} /> : null}
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
                  <small>{removingLocal ? <Busy label={t("vps.remove.local.removing")} /> : t("vps.remove.local.summary")}</small>
                </div>
                <CaretRight className="mirror-rtl" size={16} />
              </button>
              {owner ? (
                <button
                  className="removal-choice destructive"
                  disabled={busy}
                  onClick={() => setUninstalling(true)}
                >
                  <span>
                    <Trash size={20} />
                  </span>
                  <div>
                    <strong>{t("vps.remove.uninstall.title")}</strong>
                    <small>{t("vps.remove.uninstall.summary")}</small>
                  </div>
                  <CaretRight className="mirror-rtl" size={16} />
                </button>
              ) : null}
            </div>
          ) : null}

          {step === "form" ? (
            <form
              className="uninstall-form"
              id={formId}
              onSubmit={(event) => {
                event.preventDefault();
                void inspect();
              }}
            >
              <ServerChangeFailure reason={op.failure} message={op.error} />
              <fieldset disabled={busy} className="ssh-operation-fields">
                <div className="uninstall-target">
                  <GlobeHemisphereWest size={16} />
                  <code>{profile.endpoint.host}</code>
                </div>
                <SshLoginFields login={login} />
              </fieldset>
            </form>
          ) : null}

          {step === "confirmHost" && trust.inspection ? (
            <div className="uninstall-fingerprint">
              <SshHostVerification
                inspection={trust.inspection}
                confirmed={trust.confirmed}
                onConfirmed={trust.setConfirmed}
              />
              {/* The consequence is on screen before the final button, not only in the confirmation. */}
              <div className="danger-note">
                <Warning size={18} weight="fill" />
                <span>{t("vps.remove.uninstall.confirmMessage")}</span>
              </div>
            </div>
          ) : null}

          {(step === "form" || step === "confirmHost") && sshValid && !busy
            ? <OperationPlan load={() => op.plan((credentials) => ({ operation: "uninstall", server_id: profile.id, ...credentials }))} /> : null}

          {step === "running" ? <OperationProgress title={t("vps.remove.uninstall.progress")}
            steps={stepsAt([t("vps.common.step.identity"), t("vps.remove.uninstall.step"), t("vps.remove.uninstall.stepLocal")], op.phase)} /> : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
