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
    } catch (reason) {
      setError(errorMessage(reason, t("vps.remove.local.error")));
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
          heading={<>{step === "uninstalling"
              ? t("vps.remove.titleRunning")
              : t("vps.remove.title", { name: profile.name })}</>}
          description={<>{owner
              ? t("vps.remove.description.owner")
              : t("vps.remove.description.member")}</>}
          closeDisabled={busy || step === "uninstalling"}>

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
                  {t("common.action.back")}
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
                  {busy ? t("vps.common.checking") : t("vps.remove.uninstall.review")}
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
                {t("common.action.back")}
              </button>
              <SshHostVerification
                inspection={trust.inspection}
                confirmed={confirmed}
                onConfirmed={setConfirmed}
              />
              <button
                className="primary-button danger-action"
                disabled={!confirmed || !sshValid || busy}
                onClick={() => void uninstall()}
              >
                {t("vps.remove.uninstall.action")}
              </button>
            </div>
          ) : null}

          {step === "uninstalling" ? (
            <div className="uninstall-progress">
              <ArrowClockwise className="spin" size={26} />
              <strong>{t("vps.remove.uninstall.progress")}</strong>
              <p>{t("vps.common.keepOpen")}</p>
            </div>
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
