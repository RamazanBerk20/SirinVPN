import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowClockwise,
  CaretRight,
  Check,
  DownloadSimple,
  GlobeHemisphereWest,
  Key,
  LockKey,
  ShieldCheck,
  Warning,
} from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { api } from "../../api";
import { type EndpointUpdateCodeResult, type ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { CopyButton } from "../../components/CopyButton";
import { t } from "../../i18n";

/** Shape of a signed update code; a format sample, not translatable text. */
const CODE_PLACEHOLDER = "sirm1.…";

export function EndpointUpdateDialog({
  profile,
  open,
  onOpenChange,
  connected,
  onCompleted,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  connected: boolean;
  onCompleted: () => Promise<void>;
}) {
  const owner = profile.role === "owner";
  const [mode, setMode] = useState<"share" | "apply">(
    owner && profile.pending_previous_endpoint ? "share" : "apply",
  );
  const [update, setUpdate] = useState<EndpointUpdateCodeResult | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [published, setPublished] = useState(false);
  const [applied, setApplied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setMode(owner && profile.pending_previous_endpoint ? "share" : "apply");
      setUpdate(null);
      setCode("");
      setBusy(false);
      setPublished(false);
      setApplied(false);
      setError(null);
    }
  }, [open, owner, profile.pending_previous_endpoint]);

  const changeOpen = (next: boolean) => {
    if (!next && busy) return;
    onOpenChange(next);
  };

  const createOrRetrieve = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.createEndpointUpdate(profile.id);
      setUpdate(result);
      setCode(result.code);
      await onCompleted();
    } catch (reason) {
      setError(
        errorMessage(reason, t("vps.endpoint.error.create")),
      );
    } finally {
      setBusy(false);
    }
  };

  const checkCurrent = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.availableEndpointUpdate(profile.id);
      if (!result)
        throw new Error(t("vps.endpoint.error.none"));
      setUpdate(result);
      setCode(result.code);
    } catch (reason) {
      setError(
        errorMessage(reason, t("vps.endpoint.error.retrieve")),
      );
    } finally {
      setBusy(false);
    }
  };

  const publish = async () => {
    // Publish exactly the signed code shown in this tab, not the apply tab's draft.
    if (!update?.code.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.publishEndpointUpdate(profile.id, update.code.trim());
      setPublished(true);
      await onCompleted();
    } catch (reason) {
      setError(
        errorMessage(reason, t("vps.endpoint.error.publish")),
      );
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    if (!code.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.applyEndpointUpdate(profile.id, code.trim());
      setApplied(true);
      await onCompleted();
    } catch (reason) {
      setError(
        errorMessage(reason, t("vps.endpoint.error.apply")),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content invitation-dialog endpoint-update-dialog"
          heading={<>{mode === "share"
              ? t("vps.endpoint.titleShare")
              : t("vps.endpoint.titleApply")}</>}
          description={<>{t("vps.endpoint.description")}</>}
          closeDisabled={busy}>

          {owner ? (
            <div className="segmented-control endpoint-update-tabs">
              <button
                type="button"
                aria-pressed={mode === "share"}
                onClick={() => setMode("share")}
              >
                {t("vps.endpoint.tab.share")}
              </button>
              <button
                type="button"
                aria-pressed={mode === "apply"}
                onClick={() => setMode("apply")}
              >
                {t("vps.endpoint.tab.apply")}
              </button>
            </div>
          ) : null}

          {mode === "share" ? (
            <div className="endpoint-update-flow">
              {profile.pending_previous_endpoint ? (
                <div className="warning-note replacement-warning">
                  <Warning size={18} weight="fill" />
                  <span>
                    {t("vps.endpoint.pending", { host: profile.pending_previous_endpoint.host })}
                  </span>
                </div>
              ) : null}
              {!update ? (
                <div className="endpoint-update-intro">
                  <GlobeHemisphereWest size={28} weight="duotone" />
                  <h3>
                    {profile.pending_previous_endpoint
                      ? t("vps.endpoint.create.title")
                      : t("vps.endpoint.retrieve.title")}
                  </h3>
                  <p>{t("vps.endpoint.intro")}</p>
                  <button
                    className="primary-button"
                    disabled={!connected || busy}
                    onClick={() => void createOrRetrieve()}
                  >
                    {busy ? (
                      <ArrowClockwise className="spin" size={18} />
                    ) : (
                      <Key size={18} />
                    )}
                    {profile.pending_previous_endpoint
                      ? t("vps.endpoint.create.action")
                      : t("vps.endpoint.retrieve.action")}
                  </button>
                  {!connected ? (
                    <small>{t("vps.endpoint.connectFirst")}</small>
                  ) : null}
                </div>
              ) : (
                <>
                  <div className="endpoint-transition-summary">
                    <code>
                      {endpointLabel(update.previous_endpoint)}
                    </code>
                    <CaretRight size={18} />
                    <code>
                      {endpointLabel(update.endpoint)}
                    </code>
                    <span>{t("vps.endpoint.number", { number: update.generation })}</span>
                  </div>
                  <Field
                    label={t("vps.endpoint.code")}
                    hint={t("vps.endpoint.codeHint")}
                  >
                    <textarea
                      className="secret-code-output mono"
                      value={update.code}
                      readOnly
                      aria-label={t("vps.endpoint.code")}
                    />
                  </Field>
                  <div className="dialog-actions">
                    <CopyButton className="secondary-button" value={update.code}>
                      {" "}{t("vps.endpoint.copy")}
                    </CopyButton>
                    <button
                      className="primary-button"
                      disabled={busy || published}
                      onClick={() => void publish()}
                    >
                      {busy ? (
                        <ArrowClockwise className="spin" size={18} />
                      ) : (
                        <GlobeHemisphereWest size={18} />
                      )}
                      {published
                        ? t("vps.endpoint.published")
                        : t("vps.endpoint.publish")}
                    </button>
                  </div>
                  <p className="form-footnote">
                    <LockKey size={15} /> {t("vps.endpoint.publishNote")}
                  </p>
                </>
              )}
              {error ? <InlineError message={error} /> : null}
            </div>
          ) : (
            <div className="endpoint-update-flow">
              {applied ? (
                <div className="backup-success endpoint-update-success">
                  <span>
                    <Check size={26} weight="bold" />
                  </span>
                  <h3>{t("vps.endpoint.applied")}</h3>
                  <p>{t("vps.endpoint.appliedNote")}</p>
                  <button
                    className="primary-button"
                    onClick={() => changeOpen(false)}
                  >
                    {t("common.action.done")}
                  </button>
                </div>
              ) : (
                <>
                  <p>{t("vps.endpoint.applyIntro")}</p>
                  <Field label={t("vps.endpoint.code")}>
                    <textarea
                      className="secret-code-output mono"
                      value={code}
                      onChange={(event) => setCode(event.target.value)}
                      placeholder={CODE_PLACEHOLDER}
                      spellCheck={false}
                    />
                  </Field>
                  {update && update.code.trim() === code.trim() ? (
                    <div className="endpoint-transition-summary">
                      <code>
                        {endpointLabel(update.previous_endpoint)}
                      </code>
                      <CaretRight size={18} />
                      <code>
                        {endpointLabel(update.endpoint)}
                      </code>
                      <span>{t("vps.endpoint.number", { number: update.generation })}</span>
                    </div>
                  ) : null}
                  {error ? <InlineError message={error} /> : null}
                  <div className="dialog-actions">
                    <button
                      className="secondary-button"
                      disabled={!connected || busy}
                      onClick={() => void checkCurrent()}
                    >
                      <DownloadSimple size={17} /> {t("vps.endpoint.getFromServer")}
                    </button>
                    <button
                      className="primary-button"
                      disabled={!code.trim() || busy}
                      onClick={() => void apply()}
                    >
                      {busy ? (
                        <ArrowClockwise className="spin" size={18} />
                      ) : (
                        <ShieldCheck size={18} />
                      )}
                      {t("vps.endpoint.verify")}
                    </button>
                  </div>
                  <p className="form-footnote">
                    <ShieldCheck size={15} /> {t("vps.endpoint.identityNote")}
                  </p>
                </>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function endpointLabel(endpoint: { host: string; wireguard_port: number }) {
  return `${endpoint.host.includes(":") ? `[${endpoint.host}]` : endpoint.host}:${endpoint.wireguard_port}`;
}
