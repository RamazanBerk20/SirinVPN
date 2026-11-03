import { DialogContent } from "../../components/DialogContent";
import { Busy, OperationResult } from "../../components/OperationResult";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowRight,
  GlobeHemisphereWest,
  Info,
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

type Task = null | "create" | "retrieve" | "publish" | "apply";

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
  const [busy, setBusy] = useState<Task>(null);
  const [published, setPublished] = useState(false);
  const [applied, setApplied] = useState(false);
  // No Try again: each action's own button stays on screen and is the retry.
  const [error, setError] = useState<{ message: string } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setMode(owner && profile.pending_previous_endpoint ? "share" : "apply");
      setUpdate(null);
      setCode("");
      setBusy(null);
      setPublished(false);
      setApplied(false);
      setError(null);
      setNotice(null);
    }
  }, [open, owner, profile.pending_previous_endpoint]);

  const changeOpen = (next: boolean) => {
    if (!next && busy) return;
    onOpenChange(next);
  };

  const run = async (kind: Exclude<Task, null>, action: () => Promise<void>, fallback: string) => {
    setBusy(kind);
    setError(null);
    setNotice(null);
    try {
      await action();
    } catch (reason) {
      setError({ message: errorMessage(reason, fallback) });
    } finally {
      setBusy(null);
    }
  };

  const createOrRetrieve = () => run("create", async () => {
    const result = await api.createEndpointUpdate(profile.id);
    setUpdate(result);
    setCode(result.code);
    await onCompleted();
  }, t("vps.endpoint.error.create"));

  const checkCurrent = () => run("retrieve", async () => {
    const result = await api.availableEndpointUpdate(profile.id);
    // No update waiting is an answer, not a failure.
    if (!result) { setNotice(t("vps.endpoint.none")); return; }
    setUpdate(result);
    setCode(result.code);
  }, t("vps.endpoint.error.retrieve"));

  // Publish exactly the signed code shown in this tab, not the apply tab's draft.
  const publish = () => update?.code.trim() ? run("publish", async () => {
    await api.publishEndpointUpdate(profile.id, update.code.trim());
    setPublished(true);
    await onCompleted();
  }, t("vps.endpoint.error.publish")) : Promise.resolve();

  const apply = () => code.trim() ? run("apply", async () => {
    await api.applyEndpointUpdate(profile.id, code.trim());
    setApplied(true);
    await onCompleted();
  }, t("vps.endpoint.error.apply")) : Promise.resolve();

  const transition = (value: EndpointUpdateCodeResult) => <div className="endpoint-transition-summary">
    <code>{endpointLabel(value.previous_endpoint)}</code>
    <ArrowRight size={18} aria-label={t("vps.endpoint.to")} />
    <code>{endpointLabel(value.endpoint)}</code>
    <span>{t("vps.endpoint.number", { number: value.generation })}</span>
  </div>;

  const failure = error && <InlineError message={error.message} />;
  const footer = mode === "share"
    ? !update
      ? <button className="primary-button" type="button" disabled={!connected || Boolean(busy)} onClick={() => void createOrRetrieve()}>
          {busy === "create" ? <Busy label={t("vps.endpoint.working")} /> : profile.pending_previous_endpoint ? t("vps.endpoint.create.action") : t("vps.endpoint.retrieve.action")}
        </button>
      : <>
          <CopyButton className="secondary-button" value={update.code}>{" "}{t("vps.endpoint.copy")}</CopyButton>
          {published
            ? <button className="primary-button" type="button" onClick={() => changeOpen(false)}>{t("common.action.done")}</button>
            : <button className="primary-button" type="button" disabled={Boolean(busy)} onClick={() => void publish()}>
                {busy === "publish" ? <Busy label={t("vps.endpoint.publishing")} /> : <><GlobeHemisphereWest size={18} />{t("vps.endpoint.publish")}</>}
              </button>}
        </>
    : applied
      ? <button className="primary-button" type="button" onClick={() => changeOpen(false)}>{t("common.action.done")}</button>
      : <>
          <button className="secondary-button" type="button" disabled={!connected || Boolean(busy)} onClick={() => void checkCurrent()}>
            {busy === "retrieve" ? <Busy label={t("vps.endpoint.working")} /> : t("vps.endpoint.getFromServer")}
          </button>
          <button className="primary-button" type="button" disabled={!code.trim() || Boolean(busy)} onClick={() => void apply()}>
            {busy === "apply" ? <Busy label={t("vps.endpoint.applying")} /> : <><ShieldCheck size={18} />{t("vps.endpoint.verify")}</>}
          </button>
        </>;
  const footerNote = busy ? null
    : mode === "share" ? (!update && !connected ? t("vps.endpoint.connectFirst") : null)
    : applied ? null : !code.trim() ? t("vps.endpoint.pasteFirst") : null;

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content invitation-dialog endpoint-update-dialog"
          heading={owner ? t("vps.endpoint.titleShare") : t("vps.endpoint.titleApply")}
          description={t("vps.endpoint.description")}
          closeDisabled={Boolean(busy)}
          footerNote={footerNote}
          footer={footer}>

          {owner ? (
            <div className="segmented-control endpoint-update-tabs" role="group" aria-label={t("vps.endpoint.tab.label")}>
              <button
                type="button"
                aria-pressed={mode === "share"}
                disabled={Boolean(busy)}
                onClick={() => { setMode("share"); setError(null); setNotice(null); }}
              >
                {t("vps.endpoint.tab.share")}
              </button>
              <button
                type="button"
                aria-pressed={mode === "apply"}
                disabled={Boolean(busy)}
                onClick={() => { setMode("apply"); setError(null); setNotice(null); }}
              >
                {t("vps.endpoint.tab.apply")}
              </button>
            </div>
          ) : null}

          {mode === "share" ? (
            <div className="endpoint-update-flow">
              {failure}
              {profile.pending_previous_endpoint ? (
                <div className="warning-note replacement-warning">
                  <Warning size={18} weight="fill" />
                  <span>
                    {t("vps.endpoint.pending", { host: profile.pending_previous_endpoint.host })}
                  </span>
                </div>
              ) : null}
              {published && update ? (
                <OperationResult title={t("vps.endpoint.published")}>
                  <p>{t("vps.endpoint.publishNote")}</p>
                </OperationResult>
              ) : !update ? (
                <div className="endpoint-update-intro">
                  <GlobeHemisphereWest size={28} weight="duotone" />
                  <h3>
                    {profile.pending_previous_endpoint
                      ? t("vps.endpoint.create.title")
                      : t("vps.endpoint.retrieve.title")}
                  </h3>
                  <p>{t("vps.endpoint.intro")}</p>
                </div>
              ) : (
                <>
                  {transition(update)}
                  {/* Copy is in the footer; the code itself is rarely read, so it stays folded. */}
                  <details className="result-disclosure endpoint-code">
                    <summary>{t("vps.endpoint.showCode")}</summary>
                    <Field label={t("vps.endpoint.code")} hint={t("vps.endpoint.codeHint")}>
                      <textarea className="secret-code-output mono" value={update.code} readOnly aria-label={t("vps.endpoint.code")} />
                    </Field>
                  </details>
                  <p className="form-footnote">
                    <LockKey size={15} /> {t("vps.endpoint.publishNote")}
                  </p>
                </>
              )}
            </div>
          ) : (
            <div className="endpoint-update-flow">
              {failure}
              {applied ? (
                <OperationResult title={t("vps.endpoint.applied")}>
                  <p>{t("vps.endpoint.appliedNote")}</p>
                </OperationResult>
              ) : (
                <>
                  <p>{t("vps.endpoint.applyIntro")}</p>
                  <Field label={t("vps.endpoint.code")}>
                    <textarea
                      className="secret-code-output mono"
                      value={code}
                      onChange={(event) => { setCode(event.target.value); setNotice(null); }}
                      readOnly={Boolean(busy)}
                      placeholder={CODE_PLACEHOLDER}
                      spellCheck={false}
                    />
                  </Field>
                  {notice && <p className="settings-note endpoint-notice" role="status"><Info size={16} />{notice}</p>}
                  {update && update.code.trim() === code.trim() ? transition(update) : null}
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
