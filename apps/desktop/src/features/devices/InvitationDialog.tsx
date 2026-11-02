import { copyText } from "../../lib/clipboard";
import { confirmAction } from "../../lib/confirmAction";
import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise, CaretDown, Check, Copy, Key, Warning } from "@phosphor-icons/react";
import { useId, useLayoutEffect, useRef, useState } from "react";
import { memberAccessLabel, memberAccessLevel } from "../../access";
import { api } from "../../api";
import type { InvitationResult, MemberPolicy, MemberSummary, ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { errorMessage, formatExpiry } from "../../lib/errors";
import { MemberPolicyFields } from "./MemberPolicyFields";
import { policyDraft, policyFieldErrors, policyFromDraft } from "./memberPolicy";
import { InvitationShare } from "./InvitationShare";
import { t } from "../../i18n";
import { isAndroid } from "../../platform";

export function InvitationDialog({
  profile,
  open,
  target,
  self = false,
  canCreateAdmin,
  scopedAvailable = false,
  recipientNamesAvailable,
  configurationError,
  onRefreshConfiguration,
  issuer,
  delegated = false,
  onOpenChange,
  onCreated,
}: {
  profile: Pick<ServerProfile, "id">;
  open: boolean;
  target: MemberSummary | null;
  /** The target is this device's own member: the code is for the inviter's next device. */
  self?: boolean;
  canCreateAdmin: boolean;
  scopedAvailable?: boolean;
  recipientNamesAvailable: boolean | null;
  configurationError?: string | null;
  onRefreshConfiguration: () => Promise<void>;
  issuer?: MemberSummary;
  delegated?: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: () => Promise<void>;
}) {
  const form = useId();
  const initialPolicy = () => policyDraft(delegated ? { ...issuer?.policy, invite_members: false } as MemberPolicy : undefined);
  const [lifetime, setLifetime] = useState("3600");
  const [access, setAccess] = useState<"member" | "admin">("member");
  const [maxUses, setMaxUses] = useState(1);
  const usesInvalid = !Number.isInteger(maxUses) || maxUses < 1 || maxUses > 100;
  const [deviceName, setDeviceName] = useState("");
  const [policy, setPolicy] = useState(initialPolicy);
  const policyInvalid = scopedAvailable && !target && Object.keys(policyFieldErrors(policy)).length > 0;
  const [created, setCreated] = useState<InvitationResult | null>(null);
  // A one-time code that was never copied, enlarged or shared asks before it is closed for good.
  const [shared, setShared] = useState(false);
  const resultRef = useRef<HTMLDivElement>(null);
  const [copyResult, setCopyResult] = useState<"idle" | "copied" | "failed">("idle");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = recipientNamesAvailable !== null &&
    (recipientNamesAvailable || Boolean(deviceName.trim()));

  useLayoutEffect(() => {
    // A code created from the bottom of a long form starts at its sharing guidance.
    const body = resultRef.current?.parentElement;
    if (body) body.scrollTop = 0;
  }, [created]);

  const close = () => {
    setCreated(null);
    setShared(false);
    setCopyResult("idle");
    setLifetime("3600");
    setAccess("member");
    setMaxUses(1);
    setDeviceName("");
    setPolicy(initialPolicy());
    setError(null);
    onOpenChange(false);
  };

  const changeOpen = async (next: boolean) => {
    if (next) return onOpenChange(true);
    if (busy) return;
    if (created && !shared && !await confirmAction({
      title: t("devices.invite.closeUnshared.title"),
      message: t("devices.invite.closeUnshared.message"),
      confirm: t("devices.invite.closeUnshared.action"),
    })) return;
    close();
  };

  const copyCode = async () => {
    if (!created) return;
    try {
      await copyText(created.code);
      setCopyResult("copied");
      setShared(true);
    } catch {
      setCopyResult("failed");
    }
  };

  const create = async () => {
    if (busy || !ready || recipientNamesAvailable === null || usesInvalid || policyInvalid) return;
    setBusy(true);
    setError(null);
    try {
      const invitation = await api.createInvitation(
        profile.id,
        target?.name ?? (recipientNamesAvailable ? "" : deviceName.trim()),
        recipientNamesAvailable ? "" : deviceName.trim(),
        Number(lifetime),
        target?.id ?? null,
        target ? Boolean(target.administrator) : access === "admin",
        maxUses,
        target || !scopedAvailable ? undefined : policyFromDraft(policy),
        recipientNamesAvailable,
      );
      setCreated(invitation);
      await onCreated();
    } catch (reason) {
      setError(errorMessage(reason, t("devices.invite.createFailed")));
    } finally {
      setBusy(false);
    }
  };

  const heading = created
    ? t("devices.invite.titleReady")
    : self ? t("devices.invite.titleSelf")
      : target ? t("devices.invite.titleForMember", { name: target.name }) : t("devices.invite.title");
  const description = created
    ? t(target ? "devices.invite.descriptionReadyDevice" : "devices.invite.descriptionReady")
    : self ? t("devices.invite.descriptionSelf")
      : target ? t("devices.invite.descriptionForMember", { name: target.name })
        : t(recipientNamesAvailable ? "devices.invite.descriptionNamed" : "devices.invite.description");
  const createLabel = busy
    ? t("devices.invite.creating")
    : target ? t("devices.invite.createForMember") : maxUses > 1 ? t("devices.invite.createReusable") : t("devices.invite.createSingleUse");

  return (
    <Dialog.Root open={open} onOpenChange={(next) => void changeOpen(next)}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className={`dialog-content invitation-dialog${created ? " invitation-dialog-ready" : ""}`}
          heading={<>{heading}</>}
          description={<>{description}</>}
          closeDisabled={busy} closeLabel={t("common.action.close")}
          footer={created ? (
            <div className="dialog-commit">
              <button className="secondary-button" onClick={() => void copyCode()} aria-live="polite">
                {copyResult === "copied" ? <><Check size={16} /> {t("common.action.copied")}</> : <><Copy size={16} /> {t("devices.invite.copyCode")}</>}
              </button>
              <button className="primary-button" onClick={() => void changeOpen(false)}>{t("devices.invite.done")}</button>
            </div>
          ) : (
            <div className="dialog-commit">
              <button className="primary-button" type="submit" form={form} disabled={busy || !ready || usesInvalid || policyInvalid}>
                {busy ? <ArrowClockwise className="spin" size={18} /> : <Key size={18} />}
                {createLabel}
              </button>
            </div>
          )}>
          {created ? (
            <div className="invitation-result" ref={resultRef}>
              <div className="invitation-secret-note" role="note">
                <Warning size={20} weight="fill" aria-hidden="true" />
                <div>
                  <strong>{t("devices.invite.onceTitle")}</strong>
                  <p>{t("devices.invite.secretWarning")}</p>
                  <p className="invitation-result-meta">
                    {t("devices.invite.resultMeta", {
                      uses: maxUses > 1 ? t("devices.invite.usesUpTo", { count: maxUses }) : t("devices.invitations.singleUse"),
                      date: formatExpiry(created.expires_at_unix),
                    })}
                  </p>
                </div>
              </div>
              {copyResult === "failed" && <InlineError message={t(isAndroid ? "devices.invite.copyFailedAndroid" : "devices.invite.copyFailed")} />}
              <InvitationShare invitation={created} onShared={() => setShared(true)} />
            </div>
          ) : (
            <form id={form} className="invite-form" onSubmit={(event) => { event.preventDefault(); void create(); }}>
              {target ? (
                <div className="invite-target">
                  <span className={`member-avatar ${memberAccessLevel(target)}`} aria-hidden="true">{[...target.name.trim()][0]?.toLocaleUpperCase() ?? "?"}</span>
                  <p>
                    <strong>{target.name}</strong>
                    <span>{t("devices.invite.targetSummary", { role: memberAccessLabel(target), count: target.devices.length })}</span>
                  </p>
                </div>
              ) : canCreateAdmin ? (
                <Field label={t("devices.invite.role")} hint={t(access === "admin" ? "devices.invite.roleHint" : "devices.invite.roleHintMember")}>
                  <select value={access} onChange={(event) => setAccess(event.target.value as "member" | "admin")}>
                    <option value="member">{t("common.role.member")}</option>
                    <option value="admin">{t("common.role.admin")}</option>
                  </select>
                </Field>
              ) : null}
              {recipientNamesAvailable === null ? (
                configurationError
                  ? <InlineError message={configurationError} onRetry={() => void onRefreshConfiguration()} retryLabel={t("devices.invite.checkAgain")} />
                  : <p className="settings-note" role="status"><ArrowClockwise className="spin" size={15} /> {t("devices.invite.checking")}</p>
              ) : recipientNamesAvailable ? null : (<>
                <p className="settings-note">{t("devices.invite.olderServer")}</p>
                <Field label={t("devices.invite.deviceName")}>
                  <input value={deviceName} maxLength={64} required autoComplete="off" onChange={(event) => setDeviceName(event.target.value)} />
                </Field>
              </>)}
              <div className="invite-form-row">
                <Field label={t("devices.invite.lifetime")}>
                  <select value={lifetime} onChange={(event) => setLifetime(event.target.value)}>
                    <option value="3600">{t("devices.invite.hours", { count: 1 })}</option>
                    <option value="86400">{t("devices.invite.hours", { count: 24 })}</option>
                    <option value="604800">{t("devices.invite.days", { count: 7 })}</option>
                  </select>
                </Field>
                {scopedAvailable && target?.role !== "owner" && (
                  <Field label={t("devices.invite.uses")} hint={t("devices.invite.usesHint")} error={usesInvalid ? t("devices.invite.usesInvalid") : undefined}>
                    <input type="number" min={1} max={100} inputMode="numeric" value={maxUses} onChange={(event) => setMaxUses(Number(event.target.value))} />
                  </Field>
                )}
              </div>
              {scopedAvailable && !target && (
                <details className="access-disclosure member-policy-disclosure">
                  <summary>{t("devices.invite.permissions")} <CaretDown size={16} className="disclosure-chevron" /></summary>
                  <MemberPolicyFields draft={policy} onChange={setPolicy} delegated={delegated} creating />
                </details>
              )}
              {error ? <InlineError message={error} /> : null}
            </form>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
