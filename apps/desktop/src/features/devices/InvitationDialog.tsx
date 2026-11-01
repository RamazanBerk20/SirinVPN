import { copyText } from "../../lib/clipboard";
import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowClockwise,
  CaretDown,
  Check,
  Copy,
  Desktop,
  Key,
  Warning,
} from "@phosphor-icons/react";
import { useLayoutEffect, useRef, useState } from "react";
import { memberAccessLabel } from "../../access";
import { api } from "../../api";
import {
  type InvitationResult,
  type MemberSummary,
  type ServerProfile,
} from "../../types";
import { Field, InlineError } from "../../components/ui";
import { errorMessage, formatExpiry } from "../../lib/errors";
import { MemberPolicyFields } from "./MemberPolicyFields";
import { policyDraft, policyFromDraft } from "./memberPolicy";
import { InvitationShare } from "./InvitationShare";
import { t } from "../../i18n";
import { isAndroid } from "../../platform";

export function InvitationDialog({
  profile,
  open,
  target,
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
  const [lifetime, setLifetime] = useState("3600");
  const [access, setAccess] = useState<"member" | "admin">("member");
  const [maxUses, setMaxUses] = useState(1);
  const usesInvalid = !Number.isInteger(maxUses) || maxUses < 1 || maxUses > 100;
  const [deviceName, setDeviceName] = useState("");
  const [policy, setPolicy] = useState(() => policyDraft(delegated ? { ...issuer?.policy, invite_members: false } as import("../../types").MemberPolicy : undefined));
  const [created, setCreated] = useState<InvitationResult | null>(null);
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

  const changeOpen = (next: boolean) => {
    if (!next && busy) return;
    if (!next) {
      setCreated(null);
      setCopyResult("idle");
      setLifetime("3600");
      setAccess("member");
      setMaxUses(1);
      setDeviceName("");
      setPolicy(policyDraft(delegated ? { ...issuer?.policy, invite_members: false } as import("../../types").MemberPolicy : undefined));
      setError(null);
    }
    onOpenChange(next);
  };

  const copyCode = async () => {
    if (!created) return;
    try {
      await copyText(created.code);
      setCopyResult("copied");
    } catch {
      setCopyResult("failed");
    }
  };

  const create = async () => {
    if (busy || !ready || recipientNamesAvailable === null) return;
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

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className={`dialog-content invitation-dialog${created ? " invitation-dialog-ready" : ""}`}
          heading={<>{created
              ? t("devices.invite.titleReady")
              : target
                ? t("devices.invite.titleForMember", { name: target.name })
                : t("devices.invite.title")}</>}
          description={<>{created
              ? t("devices.invite.descriptionReady", { count: maxUses })
              : target
                ? t("devices.invite.descriptionForMember", { name: target.name })
                : t("devices.invite.description")}</>}
          closeDisabled={busy} closeLabel={t("common.action.close")}
          footer={created ? (
            <div className="invitation-result-actions">
              <span>{t("devices.invite.expires", { date: formatExpiry(created.expires_at_unix) })}</span>
              <button
                className="secondary-button"
                onClick={() => void copyCode()}
                aria-live="polite"
              >
                {copyResult === "copied" ? <><Check size={16} /> {t("common.action.copied")}</> : <><Copy size={16} /> {t("devices.invite.copyCode")}</>}
              </button>
            </div>
          ) : undefined}>
          {created ? (
            <div className="invitation-result" ref={resultRef}>
              {copyResult === "failed" && <InlineError message={t(isAndroid ? "devices.invite.copyFailedAndroid" : "devices.invite.copyFailed")} />}
              <div className="warning-note">
                <Warning size={18} weight="fill" />
                <span>{t("devices.invite.secretWarning")}</span>
              </div>
              <InvitationShare invitation={created} />
            </div>
          ) : (
            <form
              className="invite-form"
              onSubmit={(event) => {
                event.preventDefault();
                void create();
              }}
            >
              {target ? (
                <div className="invite-target">
                  <span>
                    <Desktop size={18} />
                  </span>
                  <div>
                    <strong>{target.name}</strong>
                    <small>
                      {t("devices.invite.targetSummary", { role: memberAccessLabel(target), count: target.devices.length })}
                    </small>
                  </div>
                </div>
              ) : (
                <>
                  {canCreateAdmin ? (
                    <Field
                      label={t("devices.invite.role")}
                      hint={t(access === "admin" ? "devices.invite.roleHint" : "devices.invite.roleHintMember")}
                    >
                      <select
                        value={access}
                        onChange={(event) =>
                          setAccess(event.target.value as "member" | "admin")
                        }
                      >
                        <option value="member">{t("common.role.member")}</option>
                        <option value="admin">{t("common.role.admin")}</option>
                      </select>
                    </Field>
                  ) : null}
                </>
              )}
              {recipientNamesAvailable === null ? (
                <div role="status">
                  {configurationError ? <>
                    <InlineError message={configurationError} />
                    <button className="secondary-button" type="button" onClick={() => void onRefreshConfiguration()}>
                      <ArrowClockwise size={16} /> {t("devices.invite.checkAgain")}
                    </button>
                  </> : <p className="settings-note">{t("devices.invite.checking")}</p>}
                </div>
              ) : recipientNamesAvailable ? null : <>
                <p className="settings-note">{t("devices.invite.olderServer")}</p>
                <Field label={t("devices.invite.deviceName")}>
                  <input value={deviceName} maxLength={64} required autoComplete="off" onChange={(event) => setDeviceName(event.target.value)} />
                </Field>
              </>}
              <Field label={t("devices.invite.lifetime")}>
                <select
                  value={lifetime}
                  onChange={(event) => setLifetime(event.target.value)}
                >
                  <option value="3600">{t("devices.invite.hours", { count: 1 })}</option>
                  <option value="86400">{t("devices.invite.hours", { count: 24 })}</option>
                  <option value="604800">{t("devices.invite.days", { count: 7 })}</option>
                </select>
              </Field>
              {scopedAvailable && target?.role !== "owner" && <Field label={t("devices.invite.uses")} hint={t("devices.invite.usesHint")} error={usesInvalid ? t("devices.invite.usesInvalid") : undefined}>
                <input type="number" min={1} max={100} value={maxUses} onChange={(event) => setMaxUses(Number(event.target.value))} />
              </Field>}
              {scopedAvailable && !target && <details className="access-disclosure member-policy-disclosure">
                <summary>{t("devices.invite.permissions")} <CaretDown size={16} className="disclosure-chevron" /></summary>
                <MemberPolicyFields draft={policy} onChange={setPolicy} delegated={delegated} />
              </details>}
              {/* What happens on the other side: a footnote to the create button, not a field of its own. */}
              {recipientNamesAvailable && <p className="settings-note">{t("devices.invite.recipientNames")}</p>}
              {error ? <InlineError message={error} /> : null}
              <button
                className="primary-button"
                type="submit"
                disabled={
                  busy || !ready || usesInvalid
                }
              >
                {busy ? (
                  <ArrowClockwise className="spin" size={18} />
                ) : (
                  <Key size={18} />
                )}
                {busy
                  ? t("devices.invite.creating")
                  : target
                    ? t("devices.invite.createForMember")
                    : maxUses > 1 ? t("devices.invite.createReusable") : t("devices.invite.createSingleUse")}
              </button>
            </form>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
