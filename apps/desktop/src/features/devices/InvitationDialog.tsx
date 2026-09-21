import { copyText } from "../../lib/clipboard";
import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowClockwise,
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
      setError(errorMessage(reason, "The invitation could not be created."));
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
              ? "Invitation ready"
              : target
                ? `Add a device for ${target.name}`
                : "Invite a member"}</>}
          description={<>{created
              ? `Copy or share this code before closing. It is only shown once and permits ${maxUses === 1 ? "one join" : `up to ${maxUses} joins`}.`
              : target
                ? `The new device will join the existing ${memberAccessLabel(target)} identity after it creates its own permanent keys.`
                : "The recipient creates permanent keys on their own device and enrolls directly with this VPS."}</>}
          closeDisabled={busy} closeLabel="Close"
          footer={created ? (
            <div className="invitation-result-actions">
              <span>Expires {formatExpiry(created.expires_at_unix)}</span>
              <button
                className="secondary-button"
                onClick={() => void copyCode()}
                aria-live="polite"
              >
                {copyResult === "copied" ? <><Check size={16} /> Copied</> : <><Copy size={16} /> Copy code</>}
              </button>
            </div>
          ) : undefined}>
          {created ? (
            <div className="invitation-result" ref={resultRef}>
              {copyResult === "failed" && <InlineError message="The code could not be copied. Select the long code and copy it manually before closing." />}
              <div className="warning-note">
                <Warning size={18} weight="fill" />
                <span>
                  This is a bearer secret. Anyone holding it can use the
                  invitation until it is redeemed, cancelled, or expired.
                  {" "}If you lose the code, cancel this invitation and create a new one.
                </span>
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
                      {memberAccessLabel(target)} · {target.devices.length}{" "}
                      authorized{" "}
                      {target.devices.length === 1 ? "device" : "devices"}
                    </small>
                  </div>
                </div>
              ) : (
                <>
                  {canCreateAdmin ? (
                    <Field
                      label="Access level"
                      hint="Admins can invite Members and manage ordinary Member devices. Only the Owner can manage Admins."
                    >
                      <select
                        value={access}
                        onChange={(event) =>
                          setAccess(event.target.value as "member" | "admin")
                        }
                      >
                        <option value="member">Member</option>
                        <option value="admin">Admin</option>
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
                      <ArrowClockwise size={16} /> Retry server check
                    </button>
                  </> : <p className="settings-note">Checking invitation support on this VPS…</p>}
                </div>
              ) : recipientNamesAvailable ? (
                <p className="settings-note">{target ? `The recipient names their new device. It stays part of ${target.name}.` : "The recipient chooses their device name when joining. You choose their access and invitation limits."}</p>
              ) : <>
                <p className="settings-note">
                  This VPS uses the earlier invitation format. Choose the device name here to create a code.
                  Update the VPS components to let recipients choose their device name when joining.
                </p>
                <Field label="Device name">
                  <input value={deviceName} maxLength={64} required autoComplete="off" onChange={(event) => setDeviceName(event.target.value)} />
                </Field>
              </>}
              <Field label="Expires after">
                <select
                  value={lifetime}
                  onChange={(event) => setLifetime(event.target.value)}
                >
                  <option value="3600">1 hour</option>
                  <option value="86400">24 hours</option>
                  <option value="604800">7 days</option>
                </select>
              </Field>
              {scopedAvailable && target?.role !== "owner" && <Field label="Number of joins" hint="Each join creates separate permanent device keys. Additional devices for an existing member also follow their device limit.">
                <input type="number" min={1} max={100} value={maxUses} onChange={(event) => setMaxUses(Number(event.target.value))} />
              </Field>}
              {scopedAvailable && !target && <details className="access-disclosure member-policy-disclosure">
                <summary>Member permissions and access times</summary>
                <MemberPolicyFields draft={policy} onChange={setPolicy} delegated={delegated} />
              </details>}
              {error ? <InlineError message={error} /> : null}
              <button
                className="primary-button"
                type="submit"
                disabled={
                  busy || !ready
                }
              >
                {busy ? (
                  <ArrowClockwise className="spin" size={18} />
                ) : (
                  <Key size={18} />
                )}
                {busy
                  ? "Creating"
                  : target
                    ? "Create device code"
                    : maxUses > 1 ? "Create reusable code" : "Create single-use code"}
              </button>
            </form>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
