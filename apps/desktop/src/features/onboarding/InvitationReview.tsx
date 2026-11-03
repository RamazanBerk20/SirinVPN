import { ShieldCheck, Warning } from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { Field } from "../../components/ui";
import type { InvitationNames, InvitationPreview } from "../../types";
import { errorMessage, formatExpiry } from "../../lib/errors";
import { deviceNameProblem } from "../devices/RenameDeviceDialog";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";
import { SettingsDisclosure } from "../settings/SettingsParts";

type Rejection = "expired" | "used" | "invalid";

/** The invitation itself was refused, as opposed to a failure worth retrying. Matches the backend's English causes. */
export function invitationRejection(reason: unknown): Rejection | null {
  const detail = reason instanceof Error ? reason.message : String(reason ?? "");
  if (/expired/i.test(detail)) return "expired";
  if (/no joins remaining|already been used|used up/i.test(detail)) return "used";
  if (/signature is invalid|code is invalid|not a valid invitation/i.test(detail)) return "invalid";
  return null;
}

export function useInvitationReview(code: string, defaultDeviceName: string) {
  const [preview, setPreview] = useState<InvitationPreview | null>(null);
  const [deviceName, setDeviceName] = useState(defaultDeviceName);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rejected, setRejected] = useState(false);
  const generation = useRef(0);
  const reviewedCode = useRef("");
  useEffect(() => {
    ++generation.current; reviewedCode.current = ""; setPreview(null); setError(null); setRejected(false); setBusy(false);
    return () => { ++generation.current; reviewedCode.current = ""; };
  }, [code]);
  const review = async () => {
    if (busy || !code.trim()) return;
    const current = generation.current;
    setBusy(true); setError(null); setRejected(false);
    try {
      const value = await api.previewInvitation(code.trim());
      if (current !== generation.current) return;
      reviewedCode.current = code.trim(); setPreview(value);
    } catch (reason) {
      if (current !== generation.current) return;
      const rejection = invitationRejection(reason);
      setRejected(rejection !== null);
      setError(rejection ? t(`devices.join.rejected.${rejection}`) : errorMessage(reason, t("onboarding.invitation.error")));
    } finally { if (current === generation.current) setBusy(false); }
  };
  const names: InvitationNames = preview?.recipient_names ? {
    ...(preview.creates_member ? { member_name: deviceName.trim() } : {}), device_name: deviceName.trim(),
  } : {};
  const ready = Boolean(preview && reviewedCode.current === code.trim() && !busy && (!preview.recipient_names ||
    !deviceNameProblem(deviceName)));
  return { preview, deviceName, setDeviceName, busy, error, rejected, review, names, ready };
}

export function InvitationReviewFields({ review, disabled }: { review: ReturnType<typeof useInvitationReview>; disabled: boolean }) {
  const preview = review.preview;
  if (!preview) return null;
  const owner = preview.access_level === "owner";
  return <div className="invitation-review">
    <div className="invitation-review-server">
      <ShieldCheck size={22} weight="duotone" aria-hidden="true" />
      <div>
        <strong>{preview.server_name}</strong>
        <p>{t("common.separator.pair", { first: preview.host, second: t(owner ? "onboarding.invitation.access.owner" : preview.access_level === "admin" ? "onboarding.invitation.access.admin" : "onboarding.invitation.access.member") })}</p>
        <small>{t("onboarding.invitation.expires", { date: formatExpiry(preview.expires_at_unix) })}</small>
      </div>
    </div>
    {!preview.creates_member && (owner
      ? <div className="invitation-review-owner" role="note">
        <Warning size={18} weight="fill" aria-hidden="true" />
        <p><strong>{t("devices.join.ownerDevice", { name: preview.member_name })}</strong> {t("devices.join.ownerPower")}</p>
      </div>
      : <p>{t("onboarding.invitation.addsDevice")}</p>)}
    {preview.recipient_names ? (
      <Field label={t("onboarding.invitation.deviceName")} error={deviceNameProblem(review.deviceName) ?? undefined}>
        <input value={review.deviceName} maxLength={128} autoComplete="off" enterKeyHint="done" disabled={disabled} onChange={(event) => review.setDeviceName(event.target.value)} />
      </Field>
    ) : <p>
      <Rich id="onboarding.invitation.presetName" params={{ name: preview.device_name }} tags={{ strong: (content) => <strong>{content}</strong> }} />
      {" "}{t("devices.join.renameLater")}
    </p>}
    <SettingsDisclosure boxed className="access-disclosure invitation-identity" summary={t("onboarding.invitation.identity")}>
      <code className="fingerprint-value">{preview.server_identity_fingerprint}</code>
      <p className="settings-note">{t("onboarding.invitation.trust")}</p>
    </SettingsDisclosure>
  </div>;
}
