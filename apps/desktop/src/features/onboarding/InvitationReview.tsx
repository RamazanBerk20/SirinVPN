import { ShieldCheck, Warning } from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import { roleDescription, roleLabel } from "../../access";
import { api } from "../../api";
import { Field } from "../../components/ui";
import type { InvitationNames, InvitationPreview } from "../../types";
import { appError, errorMessage, formatExpiry } from "../../lib/errors";
import { deviceNameProblem, personNameProblem } from "../devices/names";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";
import { SettingsDisclosure } from "../settings/SettingsParts";

type Rejection = "expired" | "used" | "invalid";

/** The join code itself was refused, as opposed to a failure worth retrying. */
export function invitationRejection(reason: unknown): Rejection | null {
  const { code } = appError(reason, ["invitation_expired", "invitation_used", "invitation_invalid"]);
  return code === "invitation_expired" ? "expired" : code === "invitation_used" ? "used" : code === "invitation_invalid" ? "invalid" : null;
}

/** Which names the joiner gives: the device's always (when the code lets them), their own only when the code has none. */
export function joinNaming(preview: Pick<InvitationPreview, "recipient_names" | "creates_member" | "member_name_fixed">) {
  return {
    deviceName: preview.recipient_names,
    personName: preview.recipient_names && preview.creates_member && !preview.member_name_fixed,
  };
}

export function useInvitationReview(code: string) {
  const [preview, setPreview] = useState<InvitationPreview | null>(null);
  const [reviewedCode, setReviewedCode] = useState("");
  const [deviceName, setDeviceName] = useState("");
  const [personName, setPersonName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rejected, setRejected] = useState(false);
  const generation = useRef(0);
  useEffect(() => {
    const counter = generation; // The ref object itself: an unmount still invalidates the request in flight.
    ++counter.current; setReviewedCode(""); setPreview(null); setError(null); setRejected(false); setBusy(false);
    return () => { ++counter.current; };
  }, [code]);
  const review = async () => {
    if (busy || !code.trim()) return;
    const current = generation.current;
    setBusy(true); setError(null); setRejected(false);
    try {
      const value = await api.previewInvitation(code.trim());
      if (current !== generation.current) return;
      setReviewedCode(code.trim()); setPreview(value);
    } catch (reason) {
      if (current !== generation.current) return;
      const rejection = invitationRejection(reason);
      setRejected(rejection !== null);
      setError(rejection ? t(`devices.join.rejected.${rejection}`) : errorMessage(reason, t("onboarding.invitation.error")));
    } finally { if (current === generation.current) setBusy(false); }
  };
  const naming = preview ? joinNaming(preview) : { deviceName: false, personName: false };
  const names: InvitationNames = naming.deviceName ? {
    ...(naming.personName ? { member_name: personName.trim() } : {}), device_name: deviceName.trim(),
  } : {};
  const ready = Boolean(preview && reviewedCode === code.trim() && !busy
    && (!naming.deviceName || !deviceNameProblem(deviceName))
    && (!naming.personName || !personNameProblem(personName)));
  return { preview, naming, deviceName, setDeviceName, personName, setPersonName, busy, error, rejected, review, names, ready };
}

/** `takenName` is a person name the server refused as already used; the field says so until it changes. */
export function InvitationReviewFields({ review, disabled, takenName = null }: { review: ReturnType<typeof useInvitationReview>; disabled: boolean; takenName?: string | null }) {
  const preview = review.preview;
  const [touched, setTouched] = useState({ device: false, person: false });
  if (!preview) return null;
  const owner = preview.access_level === "owner";
  const deviceProblem = touched.device ? deviceNameProblem(review.deviceName) : null;
  const personProblem = (touched.person ? personNameProblem(review.personName) : null)
    ?? (takenName !== null && review.personName.trim() === takenName ? t("common.errorCode.person_name_taken") : null);
  return <div className="invitation-review">
    <div className="invitation-review-server">
      <ShieldCheck size={22} weight="duotone" aria-hidden="true" />
      <div>
        <strong>{preview.server_name}</strong>
        <p dir="auto">{preview.host}</p>
        <small>{t("onboarding.invitation.expires", { date: formatExpiry(preview.expires_at_unix) })}</small>
      </div>
    </div>
    <p className="role-line" data-testid="join-role">
      <span className={`access-badge ${preview.access_level}`}>{roleLabel(preview.access_level)}</span>
      <span>{roleDescription(preview.access_level)}</span>
    </p>
    {!preview.creates_member && (owner
      ? <div className="invitation-review-owner" role="note">
        <Warning size={18} weight="fill" aria-hidden="true" />
        <p><strong>{t("devices.join.ownerDevice", { name: preview.member_name })}</strong> {t("devices.join.ownerPower")}</p>
      </div>
      : <p>{t("devices.join.addsDevice", { name: preview.member_name })}</p>)}
    {preview.creates_member && !review.naming.personName && <p data-testid="join-person">
      <Rich id="devices.join.namedPerson" params={{ name: preview.member_name }} tags={{ strong: (content) => <strong>{content}</strong> }} />
    </p>}
    {review.naming.personName && <Field label={t("devices.join.personName")} hint={t("devices.join.personNameHint")} error={personProblem ?? undefined}>
      <input value={review.personName} maxLength={128} autoComplete="name" disabled={disabled} data-testid="join-person-name"
        onBlur={() => setTouched((value) => ({ ...value, person: true }))} onChange={(event) => review.setPersonName(event.target.value)} />
    </Field>}
    {review.naming.deviceName ? (
      <Field label={t("devices.join.deviceName")} hint={t("devices.join.deviceNameHint")} error={deviceProblem ?? undefined}>
        <input value={review.deviceName} maxLength={128} autoComplete="off" enterKeyHint="done" disabled={disabled} data-testid="join-device-name"
          onBlur={() => setTouched((value) => ({ ...value, device: true }))} onChange={(event) => review.setDeviceName(event.target.value)} />
      </Field>
    ) : <p>
      <Rich id="devices.join.presetDevice" params={{ name: preview.device_name }} tags={{ strong: (content) => <strong>{content}</strong> }} />
      {" "}{t("devices.join.renameLater")}
    </p>}
    <SettingsDisclosure boxed className="access-disclosure invitation-identity" summary={t("onboarding.invitation.identity")}>
      <code className="fingerprint-value" dir="ltr">{preview.server_identity_fingerprint}</code>
      <p className="settings-note">{t("onboarding.invitation.trust")}</p>
    </SettingsDisclosure>
  </div>;
}
