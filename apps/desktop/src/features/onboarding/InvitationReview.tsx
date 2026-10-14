import { useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { Field } from "../../components/ui";
import type { InvitationNames, InvitationPreview } from "../../types";
import { errorMessage, formatExpiry } from "../../lib/errors";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";

const validName = (name: string) => Boolean(name.trim()) && [...name.trim()].length <= 64 && !/[\u0000-\u001f\u007f-\u009f]/.test(name);

export function useInvitationReview(code: string, defaultDeviceName: string) {
  const [preview, setPreview] = useState<InvitationPreview | null>(null);
  const [deviceName, setDeviceName] = useState(defaultDeviceName);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const reviewedCode = useRef("");
  useEffect(() => {
    ++generation.current; reviewedCode.current = ""; setPreview(null); setError(null); setBusy(false);
    return () => { ++generation.current; reviewedCode.current = ""; };
  }, [code]);
  const review = async () => {
    if (busy || !code.trim()) return;
    const current = generation.current;
    setBusy(true); setError(null);
    try {
      const value = await api.previewInvitation(code.trim());
      if (current !== generation.current) return;
      reviewedCode.current = code.trim(); setPreview(value);
    } catch (reason) {
      if (current === generation.current) setError(errorMessage(reason, t("onboarding.invitation.error")));
    } finally { if (current === generation.current) setBusy(false); }
  };
  const names: InvitationNames = preview?.recipient_names ? {
    ...(preview.creates_member ? { member_name: deviceName.trim() } : {}), device_name: deviceName.trim(),
  } : {};
  const ready = Boolean(preview && reviewedCode.current === code.trim() && !busy && (!preview.recipient_names ||
    validName(deviceName)));
  return { preview, deviceName, setDeviceName, busy, error, review, names, ready };
}

export function InvitationReviewFields({ review, disabled }: { review: ReturnType<typeof useInvitationReview>; disabled: boolean }) {
  const preview = review.preview;
  if (!preview) return null;
  return <div className="invitation-review">
    <div><strong>{preview.server_name}</strong><p>{t("common.separator.pair", { first: preview.host, second: t(preview.access_level === "admin" ? "onboarding.invitation.access.admin" : preview.access_level === "owner" ? "onboarding.invitation.access.owner" : "onboarding.invitation.access.member") })}</p>
      <small>{t("onboarding.invitation.expires", { date: formatExpiry(preview.expires_at_unix) })}</small></div>
    {preview.recipient_names ? <>
      {!preview.creates_member && <p>{t("onboarding.invitation.addsDevice")}</p>}
      <Field label={t("onboarding.invitation.deviceName")}><input value={review.deviceName} maxLength={64} autoComplete="off" enterKeyHint="done" disabled={disabled} onChange={(event) => review.setDeviceName(event.target.value)} /></Field>
    </> : <p><Rich id="onboarding.invitation.presetName" params={{ name: preview.device_name }} tags={{ strong: (content) => <strong>{content}</strong> }} /></p>}
    <details className="identity-disclosure"><summary>{t("onboarding.invitation.identity")}</summary><code className="fingerprint-value">{preview.server_identity_fingerprint}</code><p className="settings-note">{t("onboarding.invitation.trust")}</p></details>
  </div>;
}
