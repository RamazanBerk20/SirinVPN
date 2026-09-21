import { useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { Field } from "../../components/ui";
import type { InvitationNames, InvitationPreview } from "../../types";
import { errorMessage, formatExpiry } from "../../lib/errors";

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
      if (current === generation.current) setError(errorMessage(reason, "The invitation could not be verified. Ask your inviter for a new code."));
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
    <div><strong>{preview.server_name}</strong><p>{preview.host} · {preview.access_level === "admin" ? "Admin" : preview.access_level === "owner" ? "Owner" : "Member"} access</p>
      <small>Expires {formatExpiry(preview.expires_at_unix)}</small></div>
    {preview.recipient_names ? <>
      {!preview.creates_member && <p>Adding a device to the existing access group. Its permissions stay the same.</p>}
      <Field label="Your device name"><input value={review.deviceName} maxLength={64} autoComplete="off" enterKeyHint="done" disabled={disabled} onChange={(event) => review.setDeviceName(event.target.value)} /></Field>
    </> : <p>Device name chosen by the inviter: <strong>{preview.device_name}</strong>.</p>}
    <details className="identity-disclosure"><summary>Verified server identity</summary><code className="fingerprint-value">{preview.server_identity_fingerprint}</code><p className="settings-note">The invitation signature is valid. Join only if this is the invitation you expected from someone you trust.</p></details>
  </div>;
}
