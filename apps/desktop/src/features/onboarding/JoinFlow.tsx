import { SecretTextarea } from "../../components/SecretInput";
import { InvitationReviewFields, useInvitationReview } from "./InvitationReview";
import {
  ArrowClockwise,
  Key,
  LockKey,
  ShieldCheck,
} from "@phosphor-icons/react";
import { useState } from "react";
import { isAndroid } from "../../platform";
import { api } from "../../api";
import { type ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";

export function JoinFlow({
  onComplete,
  compact = false,
}: {
  onComplete: (profile: ServerProfile) => Promise<void>;
  compact?: boolean;
}) {
  const [code, setCode] = useState("");
  const review = useInvitationReview(code, isAndroid ? "My Android device" : "My computer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const join = async () => {
    if (!review.ready) return;
    setBusy(true);
    setError(null);
    try {
      const profile = await api.joinServer(code.trim(), review.names);
      setCode("");
      await onComplete(profile);
    } catch (reason) {
      setError(
        errorMessage(
          reason,
          "The invitation could not be redeemed. It may be invalid, expired, used, or revoked.",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className={`setup-form join-form ${compact ? "compact" : ""}`}
      onSubmit={(event) => {
        event.preventDefault();
        void join();
      }}
    >
      <div className="form-heading">
        <span>
          <Key size={20} />
        </span>
        <div>
          <h2>Join a private server</h2>
          <p>
            Your permanent device keys are generated here. The code is validated
            directly by the VPS.
          </p>
        </div>
      </div>
      <Field
        label="Invitation code"
        hint="Treat this code like a password. It is cleared after a successful join."
      >
        <SecretTextarea
          className="secret-code-input mono"
          value={code}
          onChange={(event) => setCode(event.target.value)}
          placeholder="sirin1.…"
          autoCapitalize="none"
          autoComplete="off"
          spellCheck={false}
        />
      </Field>
      {review.error && <InlineError message={review.error} />}
      <InvitationReviewFields review={review} disabled={busy} />
      {error ? <InlineError message={error} /> : null}
      {!review.preview && <button type="button" className="primary-button" disabled={busy || review.busy || !code.trim()} onClick={() => void review.review()}>{review.busy ? "Checking invitation…" : "Review invitation"}</button>}
      {review.preview && <>
      <button
        className="primary-button"
        type="submit"
        disabled={busy || !review.ready}
      >
        {busy ? (
          <ArrowClockwise className="spin" size={18} />
        ) : (
          <ShieldCheck size={18} />
        )}
        {busy ? "Joining directly" : "Join server"}
      </button>
      </>}
      <p className="form-footnote">
        <LockKey size={15} /> No cloud account. No shared permanent private key.
      </p>
    </form>
  );
}
