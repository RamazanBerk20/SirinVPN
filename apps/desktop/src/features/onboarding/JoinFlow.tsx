import { SecretTextarea } from "../../components/SecretInput";
import { InvitationReviewFields, useInvitationReview } from "./InvitationReview";
import {
  ArrowClockwise,
  Key,
  ShieldCheck,
} from "@phosphor-icons/react";
import { useState } from "react";
import { isAndroid } from "../../platform";
import { api } from "../../api";
import { type ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";

/** Invitation codes begin with this prefix; it is a format hint, not language. */
const codePlaceholder = "sirin1.…";

export function JoinFlow({
  onComplete,
  compact = false,
}: {
  onComplete: (profile: ServerProfile) => Promise<void>;
  compact?: boolean;
}) {
  const [code, setCode] = useState("");
  const review = useInvitationReview(code, isAndroid ? t("onboarding.join.defaultDeviceNameAndroid") : t("onboarding.join.defaultDeviceNameDesktop"));
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
      setError(errorMessage(reason, t("onboarding.join.error")));
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
          <h2>{t("onboarding.join.title")}</h2>
          <p>{t("onboarding.join.summary")}</p>
        </div>
      </div>
      <Field
        label={t("onboarding.join.code")}
        hint={t("onboarding.join.codeHint")}
      >
        <SecretTextarea
          className="secret-code-input mono"
          value={code}
          onChange={(event) => setCode(event.target.value)}
          placeholder={codePlaceholder}
          autoCapitalize="none"
          autoComplete="off"
          spellCheck={false}
        />
      </Field>
      {review.error && <InlineError message={review.error} />}
      <InvitationReviewFields review={review} disabled={busy} />
      {error ? <InlineError message={error} /> : null}
      {!review.preview && <button type="button" className="primary-button" disabled={busy || review.busy || !code.trim()} onClick={() => void review.review()}>{review.busy ? t("common.state.checking") : t("onboarding.join.review")}</button>}
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
        {busy ? t("onboarding.join.submitting") : t("onboarding.join.submit")}
      </button>
      </>}
    </form>
  );
}
