import { SecretTextarea } from "../../components/SecretInput";
import { InvitationReviewFields, useInvitationReview } from "./InvitationReview";
import { ArrowClockwise, CheckCircle, Key, ShieldCheck } from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { type ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { appError, errorMessage } from "../../lib/errors";
import { t } from "../../i18n";

/** Join codes begin with this prefix; it is a format hint, not language. */
const codePlaceholder = "sirin1.…";

export function JoinFlow({
  onComplete,
  compact = false,
}: {
  onComplete: (profile: ServerProfile) => Promise<void>;
  compact?: boolean;
}) {
  const form = useRef<HTMLFormElement>(null);
  const [code, setCode] = useState("");
  const [focusCode, setFocusCode] = useState(false);
  const review = useInvitationReview(code);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [takenName, setTakenName] = useState<string | null>(null);

  useEffect(() => {
    if (!focusCode) return;
    setFocusCode(false);
    form.current?.querySelector<HTMLElement>("textarea, .native-code-input button")?.focus();
  }, [focusCode]);

  // A refused or accepted code is replaced, not edited: a pasted secret is never left on screen.
  const changeCode = () => { setCode(""); setError(null); setFocusCode(true); };

  const join = async () => {
    if (!review.ready) return;
    setBusy(true);
    setError(null);
    try {
      const profile = await api.joinServer(code.trim(), review.names);
      setCode("");
      await onComplete(profile);
    } catch (reason) {
      // A taken person name belongs to its field, not to the form's error.
      if (review.naming.personName && appError(reason, ["person_name_taken"]).code === "person_name_taken") setTakenName(review.personName.trim());
      else setError(errorMessage(reason, t("onboarding.join.error")));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      ref={form}
      className={`setup-form join-form ${compact ? "compact" : ""}`}
      data-state={busy ? "joining" : review.rejected ? "rejected" : review.preview ? "reviewed" : review.busy ? "reviewing" : "entering"}
      data-rejected={review.rejected}
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
      {review.preview ? (
        <div className={`code-entered${error ? " rejected" : ""}`} role="status">
          {/* After a failed join the code was read but not accepted: no green check above the error. */}
          {!error && <CheckCircle size={20} weight="fill" aria-hidden="true" />}
          <span>{t(error ? "devices.join.codeEntered" : "devices.join.codeAccepted")}</span>
          <button type="button" className="text-button" disabled={busy} onClick={changeCode}>{t("devices.join.changeCode")}</button>
        </div>
      ) : (
        <Field label={t("onboarding.join.code")} hint={t("onboarding.join.codeHint")}>
          <SecretTextarea field="code"
            className="secret-code-input mono"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            placeholder={codePlaceholder}
            autoCapitalize="none"
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
      )}
      {review.error && (review.rejected
        ? <InlineError message={review.error} />
        : <InlineError message={review.error} onRetry={() => void review.review()} retryDisabled={review.busy} />)}
      <InvitationReviewFields review={review} disabled={busy} takenName={takenName} />
      {error ? <InlineError message={error} /> : null}
      {review.rejected ? (
        <button type="button" className="primary-button" onClick={changeCode}>{t("devices.join.changeCode")}</button>
      ) : !review.preview ? (
        <button type="button" className="primary-button" disabled={busy || review.busy || !code.trim()} onClick={() => void review.review()}>
          {review.busy && <ArrowClockwise className="spin" size={18} />}
          {review.busy ? t("common.state.checking") : t("onboarding.join.review")}
        </button>
      ) : (
        <button className="primary-button" type="submit" disabled={busy || !review.ready}>
          {busy ? <ArrowClockwise className="spin" size={18} /> : <ShieldCheck size={18} />}
          {busy ? t("onboarding.join.submitting") : t("onboarding.join.submit")}
        </button>
      )}
    </form>
  );
}
