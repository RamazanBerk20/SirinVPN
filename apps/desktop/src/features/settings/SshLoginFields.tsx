import { isAndroid } from "../../platform";
import { open } from "../../lib/nativeDialog";
import { ConfirmationRow } from "../../components/ConfirmationRow";
import { SecretInput } from "../../components/SecretInput";
import { Field, InlineError } from "../../components/ui";
import type { useSshLogin } from "../../hooks/useSshLogin";
import { errorMessage } from "../../lib/errors";
import { useState } from "react";
import { t, type MessageKey } from "../../i18n";
import type { SavedSshLogin } from "../../types";

const authLabels: Record<SavedSshLogin["authentication"], MessageKey> = {
  password: "ssh.auth.password",
  agent: "ssh.auth.agent",
  private_key: "ssh.auth.privateKey",
};

export function SshLoginFields({
  login,
}: {
  login: ReturnType<typeof useSshLogin>;
}) {
  const [pickerError, setPickerError] = useState("");
  return (
    <div className="ssh-login-fields" aria-busy={login.loading}>
      <p className="ssh-login-status settings-note" role="status">
        {login.checkingSavedLogin ? t("ssh.login.checking") : ""}
      </p>
      {/* A locked keyring is usually fixed by unlocking it, so reading again comes first; forgetting is the fallback. */}
      {login.error && <div className="ssh-login-error">
        <InlineError message={login.error} onRetry={login.saved ? undefined : login.retry} retryDisabled={login.loading || login.forgetting} />
        {!login.saved && <button type="button" className="text-button" disabled={login.loading || login.forgetting} onClick={() => void login.forget()}>
          {t("ssh.login.forgetSaved")}
        </button>}
      </div>}
      <fieldset className="ssh-login-content" disabled={login.loading || login.forgetting}>
      {login.usingSaved ? (
        <div className="saved-ssh-login">
          <div>
            <strong>{t("ssh.login.savedTitle")}</strong>
            <p>
              {t("ssh.login.savedSummary", { username: login.username, port: login.port, method: t(authLabels[login.auth]) })}
            </p>
          </div>
          <div className="saved-ssh-actions">
            <button type="button" className="text-button" onClick={login.edit}>
              {t("ssh.login.change")}
            </button>
            <button
              type="button"
              className="text-button"
              disabled={login.forgetting}
              onClick={() => void login.forget()}
            >
              {t("ssh.login.forget")}
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="field-grid two-column">
            <Field label={t("ssh.login.username")}>
              <input
                value={login.username}
                onChange={(e) => login.setUsername(e.target.value)}
                autoCapitalize="none"
              />
            </Field>
            <Field label={t("ssh.login.port")}>
              <input
                value={login.port}
                onChange={(e) => login.setPort(e.target.value)}
                inputMode="numeric"
              />
            </Field>
          </div>
          <fieldset className="auth-method">
            <legend>{t("ssh.login.method")}</legend>
            <div className="segmented-control">
              {(["password", "agent", "private_key"] as const)
                .filter((value) => !isAndroid || value !== "agent").map((value) => (
                <button
                  key={value}
                  type="button"
                  aria-pressed={login.auth === value}
                  onClick={() => login.setAuth(value)}
                >
                  {t(authLabels[value])}
                </button>
              ))}
            </div>
          </fieldset>
          {login.auth === "private_key" && (
            <div className="field-grid two-column key-fields">
              <Field label={t("ssh.login.keyPath")} error={isAndroid && pickerError ? pickerError : undefined}>
                {isAndroid ? <button type="button" className="secondary-button" onClick={() => { setPickerError(""); void open({ multiple: false }).then(path => { if (typeof path === "string") login.setKeyPath(path); }).catch(reason => setPickerError(errorMessage(reason, t("ssh.error.picker")))); }}>{login.keyPath ? t("ssh.login.changeKey") : t("ssh.login.chooseKey")}</button> : <input value={login.keyPath} onChange={(e) => login.setKeyPath(e.target.value)} placeholder={t("ssh.login.keyPathPlaceholder")} />}
              </Field>
              <Field label={t("ssh.login.keyPassphrase")} hint={t("ssh.login.keyPassphraseHint")}>
                <SecretInput
                  type="password"
                  value={login.keyPassphrase}
                  onChange={(e) => login.setKeyPassphrase(e.target.value)}
                  autoComplete="off"
                />
              </Field>
            </div>
          )}
          {login.auth === "password" && (
            <Field label={t("ssh.login.password")}>
              <SecretInput
                type="password"
                value={login.password}
                onChange={(e) => login.setPassword(e.target.value)}
                autoComplete="off"
              />
            </Field>
          )}
          {login.username.trim() !== "root" && (
            <Field
              label={t("ssh.login.sudoPassword")}
              hint={t("ssh.login.sudoPasswordHint")}
            >
              <SecretInput
                type="password"
                value={login.sudoPassword}
                onChange={(e) => login.setSudoPassword(e.target.value)}
                autoComplete="off"
              />
            </Field>
          )}
          <ConfirmationRow checked={login.remember} onChange={login.setRemember}>
            <strong>{t("ssh.login.remember")}</strong>
            <small>{t("ssh.login.rememberNote")}</small>
          </ConfirmationRow>
          {login.saved && (
            <button type="button" className="text-button" onClick={login.reuse}>
              {t("ssh.login.useSaved")}
            </button>
          )}
        </>
      )}
      </fieldset>
    </div>
  );
}
