import { isAndroid } from "../../platform";
import { open } from "../../lib/nativeDialog";
import { SecretInput } from "../../components/SecretInput";
import { Field, InlineError } from "../../components/ui";
import type { useSshLogin } from "../../hooks/useSshLogin";

export function SshLoginFields({
  login,
}: {
  login: ReturnType<typeof useSshLogin>;
}) {
  return (
    <div className="ssh-login-fields" aria-busy={login.loading}>
      <p className="ssh-login-status settings-note" role="status">
        {login.checkingSavedLogin ? "Checking for a saved SSH login…" : ""}
      </p>
      {login.error && <InlineError message={login.error} />}
      {login.error && !login.saved && (
        <button
          type="button"
          className="text-button"
          disabled={login.forgetting}
          onClick={() => void login.forget()}
        >
          Forget saved login
        </button>
      )}
      <fieldset className="ssh-login-content" disabled={login.loading || login.forgetting}>
      {login.usingSaved ? (
        <div className="saved-ssh-login">
          <div>
            <strong>Saved SSH login</strong>
            <p>
              {login.username} · port {login.port} ·{" "}
              {login.auth === "agent"
                ? "SSH agent"
                : login.auth === "private_key"
                  ? "Private key"
                  : "Password"}
            </p>
          </div>
          <div className="saved-ssh-actions">
            <button type="button" className="text-button" onClick={login.edit}>
              Change login
            </button>
            <button
              type="button"
              className="text-button"
              disabled={login.forgetting}
              onClick={() => void login.forget()}
            >
              Forget login
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="field-grid two-column">
            <Field label="SSH username">
              <input
                value={login.username}
                onChange={(e) => login.setUsername(e.target.value)}
                autoCapitalize="none"
              />
            </Field>
            <Field label="SSH port">
              <input
                value={login.port}
                onChange={(e) => login.setPort(e.target.value)}
                inputMode="numeric"
              />
            </Field>
          </div>
          <fieldset className="auth-method">
            <legend>Authentication</legend>
            <div className="segmented-control">
              {(
                [
                  ["password", "Password"],
                  ["agent", "SSH agent"],
                  ["private_key", "Private key"],
                ] as const
              ).filter(([value]) => !isAndroid || value !== "agent").map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  aria-pressed={login.auth === value}
                  onClick={() => login.setAuth(value)}
                >
                  {label}
                </button>
              ))}
            </div>
          </fieldset>
          {login.auth === "private_key" && (
            <div className="field-grid two-column key-fields">
              <Field label="Private key path">
                {isAndroid ? <button type="button" className="secondary-button" onClick={() => void open({ multiple: false }).then(path => { if (typeof path === "string") login.setKeyPath(path); })}>{login.keyPath ? "SSH key selected · Change" : "Choose SSH key"}</button> : <input value={login.keyPath} onChange={(e) => login.setKeyPath(e.target.value)} placeholder="/home/me/.ssh/vps" />}
              </Field>
              <Field label="Key passphrase" hint="Leave empty if unencrypted">
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
            <Field label="SSH password">
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
              label="sudo password"
              hint="Leave empty for passwordless sudo"
            >
              <SecretInput
                type="password"
                value={login.sudoPassword}
                onChange={(e) => login.setSudoPassword(e.target.value)}
                autoComplete="off"
              />
            </Field>
          )}
          <label className="replacement-option ssh-remember-option">
            <input
              type="checkbox"
              checked={login.remember}
              onChange={(e) => login.setRemember(e.target.checked)}
            />
            <span>
              <strong>Remember login on this device</strong>
              <small>
                Save in your secure credential store after SSH authentication succeeds.
                Reuse it for future VPS actions.
              </small>
            </span>
          </label>
          {login.saved && (
            <button type="button" className="text-button" onClick={login.reuse}>
              Use saved login
            </button>
          )}
        </>
      )}
      </fieldset>
    </div>
  );
}
