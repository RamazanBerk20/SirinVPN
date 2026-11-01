import { InlineError } from "../../components/ui";
import type { useConnectionPreferences } from "./useConnectionPreferences";
import { preferenceDifferences } from "./connectionPreferences";
import type { LocalTunnelStatus } from "../../types";
import { formatList, t } from "../../i18n";
import { Rich } from "../../i18n/Rich";

export function PreferenceSaveBar({
  preferences,
  local,
  serverId,
}: {
  preferences: ReturnType<typeof useConnectionPreferences>;
  local?: LocalTunnelStatus;
  serverId?: string;
}) {
  // Until saved preferences load, the editors show PreferencesPending instead.
  if (!preferences.ready) return null;
  const pending =
    preferences.saved && local && serverId
      ? preferenceDifferences(preferences.saved, local, serverId)
      : [];
  return (
    <div className={`connection-save-state${preferences.dirty ? " has-unsaved-preferences" : ""}`}>
      <div className="preference-save-bar">
        <span role="status">
          {preferences.saving
            ? t("common.state.saving")
            : preferences.dirty
              ? t("connection.saveBar.unsaved")
              : preferences.notice ||
                (preferences.ready
                  ? t("connection.saveBar.idle")
                  : t("common.state.loading"))}
        </span>
        {preferences.dirty && (
          <>
            <button
              className="text-button"
              disabled={preferences.saving}
              onClick={preferences.discard}
            >
              {t("connection.saveBar.discard")}
            </button>
            <button
              className="primary-button"
              disabled={preferences.saving || preferences.badRoutes.length > 0}
              onClick={() => void preferences.save()}
            >
              {t("connection.saveBar.save")}
            </button>
          </>
        )}
      </div>
      {preferences.error && (
        <>
          <InlineError message={preferences.error} />
          {!preferences.ready && (
            <button
              className="secondary-button"
              onClick={() => void preferences.reload()}
            >
              {t("common.action.retry")}
            </button>
          )}
        </>
      )}
      {/* Saved-but-not-live differences wait until the floating unsaved bar is gone, so it stays one line tall. */}
      {pending.length > 0 && !preferences.dirty && (
        <p className="pending-preferences">
          <Rich
            id="connection.saveBar.pending"
            params={{ differences: formatList(pending, "unit") }}
            tags={{ strong: (content) => <strong>{content}</strong> }}
          />
        </p>
      )}
    </div>
  );
}

/** Shown instead of a preference editor until the saved values load, so defaults never pose as saved settings. */
export function PreferencesPending({ preferences }: { preferences: ReturnType<typeof useConnectionPreferences> }) {
  return <section className="settings-card" aria-busy={!preferences.error}>
    {preferences.error ? <>
      <InlineError message={preferences.error} />
      <div className="settings-action-row"><button className="secondary-button" onClick={() => void preferences.reload()}>{t("common.action.retry")}</button></div>
    </> : <p role="status">{t("connection.preferences.loading")}</p>}
  </section>;
}
