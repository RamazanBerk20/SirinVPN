import { InlineError } from "../../components/ui";
import type { useConnectionPreferences } from "./useConnectionPreferences";
import { preferenceDifferences } from "./connectionPreferences";
import type { LocalTunnelStatus } from "../../types";
import { formatList, t } from "../../i18n";
import { Rich } from "../../i18n/Rich";

/**
 * The page's one save-state line. It shows only when there is something to say: unsaved edits
 * (a floating bar with Discard and Save), a failed save, or saved values the live connection
 * doesn't use yet. A successful save is confirmed with a toast.
 */
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
  const invalid = preferences.badRoutes.length > 0 || preferences.mtuInvalid;
  if (!preferences.dirty && !preferences.error && !pending.length) return null;
  return (
    <div className={`connection-save-state${preferences.dirty ? " has-unsaved-preferences" : ""}`}>
      {preferences.dirty && <div className="preference-save-bar">
        <span role="status" className={invalid ? "field-error" : undefined}>
          {preferences.saving
            ? t("common.state.saving")
            : invalid ? t("connection.saveBar.invalid") : t("connection.saveBar.unsaved")}
        </span>
        <button
          className="text-button"
          disabled={preferences.saving}
          onClick={preferences.discard}
        >
          {t("connection.saveBar.discard")}
        </button>
        <button
          className="primary-button"
          disabled={preferences.saving || invalid}
          onClick={() => void preferences.save()}
        >
          {t("connection.saveBar.save")}
        </button>
      </div>}
      {preferences.error && <InlineError message={preferences.error} />}
      {/* Saved-but-not-live differences wait until the floating unsaved bar is gone, so it stays one line tall. */}
      {pending.length > 0 && !preferences.dirty && (
        <p className="pending-preferences" role="status">
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
    {preferences.error
      ? <InlineError message={preferences.error} onRetry={() => void preferences.reload()} />
      : <p role="status">{t("connection.preferences.loading")}</p>}
  </section>;
}
