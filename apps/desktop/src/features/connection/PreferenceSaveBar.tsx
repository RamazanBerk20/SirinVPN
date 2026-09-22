import { isAndroid } from "../../platform";
import { InlineError } from "../../components/ui";
import type { useConnectionPreferences } from "./useConnectionPreferences";
import { preferenceDifferences } from "./connectionPreferences";
import type { LocalTunnelStatus } from "../../types";

export function PreferenceSaveBar({
  preferences,
  local,
  serverId,
}: {
  preferences: ReturnType<typeof useConnectionPreferences>;
  local?: LocalTunnelStatus;
  serverId?: string;
}) {
  const pending =
    preferences.saved && local && serverId
      ? preferenceDifferences(preferences.saved, local, serverId)
      : [];
  return (
    <div className="connection-save-state">
      <div className="preference-save-bar">
        <span role="status">
          {preferences.saving
            ? "Saving…"
            : preferences.dirty
              ? "Unsaved connection preferences"
              : preferences.notice ||
                (preferences.ready
                  ? isAndroid ? "Reconnect applies immediately; other saved preferences apply on your next connection." : "Saved on this device. Applies when you next connect."
                  : "Loading connection preferences…")}
        </span>
        {preferences.dirty && (
          <>
            <button
              className="text-button"
              disabled={preferences.saving}
              onClick={preferences.discard}
            >
              Discard
            </button>
            <button
              className="primary-button"
              disabled={preferences.saving}
              onClick={() => void preferences.save()}
            >
              Save preferences
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
              Retry loading preferences
            </button>
          )}
        </>
      )}
      {pending.length > 0 && (
        <p className="pending-preferences">
          <strong>Saved for next connection.</strong> Current connection:{" "}
          {pending.join(" · ")}.
        </p>
      )}
    </div>
  );
}
