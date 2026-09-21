import type { LocalTunnelStatus } from "../../types";
import { InlineError } from "../../components/ui";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

// Service enablement is a current, read-only platform observation. It is not
// inferred from a saved preference, and it does not promise a successful boot.
export function describeStartup(local: LocalTunnelStatus, serverId: string) {
  if (local.state === "unknown")
    return "Startup connection: status unknown. Refresh local status.";
  if (local.server_id && local.server_id !== serverId)
    return "Startup connection: saved for this server. Another server is currently active.";
  if (local.startup_service_enabled === undefined)
    return "Startup connection: saved; service status unavailable.";
  if (!local.startup_service_enabled)
    return "Startup connection: saved, not active.";
  if (local.server_id === serverId && local.connect_on_startup)
    return "Startup connection: active for this server.";
  return "Startup connection: service enabled; server not confirmed.";
}

export function StartupConnectionState({
  model,
}: {
  model: ServerWorkspaceModel;
}) {
  if (!model.preferences.saved?.policy.connect_on_startup) return null;
  const canActivate =
    model.localKnown &&
    !model.active &&
    !model.anotherConnected &&
    model.localStatus.startup_service_enabled === false;
  return (
    <div className="startup-connection-state">
      <p>{describeStartup(model.localStatus, model.profile.id)}</p>
      {canActivate && <p className="settings-note">Activate by connecting to {model.profile.name}.</p>}
      {canActivate && (
        <button
          className="secondary-button"
          disabled={
            model.busy || model.preferences.dirty || model.preferences.saving
          }
          onClick={() => void model.toggle()}
        >
          Connect & activate startup
        </button>
      )}
      {model.error && <InlineError message={model.error} />}
    </div>
  );
}
