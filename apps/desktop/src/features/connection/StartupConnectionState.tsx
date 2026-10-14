import type { LocalTunnelStatus } from "../../types";
import { InlineError } from "../../components/ui";
import type { ServerWorkspaceModel } from "./useServerWorkspace";
import { t } from "../../i18n";

// Service enablement is a current, read-only platform observation. It is not
// inferred from a saved preference, and it does not promise a successful boot.
export function describeStartup(local: LocalTunnelStatus, serverId: string) {
  if (local.state === "unknown")
    return t("connection.startup.unknown");
  if (local.server_id && local.server_id !== serverId)
    return t("connection.startup.otherServer");
  if (local.startup_service_enabled === undefined)
    return t("connection.startup.serviceUnknown");
  if (!local.startup_service_enabled)
    return t("connection.startup.inactive");
  if (local.server_id === serverId && local.connect_on_startup)
    return t("connection.startup.active");
  return t("connection.startup.unconfirmed");
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
      {canActivate && (
        <button
          className="secondary-button"
          disabled={
            model.busy || model.preferences.dirty || model.preferences.saving
          }
          onClick={() => void model.toggle()}
        >
          {t("connection.startup.activate")}
        </button>
      )}
      {model.error && <InlineError message={model.error} />}
    </div>
  );
}
