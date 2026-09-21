import { useCallback, useEffect, useRef, useState } from "react";
import { useConnectionPreferences } from "./useConnectionPreferences";
import type { MaintenanceOperation } from "./MaintenanceReview";
import type { StatusFreshness } from "../../hooks/useDesktopStatus";
import { resolveAccess } from "../../access";
import { api } from "../../api";
import {
  type DiagnosticReport,
  type LocalTunnelStatus,
  type NetworkProfile,
  type ServerProfile,
  type ServerStatus,
  type TransportPreference,
  type TunnelRoutingMode,
} from "../../types";
import { errorMessage } from "../../lib/errors";
import { clearMembershipCache } from "../devices/membershipCache";

export function useServerWorkspace({
  profile,
  localStatus,
  serverStatus,
  freshness,
  onRefresh,
  onAccessChanged,
  onRemoved,
}: {
  profile: ServerProfile;
  localStatus: LocalTunnelStatus;
  serverStatus: ServerStatus | null;
  freshness: StatusFreshness;
  trafficUpdates?: import("../../hooks/trafficStore").TrafficStore<LocalTunnelStatus>;
  onRefresh: (status?: LocalTunnelStatus) => Promise<void>;
  onAccessChanged: () => Promise<void>;
  onRemoved: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [connectionOperation, setConnectionOperation] = useState<"connecting" | "disconnecting" | null>(null);
  const connectionGeneration = useRef(0);
  useEffect(() => () => { ++connectionGeneration.current; }, []);
  const [maintenanceReview, setMaintenanceReview] =
    useState<MaintenanceOperation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [diagnostics, setDiagnostics] = useState<DiagnosticReport | null>(null);
  const [diagnosticsOpen, setDiagnosticsOpenState] = useState(false);
  const diagnosticGeneration = useRef(0);
  const setDiagnosticsOpen = useCallback((open: boolean) => {
    if (!open) { diagnosticGeneration.current += 1; setDiagnostics(null); }
    setDiagnosticsOpenState(open);
  }, []);
  useEffect(() => {
    diagnosticGeneration.current += 1;
    setDiagnostics(null); setDiagnosticsOpenState(false);
    return () => { diagnosticGeneration.current += 1; };
  }, [profile.id]);
  const [backupOpen, setBackupOpen] = useState(false);
  const [vpsBackupOpen, setVpsBackupOpen] = useState(false);
  const [vpsRestoreOpen, setVpsRestoreOpen] = useState(false);
  const [repairIntent, setRepairIntent] = useState<"repair" | "update" | "dns">(
    "repair",
  );
  const [repairOpen, setRepairOpen] = useState(false);
  const [rotationOpen, setRotationOpen] = useState(false);
  const [endpointUpdateOpen, setEndpointUpdateOpen] = useState(false);
  const [rotationPending, setRotationPending] = useState(true);
  const [removeOpen, setRemoveOpen] = useState(false);
  const preferences = useConnectionPreferences(profile.id);
  const connectionPolicy = preferences.draft.policy;
  const selectedTransport = preferences.draft.transport;
  const selectedNetworkProfile = preferences.draft.network_profile;
  const routingMode = preferences.draft.routing.mode;
  const allowLan = preferences.draft.routing.allow_lan;
  const includedRoutesDraft = preferences.routesText;
  const includedRoutes = includedRoutesDraft.split(/[\s,]+/).filter(Boolean);
  const setConnectionPolicy = (
    key: keyof typeof connectionPolicy,
    value: boolean,
  ) => preferences.change({ policy: { ...connectionPolicy, [key]: value } });
  const setSelectedTransport = (value: TransportPreference) =>
    preferences.change({ transport: value });
  const setSelectedNetworkProfile = (value: NetworkProfile) =>
    preferences.change({ network_profile: value });
  const setRoutingMode = (mode: TunnelRoutingMode) =>
    preferences.route({ mode });
  const setAllowLan = (allow_lan: boolean) => preferences.route({ allow_lan });
  const setIncludedRoutesDraft = preferences.setRoutesText;
  const connected =
    localStatus.server_id === profile.id && localStatus.state === "connected";
  const reconnecting =
    localStatus.server_id === profile.id &&
    !localStatus.waiting_for_user &&
    localStatus.auto_reconnect_enabled &&
    (localStatus.state === "connecting" || localStatus.state === "degraded");
  const protectedConnection =
    localStatus.state !== "unknown" &&
    localStatus.server_id === profile.id &&
    (localStatus.kill_switch_state === "armed" ||
      localStatus.kill_switch_state === "blocking");
  const splitConnection =
    localStatus.server_id === profile.id &&
    localStatus.routing_mode === "selected_routes";
  const localKnown = localStatus.state !== "unknown";
  const active =
    localKnown &&
    localStatus.server_id === profile.id &&
    localStatus.state !== "disconnected";
  const anotherConnected =
    localStatus.server_id !== null && localStatus.server_id !== profile.id;
  const { level: accessLevel, canManage: canManageAccess } = resolveAccess(
    profile,
    serverStatus,
    connected,
  );
  const liveServerMetrics =
    serverStatus !== null &&
    [
      serverStatus.cpu_usage_basis_points,
      serverStatus.memory_used_bytes,
      serverStatus.memory_total_bytes,
      serverStatus.rx_bytes_per_second,
      serverStatus.tx_bytes_per_second,
    ].some((value) => value !== undefined);
  const sampledMetric = (
    value: number | undefined,
    format: (value: number | undefined) => string,
  ) => {
    if (!serverStatus) return "Unavailable";
    if (!liveServerMetrics) return "Update server";
    return value === undefined ? "Sampling" : format(value);
  };

  const refreshRotationPending = useCallback(async () => {
    try {
      setRotationPending(await api.keyRotationPending(profile.id));
    } catch {
      setRotationPending(true);
    }
  }, [profile.id]);

  useEffect(() => {
    void refreshRotationPending();
  }, [refreshRotationPending]);

  const toggle = async () => {
    if (!localKnown || busy || anotherConnected) return;
    if (
      !active &&
      (!preferences.ready || preferences.dirty || preferences.saving)
    ) {
      setError(
        preferences.dirty
          ? "Save or discard your connection preferences in Settings before connecting."
          : "Load saved connection preferences in Settings before connecting.",
      );
      return;
    }
    setBusy(true);
    const request = ++connectionGeneration.current;
    setConnectionOperation(active ? "disconnecting" : "connecting");
    setError(null);
    try {
      if (active) clearMembershipCache();
      const status = active ? await api.disconnect() : await api.connectWithPolicy(
          profile.id,
          preferences.saved ?? preferences.draft,
        );
      if (request !== connectionGeneration.current) return;
      await onRefresh(status);
    } catch (reason) {
      if (request !== connectionGeneration.current) return;
      const fallback =
        "The network change did not complete. Refresh the connection state before trying again.";
      setError(errorMessage(reason, fallback));
      await onRefresh();
    } finally {
      if (request === connectionGeneration.current) { setBusy(false); setConnectionOperation(null); }
    }
  };

  const cancelConnection = async () => {
    if (connectionOperation === "disconnecting") return;
    const request = ++connectionGeneration.current;
    setBusy(true); setConnectionOperation("disconnecting"); setError(null);
    clearMembershipCache();
    try {
      const status = await api.disconnect();
      if (request === connectionGeneration.current) await onRefresh(status);
    } catch (reason) {
      if (request === connectionGeneration.current) {
        setError(errorMessage(reason, "The VPN has not confirmed that it stopped. Check its current status."));
        await onRefresh();
      }
    } finally {
      if (request === connectionGeneration.current) { setBusy(false); setConnectionOperation(null); }
    }
  };

  const resume = async () => {
    if (busy || !localStatus.waiting_for_user) return;
    setBusy(true);
    setError(null);
    try {
      await api.resume(profile.id);
    } catch (reason) {
      setError(
        errorMessage(
          reason,
          "Could not resume. The current traffic policy was retained.",
        ),
      );
    } finally {
      await onRefresh();
      setBusy(false);
    }
  };

  const runDiagnostics = async () => {
    const request = ++diagnosticGeneration.current;
    setDiagnosticsOpen(true);
    setDiagnostics(null);
    try {
      const report = await api.diagnostics(profile.id);
      if (request === diagnosticGeneration.current) setDiagnostics(report);
    } catch {
      if (request !== diagnosticGeneration.current) return;
      setDiagnostics({
        api_version: "v1",
        checks: [
          {
            code: "local_diagnostics_unavailable",
            label: "Current diagnostics",
            level: "fail",
            message: "The diagnostic request could not complete. Refresh local connection state and try again. An unavailable report does not establish a tunnel or certificate failure.",
          },
        ],
      });
    }
  };

  return {
    connectionOperation,
    cancelConnection,
    maintenanceReview,
    setMaintenanceReview,
    busy,
    preferences,
    error,
    clearConnectionError: () => setError(null),
    diagnostics,
    diagnosticsOpen,
    setDiagnosticsOpen,
    backupOpen,
    setBackupOpen,
    vpsBackupOpen,
    setVpsBackupOpen,
    vpsRestoreOpen,
    setVpsRestoreOpen,
    repairIntent,
    setRepairIntent,
    repairOpen,
    setRepairOpen,
    rotationOpen,
    setRotationOpen,
    endpointUpdateOpen,
    setEndpointUpdateOpen,
    rotationPending,
    removeOpen,
    setRemoveOpen,
    connectionPolicy,
    setConnectionPolicy,
    selectedTransport,
    setSelectedTransport,
    selectedNetworkProfile,
    setSelectedNetworkProfile,
    routingMode,
    setRoutingMode,
    includedRoutesDraft,
    setIncludedRoutesDraft,
    allowLan,
    setAllowLan,
    includedRoutes,
    connected,
    reconnecting,
    protectedConnection,
    splitConnection,
    active,
    anotherConnected,
    accessLevel,
    canManageAccess,
    localKnown,
    freshness,
    liveServerMetrics,
    sampledMetric,
    refreshRotationPending,
    toggle,
    resume,
    runDiagnostics,
    profile,
    localStatus,
    serverStatus,
    onRefresh,
    onAccessChanged,
    onRemoved,
  };
}

export type ServerWorkspaceModel = ReturnType<typeof useServerWorkspace>;
