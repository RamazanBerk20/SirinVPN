import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
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
import { t } from "../../i18n";
import { disconnectTunnel, runCommand, usePendingCommand } from "./connectionCommands";
import { connectionView } from "./connectionView";
import { workspaceDialogReducer, type DialogKind, type RepairIntent } from "./workspaceDialog";

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
  const pending = usePendingCommand();
  const view = connectionView(localStatus, profile.id, pending);
  // One tunnel per device: any command in flight blocks every connect control.
  const busy = pending !== null;
  const connectionOperation = view.phase === "starting" && pending ? "connecting" as const : view.phase === "stopping" ? "disconnecting" as const : null;
  const connectionGeneration = useRef(0);
  useEffect(() => () => { ++connectionGeneration.current; }, []);
  const [error, setError] = useState<string | null>(null);
  const [dialog, dispatchDialog] = useReducer(workspaceDialogReducer, null);
  const diagnosticRequest = useRef(0);
  useEffect(() => { dispatchDialog({ type: "reset" }); }, [profile.id]);
  const dialogs = useMemo(() => {
    const flag = (kind: "troubleshoot" | "backup" | "vpsBackup" | "vpsRestore" | "vpsBackupSchedule" | "rotation" | "endpointUpdate" | "remove") =>
      (open: boolean) => dispatchDialog(open ? { type: "open", dialog: { kind } } : { type: "close", kind });
    return {
      setTroubleshootOpen: flag("troubleshoot"), setBackupOpen: flag("backup"), setVpsBackupOpen: flag("vpsBackup"),
      setVpsRestoreOpen: flag("vpsRestore"), setVpsBackupScheduleOpen: flag("vpsBackupSchedule"), setRotationOpen: flag("rotation"),
      setEndpointUpdateOpen: flag("endpointUpdate"), setRemoveOpen: flag("remove"),
      setMaintenanceReview: (operation: MaintenanceOperation | null) =>
        dispatchDialog(operation ? { type: "open", dialog: { kind: "review", operation } } : { type: "close", kind: "review" }),
      openRepair: (intent: RepairIntent) => dispatchDialog({ type: "open", dialog: { kind: "repair", intent } }),
      setRepairOpen: (open: boolean) => { if (!open) dispatchDialog({ type: "close", kind: "repair" }); },
      setDiagnosticsOpen: (open: boolean) => { if (!open) dispatchDialog({ type: "close", kind: "diagnostics" }); },
    };
  }, []);
  const is = (kind: DialogKind) => dialog?.kind === kind;
  const [rotationPending, setRotationPending] = useState(true);
  const [presharedKeyMissing, setPresharedKeyMissing] = useState(false);
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
  const reconnecting = view.phase === "reconnecting";
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
    if (!serverStatus) return t("common.state.unavailable");
    if (!liveServerMetrics) return t("maintenance.workspace.metric.needsUpdate");
    return value === undefined ? t("maintenance.workspace.metric.sampling") : format(value);
  };

  // Maintenance treats an unknown answer as pending; Home only reports a confirmed one.
  const [rotationPendingConfirmed, setRotationPendingConfirmed] = useState(false);
  const refreshRotationPending = useCallback(async () => {
    try {
      const pending = await api.keyRotationPending(profile.id);
      setRotationPending(pending);
      setRotationPendingConfirmed(pending);
    } catch {
      setRotationPending(true);
      setRotationPendingConfirmed(false);
    }
  }, [profile.id]);

  useEffect(() => {
    void refreshRotationPending();
  }, [refreshRotationPending]);

  // Only offers rotation; it reconnects and can need recovery, so it never runs unasked.
  useEffect(() => {
    setPresharedKeyMissing(false);
    if (!connected || rotationPending) return;
    let current = true;
    api.presharedKeyRotationRecommended(profile.id).then(
      (missing) => { if (current) setPresharedKeyMissing(missing); },
      () => undefined,
    );
    return () => { current = false; };
  }, [profile.id, connected, rotationPending]);

  const toggle = async () => {
    if (!localKnown || busy || anotherConnected) return;
    if (
      !active &&
      (!preferences.ready || preferences.dirty || preferences.saving)
    ) {
      setError(
        preferences.dirty
          ? t("maintenance.workspace.error.unsavedSettings")
          : t("maintenance.workspace.error.settingsNotLoaded"),
      );
      return;
    }
    const request = ++connectionGeneration.current;
    setError(null);
    try {
      const status = active ? await disconnectTunnel(profile.id) : await runCommand("connect", profile.id, () => api.connectWithPolicy(
          profile.id,
          preferences.saved ?? preferences.draft,
        ));
      if (request !== connectionGeneration.current) return;
      await onRefresh(status);
    } catch (reason) {
      if (request !== connectionGeneration.current) return;
      setError(errorMessage(reason, t("maintenance.workspace.error.connectionChange")));
      await onRefresh();
    }
  };

  const cancelConnection = async () => {
    if (connectionOperation === "disconnecting") return;
    const request = ++connectionGeneration.current;
    setError(null);
    try {
      const status = await disconnectTunnel(profile.id);
      if (request === connectionGeneration.current) await onRefresh(status);
    } catch (reason) {
      if (request === connectionGeneration.current) {
        setError(errorMessage(reason, t("maintenance.workspace.error.stopUnconfirmed")));
        await onRefresh();
      }
    }
  };

  const resume = async () => {
    if (busy || !localStatus.waiting_for_user) return;
    setError(null);
    try {
      await runCommand("resume", profile.id, async () => {
        try { await api.resume(profile.id); } finally { await onRefresh(); }
      });
    } catch (reason) {
      setError(errorMessage(reason, t("maintenance.workspace.error.resume")));
    }
  };

  const runDiagnostics = useCallback(async () => {
    const request = ++diagnosticRequest.current;
    dispatchDialog({ type: "open", dialog: { kind: "diagnostics", run: { state: "running", request } } });
    let report: DiagnosticReport | null = null;
    try { report = await api.diagnostics(profile.id); } catch { report = null; }
    dispatchDialog({ type: "diagnosticsFinished", request, report });
  }, [profile.id]);
  const run = dialog?.kind === "diagnostics" ? dialog.run : null;

  return {
    view,
    pending,
    connectionOperation,
    cancelConnection,
    dialog,
    ...dialogs,
    maintenanceReview: dialog?.kind === "review" ? dialog.operation : null,
    busy,
    preferences,
    error,
    clearConnectionError: () => setError(null),
    diagnostics: run?.state === "done" ? run.report : null,
    diagnosticsFailed: run?.state === "failed",
    diagnosticsOpen: is("diagnostics"),
    troubleshootOpen: is("troubleshoot"),
    backupOpen: is("backup"),
    vpsBackupOpen: is("vpsBackup"),
    vpsRestoreOpen: is("vpsRestore"),
    vpsBackupScheduleOpen: is("vpsBackupSchedule"),
    repairIntent: dialog?.kind === "repair" ? dialog.intent : null,
    rotationOpen: is("rotation"),
    endpointUpdateOpen: is("endpointUpdate"),
    rotationPending,
    presharedKeyMissing,
    rotationPendingConfirmed,
    setPresharedKeyMissing,
    removeOpen: is("remove"),
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
