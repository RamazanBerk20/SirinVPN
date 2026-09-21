import type { SavedSshLogin, SshLoginInput, WifiPolicySnapshot } from "./types";
import type { VpsReleaseInput, VpsBaselineAccess, VpsBaselineCandidate } from "./features/settings/vpsRelease";
import { Channel } from "@tauri-apps/api/core";
import { invoke, isAndroid, watchAndroidStatus, watchAndroidServerStatus } from "./platform";
import type { ConnectionPreferences } from "./features/connection/connectionPreferences";
import type {
  AppPreferences,
  NotificationPermission,
  PreferencesSnapshot,
} from "./features/settings/preferences";
import type {
  ClientPlatform,
  CurrentConfiguration,
  DiagnosticReport,
  EndpointTransitionResult,
  EndpointUpdateCodeResult,
  InvitationResult,
  KeyRotationResult,
  LocalTunnelStatus,
  SshHostInspection,
  MembershipSnapshot,
  NetworkProfile,
  PortForwardProtocol,
  ProvisionInput,
  ProvisionResult,
  NetworkPreflight,
  TransportSetup,
  RepairInput,
  RepairResult,
  ReleaseUpdateCandidate,
  ReleaseUpdateStatus,
  ReleaseUpdateChannel,
  ServerBackupResult,
  ServerProfile,
  ServerRestoreResult,
  ServerStatus,
  ServerStatusEvent,
  TransportPreference,
  TunnelRoutingPolicy,
  UninstallInput,
  VpsBackupInput,
  VpsRestoreInput,
} from "./types";

export const api = {
  watchLocalStatus: (onEvent: (event: import("./types").LocalStatusEvent) => void): (() => void) => {
    if (isAndroid) return watchAndroidStatus(onEvent);
    const subscriptionId = crypto.randomUUID();
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const start = (): Promise<void> => {
      const channel = new Channel<import("./types").LocalStatusEvent>();
      channel.onmessage = event => { if (active) onEvent(event); };
      return invoke<void>("subscribe_local_status", { subscriptionId, onEvent: channel }).catch(() => {
        if (!active) return;
        onEvent({ status: null, sequence: 0, generation: 0, phase: "unknown", stale: true });
        timer = setTimeout(() => { ready = start(); }, 1_000);
      });
    };
    let ready = start();
    return () => {
      active = false; clearTimeout(timer);
      void ready.then(() => invoke<void>("unsubscribe_local_status", { subscriptionId })).catch(() => {});
    };
  },
  localComponentUpdateStatus: () => invoke<{ install_available: boolean; update_required: boolean }>("local_component_update_status"),
  installLocalVpnComponent: () => invoke<LocalTunnelStatus>("install_local_vpn_component", { confirmed: true }),
  launchVpnApplication: (serverId: string, executable: string, args: string[]) =>
    invoke<{ process_id: number | null; completed: boolean }>("launch_vpn_application", { serverId, executable, arguments: args }),
  prepareVpsBaseline: (input: VpsBaselineAccess & { source: string; channel: "stable" | "preview" }) => invoke<VpsBaselineCandidate>("prepare_vps_baseline", { input }),
  installVpsBaseline: (input: VpsBaselineAccess & { manifest_sha256: string }) => invoke<unknown>("install_vps_baseline", { input }),
  discardVpsBaseline: (serverId: string) => invoke<void>("discard_vps_baseline", { serverId }),
  manageVpsRelease: <T>(input: VpsReleaseInput) => invoke<T>("manage_vps_release", { input }),
  inspectServerNetwork: (input: { ssh: SshLoginInput; transport: TransportSetup; endpoint_discovery_port?: number }) =>
    invoke<NetworkPreflight>("inspect_server_network", { input }),
  getWifiPolicy: () => invoke<WifiPolicySnapshot>("get_wifi_policy"),
  setWifiPolicy: (policy: WifiPolicySnapshot["policy"]) => invoke<void>("set_wifi_policy", { policy }),
  trustCurrentWifi: (expectedNetworkToken: string, label: string) => invoke<void>("trust_current_wifi", { expectedNetworkToken, label }),
  forgetTrustedWifi: (id: string) => invoke<void>("forget_trusted_wifi", { id }),
  getConnectionPreferences: (serverId: string) =>
    invoke<ConnectionPreferences>("get_connection_preferences", { serverId }),
  setConnectionPreferences: (
    serverId: string,
    preferences: ConnectionPreferences,
  ) =>
    invoke<ConnectionPreferences>("set_connection_preferences", {
      serverId,
      preferences,
    }),
  getAppPreferences: () => invoke<PreferencesSnapshot>("get_app_preferences"),
  setAppPreferences: (preferences: AppPreferences) =>
    invoke<PreferencesSnapshot>("set_app_preferences", { preferences }),
  requestNotificationPermission: () =>
    invoke<NotificationPermission>("request_notification_permission"),
  testNotification: () => invoke<void>("test_notification"),
  clientPlatform: () => invoke<ClientPlatform>("client_platform"),
  checkReleaseUpdate: (source: string, channel: ReleaseUpdateChannel) =>
    invoke<ReleaseUpdateCandidate>("check_release_update", {
      input: { source, channel },
    }),
  installReleaseUpdate: (confirmed: boolean, baselineOnly = false) =>
    invoke<ReleaseUpdateCandidate>("install_release_update", {
      input: { confirmed, ...(isAndroid ? { baseline_only: baselineOnly } : {}) },
    }),
  discardReleaseUpdate: () => invoke<void>("discard_release_update"),
  releaseUpdateStatus: () => invoke<ReleaseUpdateStatus>("get_release_update_status"),
  rollbackReleaseUpdate: (expectedVersion: string) => invoke<void>("rollback_release_update", {
    input: { confirmed: true, expected_version: expectedVersion },
  }),
  updateServerPresentation: (
    serverId: string,
    name: string | null,
    favorite: boolean | null,
  ) => invoke<void>("update_server_presentation", { serverId, name, favorite }),
  listServers: () => invoke<ServerProfile[]>("list_servers"),
  probeHostKey: (host: string, port: number) =>
    invoke<string>("probe_host_key", { input: { host, port } }),
  inspectSshHost: (host: string, port: number) =>
    invoke<SshHostInspection>("inspect_ssh_host", { input: { host, port } }),
  trustSshHost: (host: string, port: number, fingerprint: string) =>
    invoke<void>("trust_ssh_host", { input: { host, port }, fingerprint }),
  getSshLogin: (host: string) =>
    invoke<SavedSshLogin | null>("get_ssh_login", { host }),
  saveSshLogin: (input: SshLoginInput) =>
    invoke<SavedSshLogin>("save_ssh_login", { input }),
  forgetSshLogin: (host: string) => invoke<void>("forget_ssh_login", { host }),
  provisionServer: (input: ProvisionInput) =>
    invoke<ProvisionResult>("provision_server", { input }),
  removeServer: (serverId: string) =>
    invoke<void>("remove_server", { serverId }),
  exportServerBackup: (
    serverId: string,
    path: string,
    password: string,
    confirmed: boolean,
  ) =>
    invoke<void>("export_server_backup", {
      input: { server_id: serverId, path, password, confirmed },
    }),
  importServerBackup: (path: string, password: string) =>
    invoke<ServerProfile>("import_server_backup", {
      input: { path, password },
    }),
  exportVpsBackup: (input: VpsBackupInput) =>
    invoke<ServerBackupResult>("export_vps_backup", { input }),
  restoreVpsBackup: (input: VpsRestoreInput) =>
    invoke<ServerRestoreResult>("restore_vps_backup", { input }),
  uninstallServer: (input: UninstallInput) =>
    invoke<void>("uninstall_server", { input }),
  repairServer: (input: RepairInput) =>
    invoke<RepairResult>("repair_server", { input }),
  createEndpointUpdate: (serverId: string) =>
    invoke<EndpointUpdateCodeResult>("create_endpoint_update", { serverId }),
  availableEndpointUpdate: (serverId: string) =>
    invoke<EndpointUpdateCodeResult | null>("available_endpoint_update", {
      serverId,
    }),
  applyEndpointUpdate: (serverId: string, code: string) =>
    invoke<EndpointTransitionResult>("apply_endpoint_update", {
      input: { server_id: serverId, code },
    }),
  publishEndpointUpdate: (serverId: string, code: string) =>
    invoke<EndpointTransitionResult>("publish_endpoint_update", {
      input: { server_id: serverId, code },
    }),
  keyRotationPending: (serverId: string) =>
    invoke<boolean>("key_rotation_pending", { serverId }),
  rotateDeviceKeys: (serverId: string, confirmed: boolean) =>
    invoke<KeyRotationResult>("rotate_device_keys", {
      input: { server_id: serverId, confirmed },
    }),
  connect: (
    serverId: string,
    persistentProtection: boolean,
    transport: TransportPreference,
    networkProfile: NetworkProfile,
    routing: TunnelRoutingPolicy,
  ) =>
    invoke<LocalTunnelStatus>("connect_server", {
      serverId,
      persistentProtection,
      transport,
      networkProfile,
      routing,
    }),
  connectWithPolicy: (serverId: string, preferences: ConnectionPreferences) =>
    invoke<LocalTunnelStatus>("connect_server_with_policy", {
      serverId,
      preferences,
    }),
  currentNetworkProfile: () =>
    invoke<NetworkProfile>("current_network_profile"),
  resume: (serverId: string) =>
    invoke<LocalTunnelStatus>("resume_server", { serverId }),
  disconnect: () => invoke<LocalTunnelStatus>("disconnect_server"),
  localStatus: () => invoke<LocalTunnelStatus>("local_status"),
  serverStatus: (serverId: string) =>
    invoke<ServerStatus>("server_status", { serverId }),
  watchServerStatus: (
    serverId: string,
    onEvent: (event: ServerStatusEvent) => void,
  ): (() => void) => {
    if (isAndroid) return watchAndroidServerStatus(serverId, onEvent);
    const subscriptionId = crypto.randomUUID();
    let active = true;
    let retry: ReturnType<typeof setTimeout> | undefined;
    const start = (): Promise<void> => {
      const channel = new Channel<ServerStatusEvent>();
      channel.onmessage = (event) => {
        if (active) onEvent(event);
      };
      return invoke<void>("subscribe_server_status", {
        serverId,
        subscriptionId,
        onEvent: channel,
      }).catch(() => {
        if (!active) return;
        onEvent({ kind: "state", state: "reconnecting" });
        retry = setTimeout(() => {
          ready = start();
        }, 2_000);
      });
    };
    let ready = start();
    return () => {
      active = false;
      clearTimeout(retry);
      // A slow subscription acknowledgement must not arrive after its cancellation.
      void ready
        .then(() =>
          invoke<void>("unsubscribe_server_status", { subscriptionId }),
        )
        .catch(() => {});
    };
  },
  serverConfiguration: (serverId: string) =>
    invoke<CurrentConfiguration>("server_configuration", { serverId }),
  diagnostics: (serverId: string) =>
    invoke<DiagnosticReport>("run_diagnostics", { serverId }),
  membership: (serverId: string) =>
    invoke<MembershipSnapshot>("membership", { serverId }),
  recoverySettings: (serverId: string) => invoke<import("./types").RecoverySettings>("recovery_settings", { serverId }),
  updateRecoveryPolicy: (serverId: string, administratorMemberIds: string[]) => invoke<import("./types").RecoverySettings>("update_recovery_policy", { serverId, administratorMemberIds }),
  createRecoveryKey: (serverId: string, replaceRecoveryId: string | null, confirmed: boolean) => invoke<import("./types").RecoveryKeyOutput>("create_recovery_key", { input: { server_id: serverId, replace_recovery_id: replaceRecoveryId, confirmed } }),
  revokeRecoveryKey: (serverId: string, recoveryId: string) => invoke<import("./types").RecoverySettings>("revoke_recovery_key", { serverId, recoveryId }),
  previewRecoveryKey: (key: string) => invoke<import("./types").RecoveryPreview>("preview_recovery_key", { input: { key } }),
  recoverOwnerAccess: (key: string, deviceName: string, confirmed: boolean, replaceExisting: boolean) => invoke<ServerProfile>("recover_owner_access", { input: { key, device_name: deviceName, confirmed, replace_existing: replaceExisting } }),
  exportRecoveryPackage: (key: string, path: string, password: string, confirmed: boolean) => invoke<void>("export_recovery_package", { input: { key, path, password, confirmed } }),
  importRecoveryPackage: (path: string, password: string) => invoke<import("./types").RecoveryKeyOutput>("import_recovery_package", { input: { path, password } }),
  createInvitation: (
    serverId: string,
    memberName: string,
    deviceName: string,
    expiresInSeconds: number,
    targetMemberId: string | null = null,
    administrator = false,
    maxUses = 1,
    memberPolicy?: import("./types").MemberPolicy,
    recipientNames = true,
  ) =>
    invoke<InvitationResult>("create_invitation", {
      input: {
        server_id: serverId,
        member_name: memberName,
        device_name: deviceName,
        target_member_id: targetMemberId,
        administrator,
        max_uses: maxUses,
        member_policy: memberPolicy,
        expires_in_seconds: expiresInSeconds,
        recipient_names: recipientNames,
      },
    }),
  cancelInvitation: (serverId: string, invitationId: string) =>
    invoke<void>("cancel_invitation", { serverId, invitationId }),
  updateMemberPolicy: (serverId: string, memberId: string, policy: import("./types").MemberPolicy) =>
    invoke<MembershipSnapshot>("update_member_policy", { input: { server_id: serverId, member_id: memberId, policy } }),
  renameDevice: (serverId: string, deviceId: string, name: string) =>
    invoke<MembershipSnapshot>("rename_device", {
      input: { server_id: serverId, device_id: deviceId, name },
    }),
  revokeDevice: (serverId: string, deviceId: string) =>
    invoke<MembershipSnapshot>("revoke_device", { serverId, deviceId }),
  updateDevicePeerCommunication: (
    serverId: string,
    deviceId: string,
    enabled: boolean,
  ) =>
    invoke<MembershipSnapshot>("update_device_peer_communication", {
      input: { server_id: serverId, device_id: deviceId, enabled },
    }),
  createPortForward: (
    serverId: string,
    protocol: PortForwardProtocol,
    publicPort: number,
    deviceId: string,
    devicePort: number,
  ) =>
    invoke<MembershipSnapshot>("create_port_forward", {
      input: {
        server_id: serverId,
        protocol,
        public_port: publicPort,
        device_id: deviceId,
        device_port: devicePort,
        confirmed: true,
      },
    }),
  removePortForward: (
    serverId: string,
    protocol: PortForwardProtocol,
    publicPort: number,
  ) =>
    invoke<MembershipSnapshot>("remove_port_forward", {
      input: { server_id: serverId, protocol, public_port: publicPort },
    }),
  updateMemberAccess: (
    serverId: string,
    memberId: string,
    administrator: boolean,
  ) =>
    invoke<MembershipSnapshot>("update_member_access", {
      input: { server_id: serverId, member_id: memberId, administrator },
    }),
  updateMemberSuspension: (
    serverId: string,
    memberId: string,
    suspended: boolean,
  ) =>
    invoke<MembershipSnapshot>("update_member_suspension", {
      input: { server_id: serverId, member_id: memberId, suspended },
    }),
  revokeMemberDevices: (
    serverId: string,
    memberId: string,
    confirmed: boolean,
  ) =>
    invoke<MembershipSnapshot>("revoke_member_devices", {
      input: { server_id: serverId, member_id: memberId, confirmed },
    }),
  transferOwnership: (serverId: string, destinationDeviceId: string) =>
    invoke<MembershipSnapshot>("transfer_ownership", {
      input: {
        server_id: serverId,
        destination_device_id: destinationDeviceId,
        confirmed: true,
      },
    }),
  previewInvitation: (code: string) => invoke<import("./types").InvitationPreview>("preview_invitation", { code }),
  joinServer: (code: string, names: import("./types").InvitationNames = {}) =>
    invoke<ServerProfile>("join_server", { input: { code, ...names } }),
};
