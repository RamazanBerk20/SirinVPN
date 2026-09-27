export type ServerId = string;
export type ClientPlatform = "desktop" | "android";
export type ReleaseUpdateChannel = "stable" | "preview";
export interface ReleaseUpdateStatus {
  installer_kind: "debian" | "windows" | "appimage" | "android";
  rollback_version: string | null;
  baseline_required: boolean;
  pending_version?: string | null;
}

export interface ReleaseUpdateCandidate {
  current_version: string;
  release_version: string;
  release_sequence: string;
  channel: ReleaseUpdateChannel;
  security_update: boolean;
  trust_policy_sequence: string;
  root_key_id_sha256: string;
  release_key_id_sha256: string;
  artifact_file_name: string;
  artifact_target: string;
  artifact_size_bytes: number;
  artifact_sha256: string;
  newer_than_running: boolean;
  debian_install_available: boolean;
  windows_install_available?: boolean;
  appimage_install_available?: boolean;
  android_install_available?: boolean;
  baseline_bind_available?: boolean;
  baseline_bound?: boolean;
  installer_kind?: "debian" | "windows" | "appimage" | "android";
}

export interface LocalStatusEvent {
  operation?: { command: string; phase: string } | null;
  status: LocalTunnelStatus | null;
  sequence: number;
  generation: number;
  phase: string;
  stale: boolean;
}

export interface ServerProfile {
  alternate_endpoint_hosts?: string[];
  endpoint_discovery_port?: number;
  favorite?: boolean;
  schema_version: number;
  id: ServerId;
  name: string;
  endpoint: {
    host: string;
    wireguard_port: number;
  };
  endpoint_generation?: number;
  pending_previous_endpoint?: {
    host: string;
    wireguard_port: number;
  };
  client_tunnel_address: string;
  server_tunnel_address: string;
  server_wireguard_public_key: string;
  pinned_server_certificate_pem: string;
  client_management_certificate_pem: string;
  identity_reference: string;
  role: "owner" | "member";
  administrator?: boolean;
  member_id?: string;
  device_id?: string;
  ipv6_tunnel_enabled?: boolean;
  obfuscated_udp?: {
    port: number;
    server_public_key: string;
  };
  tcp_fallback?: {
    port: number;
    server_public_key: string;
  };
  tls_like?: {
    port: number;
    server_public_key: string;
    certificate_sha256: string;
    https?: HttpsTransport | null;
  };
}

export type ConnectionState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "degraded"
  | "unknown";
export type TransportKind =
  | "direct_udp"
  | "obfuscated_udp"
  | "tls_like"
  | "tcp_fallback";
export type TransportPreference = "automatic" | TransportKind;
export type NetworkProfile = "automatic" | "normal" | "restricted" | "extreme";
export type TunnelRoutingMode = "full_tunnel" | "selected_routes" | "selected_applications";

export interface TunnelRoutingPolicy {
  mode: TunnelRoutingMode;
  included_routes: string[];
  allow_lan: boolean;
}

export interface DnsOverTlsEndpoint {
  address: string;
  authentication_name: string;
}

export interface DnsOverHttpsEndpoint {
  address: string;
  authentication_name: string;
  path: string;
}

export type DnsUpstream =
  | { mode: "recursive" }
  | { mode: "dns_over_tls"; endpoints: DnsOverTlsEndpoint[] }
  | { mode: "dns_over_https"; endpoints: DnsOverHttpsEndpoint[] }
  | { mode: "split"; default: DnsUpstream; zones: DnsSplitZone[] };

export interface DnsSplitZone {
  suffix: string;
  upstream: { mode: "private"; addresses: string[] } | { mode: "dns_over_tls"; endpoints: DnsOverTlsEndpoint[] };
  allow_unsigned_answers: boolean;
}

export interface PrivateDnsRecord {
  name: string;
  address: string;
}

export interface ConnectionPolicy {
  kill_switch: boolean;
  automatic_reconnect: boolean;
  connect_on_startup: boolean;
}

export interface WifiPolicySnapshot {
  policy: { enabled: boolean; server_id: string | null };
  trusted_networks: { id: string; label: string }[];
  current_network: "unavailable" | "other_network" | "trusted_wifi" | "untrusted_wifi";
  can_trust_current: boolean;
  current_network_token: string | null;
  permission_required?: boolean;
  location_enabled?: boolean;
  network_names?: Record<string, string>;
  automation_status: "disabled" | "waiting_for_wifi" | "trusted" | "connecting" | "session_active" | "waiting_for_network_change" | "needs_attention" | "needs_authorization";
}

export interface LocalTunnelStatus {
  always_on?: boolean;
  lockdown?: boolean;
  application_routing_backend?: "linux_namespace" | "windows_bind_redirect" | "android_packages";
  application_routing_supported?: boolean;
  application_routing_ready?: boolean;
  endpoint_updates_supported?: boolean;
  endpoint_checkpoint?: { claims: { server_id: string; generation: number } };
  transport_quality_supported?: boolean;
  transport_quality?: {
    isolated_measurement_supported?: boolean;
    last_switch_reason?: "confirmed_failure" | "quality_improvement" | "rollback";
    sample: { transport: TransportKind; probes_sent: number; probes_received: number; latency_micros: number; jitter_micros: number } | null;
    selection: "pending" | "observing" | "waiting_for_idle" | "comparing" | "selected" | "icmp_unavailable" | "protection_required";
    candidates_checked: number;
  } | null;
  mtu_detection_supported?: boolean;
  https_transport_supported?: boolean;
  mtu?: { policy: { mode: "automatic" } | { mode: "manual"; value: number }; configured: number; suggested: number | null; outcome: "pending" | "measured" | "icmp_unavailable" | "no_usable_mtu" | "apply_failed" } | null;
  /** Monotonic frontend observation time; never persisted or sent to the helper. */
  observed_at_ms?: number;
  connection_control_supported?: boolean;
  recovery_in_progress?: boolean;
  startup_service_enabled?: boolean;
  supervisor_status_known?: boolean;
  policy?: ConnectionPolicy;
  independent_policy_supported?: boolean;
  kill_switch_state?: "off" | "armed" | "blocking" | "failed" | "unknown";
  connect_on_startup?: boolean;
  waiting_for_user?: boolean;
  traffic_metrics_supported?: boolean;
  byte_counters_available?: boolean;
  included_routes?: string[];
  state: ConnectionState;
  interface_name: string;
  server_id: ServerId | null;
  rx_bytes: number;
  tx_bytes: number;
  rx_packets?: number;
  tx_packets?: number;
  tunnel_uptime_seconds?: number;
  counter_epoch?: string;
  /** Native monotonic time of the byte-counter reading, unchanged by status-only updates. */
  counter_sampled_at_ms?: number;
  rx_bytes_per_second?: number;
  tx_bytes_per_second?: number;
  ipv6_blocked: boolean;
  ipv6_tunneled?: boolean;
  transport?: TransportKind;
  kill_switch_enabled: boolean;
  auto_reconnect_enabled: boolean;
  transport_fallback_enabled: boolean;
  routing_mode?: TunnelRoutingMode;
  allow_lan?: boolean;
}

export interface SshHostInspection {
  fingerprint: string;
  status: "trusted" | "unknown" | "changed";
}

export interface ServerStatus {
  authorization_recovery?: {
    health: "healthy" | "applying" | "recovery_pending" | "recovery_failed";
    generation: number;
    containment_verified: boolean;
    committed: boolean;
  };
  api_version: string;
  server_name: string;
  connection_state: ConnectionState;
  interface_up: boolean;
  dns_healthy: boolean;
  dns_upstream?: DnsUpstream;
  private_dns_records?: PrivateDnsRecord[];
  transport: TransportKind;
  peer_count: number;
  peer_activity_supported?: boolean;
  recently_active_peer_count?: number;
  rx_bytes: number;
  tx_bytes: number;
  uptime_seconds: number;
  cpu_usage_basis_points?: number;
  memory_used_bytes?: number;
  memory_total_bytes?: number;
  rx_bytes_per_second?: number;
  tx_bytes_per_second?: number;
  disk_used_bytes?: number;
  disk_total_bytes?: number;
  rx_packets?: number;
  tx_packets?: number;
  management_latency_ms?: number;
  caller_role?: "owner" | "member";
  caller_administrator?: boolean;
  caller_device_id?: string;
  caller_identity_fingerprint?: string;
}

export type ServerStatusEvent =
  | {
      kind: "status";
      status: ServerStatus;
      mode: "live" | "polling";
      management_latency_ms: number | null;
    }
  | { kind: "state"; state: "connecting" | "reconnecting" };

export interface DiagnosticCheck {
  code: string;
  label: string;
  level: "pass" | "warning" | "fail";
  message: string;
}

export interface DiagnosticReport {
  api_version: string;
  checks: DiagnosticCheck[];
}

export interface ProvisionInput {
  name: string;
  host: string;
  username: string;
  ssh_port: number;
  authentication: "agent" | "password" | "private_key" | "saved";
  password: string | null;
  private_key_path: string | null;
  private_key_passphrase: string | null;
  sudo_password: string | null;
  host_key_sha256: string;
  replace_existing_installation: boolean;
  dns_upstream: DnsUpstream;
  private_dns_records: PrivateDnsRecord[];
  transport?: TransportSetup;
}

export interface UninstallInput {
  server_id: string;
  username: string;
  ssh_port: number;
  authentication: "agent" | "password" | "private_key" | "saved";
  password: string | null;
  private_key_path: string | null;
  private_key_passphrase: string | null;
  sudo_password: string | null;
  host_key_sha256: string;
}

export interface RepairInput extends UninstallInput {
  confirmed: boolean;
  dns_upstream: DnsUpstream | null;
  private_dns_records: PrivateDnsRecord[] | null;
  transport?: TransportSetup | null;
}

export interface VpsBackupInput extends UninstallInput {
  path: string;
  backup_password: string;
  confirmed: boolean;
}

export interface VpsRestoreInput extends UninstallInput {
  path: string;
  backup_password: string;
  host: string;
  replace_existing: boolean;
  confirmed: boolean;
}

export interface ServerBackupResult {
  server_id: string;
  artifact_sha256: string;
}

export interface ServerRestoreResult {
  network_preflight?: NetworkPreflight;
  events: InstallEvent[];
  profile: ServerProfile;
  artifact_sha256: string;
  dns_upstream: DnsUpstream;
  private_dns_records: PrivateDnsRecord[];
  replaced_existing_installation: boolean;
}

export interface InstallEvent {
  phase: string;
  message: string;
}

export interface ProvisionResult {
  network_preflight?: NetworkPreflight;
  profile: ServerProfile;
  events: InstallEvent[];
  dns_upstream: DnsUpstream;
  private_dns_records: PrivateDnsRecord[];
}

export interface NetworkPreflight {
  public_endpoint: string;
  endpoint_addresses: string[];
  ssh_local_address: string | null;
  exposure: "public_interface" | "nat_or_proxy" | "private_endpoint" | "unresolved";
  assigned_addresses: { interface: string; address: string; prefix_length: number; public: boolean }[];
  required_ports: { protocol: PortForwardProtocol; port: number }[];
  issues: { blocking: boolean; code: string; message: string }[];
}

export interface RepairResult {
  network_preflight?: NetworkPreflight;
  events: InstallEvent[];
  artifact_sha256: string;
  server_identity_fingerprint?: string;
  dns_upstream: DnsUpstream;
  private_dns_records: PrivateDnsRecord[];
}

export interface KeyRotationResult {
  rotation_id: string;
  server_id: string;
  device_id: string;
  identity_fingerprint: string;
  resumed: boolean;
}

export interface EndpointUpdateCodeResult {
  server_id: string;
  generation: number;
  previous_endpoint: {
    host: string;
    wireguard_port: number;
  };
  endpoint: {
    host: string;
    wireguard_port: number;
  };
  code: string;
}

export interface EndpointTransitionResult {
  server_id: string;
  generation: number;
  previous_endpoint: {
    host: string;
    wireguard_port: number;
  };
  endpoint: {
    host: string;
    wireguard_port: number;
  };
}

export interface DeviceSummary {
  id: string;
  member_id: string;
  name: string;
  client_tunnel_address: string;
  identity_fingerprint?: string;
  peer_communication_enabled?: boolean;
  recent_handshake?: boolean;
}

export interface MemberSummary {
  id: string;
  name: string;
  role: "owner" | "member";
  administrator?: boolean;
  suspended?: boolean;
  policy?: MemberPolicy;
  devices: DeviceSummary[];
}

export interface MemberPolicy {
  device_limit: number | null;
  expires_at_unix: number | null;
  weekly_access: { start_minute: number; end_minute: number }[];
  invite_members: boolean;
  add_own_devices: boolean;
  manage_own_peer_communication: boolean;
  manage_own_port_forwards: boolean;
}

export interface ActiveInvitationSummary {
  recipient_names?: boolean;
  id: string;
  member_name: string;
  device_name: string;
  target_member_id?: string;
  administrator?: boolean;
  expires_at_unix: number;
  max_uses?: number;
  uses_remaining?: number;
  member_policy?: MemberPolicy;
}

export type PortForwardProtocol = "tcp" | "udp";

export interface PortForward {
  protocol: PortForwardProtocol;
  public_port: number;
  device_id: string;
  device_port: number;
}

export interface CurrentConfiguration {
  port_forwarding_enabled?: boolean;
  member_lifecycle_enabled?: boolean;
  member_policies_enabled?: boolean;
  reusable_invitations_enabled?: boolean;
  recipient_names_enabled?: boolean;
  recovery_keys_enabled?: boolean;
}

export interface RecoverySettings {
  policy: { administrator_member_ids: string[] };
  key: { recovery_id: string; identity_fingerprint: string } | null;
  enrollment_finishing: boolean;
  can_issue_key: boolean;
}
export interface RecoveryKeyOutput { key: string; qr_svg: string; recovery_id: string }
export interface RecoveryPreview {
  preview: { server_id: string; server_name: string; host: string; recovery_id: string; server_identity_fingerprint: string };
  existing_profile: boolean;
}

export interface MembershipSnapshot {
  members: MemberSummary[];
  active_invitations: ActiveInvitationSummary[];
  port_forwards?: PortForward[];
}

export interface InvitationResult {
  invitation_id: string;
  expires_at_unix: number;
  code: string;
  qr_svg: string;
}

export type SshCredentials = Pick<
  UninstallInput,
  | "username"
  | "ssh_port"
  | "authentication"
  | "password"
  | "private_key_path"
  | "private_key_passphrase"
  | "sudo_password"
  | "host_key_sha256"
>;
export interface SshLoginInput extends SshCredentials {
  host: string;
}
export interface SavedSshLogin {
  username: string;
  ssh_port: number;
  authentication: "agent" | "password" | "private_key";
  private_key_path: string | null;
}

export interface HttpsTransport { server_name: string; path: string }
export interface TransportSetup {
  public_host: string | null;
  alternate_endpoint_hosts: string[];
  wireguard_port: number;
  obfuscated_udp_port: number;
  tcp_tls_port: number;
  https: HttpsTransport | null;
  https_certificate_path: string | null;
  https_private_key_path: string | null;
  disable_https: boolean;
}

export interface InvitationPreview {
  server_name: string; host: string; server_identity_fingerprint: string; expires_at_unix: number;
  recipient_names: boolean; creates_member: boolean; member_name: string; device_name: string; access_level: "owner" | "admin" | "member";
}
export interface InvitationNames { member_name?: string; device_name?: string; }
