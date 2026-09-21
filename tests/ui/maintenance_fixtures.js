// Synthetic maintenance states. Loaded only by the visual/interaction tests.
window.__maintenance = {
  configured: false, enabled: false, source: "", version: "1.0.1", failSchedule: false,
  wifi: { policy: { enabled: true, server_id: id }, trusted_networks: [], current_network: "untrusted_wifi", can_trust_current: true, current_network_token: "network-one", automation_status: "session_active" },
};
window.__sirinLocalOverride = { supervisor_status_known: true, application_routing_supported: true,
  application_routing_backend: "linux_namespace", application_routing_ready: true, connection_control_supported: true,
  startup_service_enabled: false, transport_quality_supported: true,
  transport_quality: { sample: { transport: "direct_udp", probes_sent: 8, probes_received: 8, latency_micros: 27400, jitter_micros: 1200 }, selection: "observing", candidates_checked: 1 },
  mtu: { policy: { mode: "automatic" }, configured: 1420, suggested: 1360, outcome: "measured" },
};
const release = { release_version: "1.0.2", release_sequence: "2", channel: "stable", security_update: true,
  manifest_sha256: "c".repeat(64), artifact_sha256: "d".repeat(64), artifact_target: "x86_64-unknown-linux-gnu", artifact_size_bytes: 18000000,
  action: "upgrade", can_install: true, baseline_required: false };
const network = { public_endpoint: "vpn.example.com", endpoint_addresses: ["192.0.2.12"], ssh_local_address: "192.0.2.12", exposure: "public_interface",
  assigned_addresses: [{ interface: "eth0", address: "192.0.2.12", prefix_length: 24, public: true }],
  required_ports: [{ protocol: "udp", port: 51820 }, { protocol: "udp", port: 443 }, { protocol: "tcp", port: 443 }],
  issues: [{ code: "additional_firewall_tables", blocking: false, message: "Other firewall tables are present. SirinVPN preserves them; their presence alone does not indicate a conflict." },
    { code: "docker", blocking: false, message: "Docker networking is present. Existing container networking remains in place." }] };
const check = (code, label, level, message) => ({ code, label, level, message });
const diagnostics = { api_version: "v1", checks: [
  check("local_backend", "Local VPN service", "pass", "The native VPN service responded to the current status request."),
  check("local_tunnel", "Selected VPN connection", "pass", "The local VPN service reports an active tunnel for the selected server."),
  check("local_protection", "Current traffic protection", "pass", "The native service reports the kill switch armed for the active connection."),
  check("local_routes", "Configured VPN routing", "pass", "Full-tunnel routing is configured. Explicit local-network exceptions follow the saved policy."),
  check("dns_resolver_response", "VPS private resolver response", "pass", "Valid DNS response in 28 ms. No query history is retained."),
  ...Array.from({ length: 20 }, (_, i) => check(`dns_zone_${i}`, `VPS split DNS zone ${i + 1}`, "pass", "The resolver returned a valid DNS response.")),
  check("external_reachability", "Provider firewall and public reachability", "warning", "Local listeners cannot establish public reachability. If a transport fails, check the VPS provider firewall and configured public ports."),
] };
const originalInvoke = window.__TAURI_INTERNALS__.invoke;
window.__TAURI_INTERNALS__.invoke = async (command, args) => {
  const state = window.__maintenance;
  const handled = ["repair_server", "manage_vps_release", "prepare_vps_baseline", "install_vps_baseline", "run_diagnostics", "get_wifi_policy", "set_wifi_policy", "trust_current_wifi", "forget_trusted_wifi", "preview_recovery_key", "recover_owner_access"];
  if (!handled.includes(command)) return originalInvoke(command, args);
  window.__sirinCommands.push(command);
  window.__sirinCommandArguments.push({ command, args });
  if (command === "repair_server") {
    if (state.holdRepair) await new Promise(resolve => { window.__finishRepair = resolve; });
    return { artifact_sha256: "b".repeat(64), server_identity_fingerprint: "a".repeat(64), dns_upstream: { mode: "recursive" }, private_dns_records: [], network_preflight: network, events: [] };
  }
  if (command === "get_wifi_policy") return state.wifi;
  if (command === "set_wifi_policy") { state.wifi.policy = args.policy; return state.wifi; }
  if (command === "trust_current_wifi") { state.wifi.current_network = "trusted_wifi"; return state.wifi; }
  if (command === "forget_trusted_wifi") return;
  if (command === "run_diagnostics") return diagnostics;
  if (command === "preview_recovery_key") return { existing_profile: false, preview: { server_name: profile.name, host: profile.endpoint.host, server_identity_fingerprint: "a".repeat(64), recovery_id: "fixture-key" } };
  if (command === "recover_owner_access") { window.__sirinScenario = "disconnected"; return profile; }
  if (command === "prepare_vps_baseline") return { ...release, artifact: { sha256: release.artifact_sha256, target: release.artifact_target, size_bytes: release.artifact_size_bytes } };
  if (command === "install_vps_baseline") { state.configured = true; state.version = release.release_version; return; }
  const op = args.input.operation;
  if (op.action === "check") return { ...release, baseline_required: !state.configured, action: state.configured ? "upgrade" : "initialize" };
  if (op.action === "install") { state.configured = true; state.version = release.release_version; return; }
  if (op.action === "configure") {
    if (state.failSchedule) throw new Error("The VPS could not save the schedule.");
    state.enabled = op.enabled; if (op.source) state.source = op.source;
  }
  return { release: { installed: state.configured ? { active_release_version: state.version, active_release_sequence: "1", highest_accepted_release_sequence: "1", channel: "stable", active_artifact: { sha256: "a".repeat(64), target: release.artifact_target } } : null,
    rollback_version: state.configured ? "1.0.0" : null, recovery_pending: false },
    security_updates: { schema_version: 1, enabled: state.enabled, source: state.source || null, channel: "stable" }, automatic_outcome: "disabled", installed_binary_matches: state.configured };
};
