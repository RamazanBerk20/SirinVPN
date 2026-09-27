// Only injected by the visual test runner. Never imported by the production app.
window.__sirinCommands = [];
window.__sirinCommandArguments = [];
let connectionPreferences = JSON.parse(localStorage.getItem("sirin-fixture-connection-preferences") || "{}");
const defaultConnectionPreferences = { transport:"automatic", network_profile:"automatic", policy:{kill_switch:false,automatic_reconnect:false,connect_on_startup:false}, routing:{mode:"full_tunnel", included_routes:[], allow_lan:false} };
let preferences = JSON.parse(localStorage.getItem("sirin-fixture-preferences") || "null") || {
  start_on_login: false, launch_minimized: false, close_to_tray: false, notifications: false, animations: true
};
const preferencesSnapshot = () => ({ preferences, startup_available: true,
  tray_available: true, notification_permission: "granted" });
const id = "123e4567-e89b-42d3-a456-426614174000";
const member = "223e4567-e89b-42d3-a456-426614174000";
const device = "323e4567-e89b-42d3-a456-426614174000";
const profile = {
  schema_version: 1, id, name: "My private VPS", endpoint: { host: "vpn.example.com", wireguard_port: 51820 },
  client_tunnel_address: "10.77.0.2", server_tunnel_address: "10.77.0.1", role: "owner", member_id: member, device_id: device,
  ipv6_tunnel_enabled: false, identity_reference: "visual-fixture", server_wireguard_public_key: "fixture",
  pinned_server_certificate_pem: "fixture", client_management_certificate_pem: "fixture",
  obfuscated_udp: { port: 443, server_public_key: "fixture" }, tcp_fallback: { port: 443, server_public_key: "fixture" },
  tls_like: { port: 443, server_public_key: "fixture", certificate_sha256: "fixture" },
};
const sampleStarted = performance.now();
let connected = window.__sirinScenario !== "disconnected";
const local = () => ({state: connected ? "connected" : "disconnected", interface_name: "sirinvpn0", server_id: connected ? id : null,
  traffic_metrics_supported:true, mtu_detection_supported:true, endpoint_updates_supported:true, kill_switch_state:"off", byte_counters_available:connected, included_routes:[], counter_epoch: "fixture-session", tunnel_uptime_seconds: 4321 + Math.floor((performance.now() - sampleStarted) / 1000), rx_packets: 412890, tx_packets: 86712,
  rx_bytes: 234580992 + Math.floor((performance.now() - sampleStarted) * 100), tx_bytes: 35082421 + Math.floor((performance.now() - sampleStarted) * 20), ipv6_blocked: connected, ipv6_tunneled: false, kill_switch_enabled: false,
  auto_reconnect_enabled: false, transport_fallback_enabled: false, routing_mode: "full_tunnel", allow_lan: false, transport: connected ? "direct_udp" : null});
const remoteStatus = () => { if (window.__sirinRemoteFails) throw new Error("Management unavailable"); return {api_version:"v1",server_name:profile.name,connection_state:"connected",interface_up:true,dns_healthy:true,dns_upstream:{mode:"recursive"},transport:"direct_udp",peer_count:3,peer_activity_supported:true,recently_active_peer_count:2,rx_bytes:234580992,tx_bytes:35082421,uptime_seconds:3645234,disk_used_bytes:12600000000,disk_total_bytes:100000000000,rx_packets:12458392,tx_packets:8911732,cpu_usage_basis_points:1240,memory_used_bytes:450000000,memory_total_bytes:2000000000,rx_bytes_per_second:15675000,tx_bytes_per_second:5337500,caller_role:"owner",caller_administrator:false,caller_device_id:device,...(window.__sirinServerOverride || {})}; };
const statusSubscriptions = new Map();
const nativeCallbacks = new Map();
let nextCallback = 1;
window.__TAURI_INTERNALS__ = {
  transformCallback: (callback) => { const id = nextCallback++; nativeCallbacks.set(id, callback); return id; },
  unregisterCallback: (id) => nativeCallbacks.delete(id),
  invoke: async (command, args) => {
    window.__sirinCommands.push(command);
    window.__sirinCommandArguments.push({command, args});
    switch (command) {
      case "client_platform": return window.__sirinPlatform || "desktop";
      case "credential_storage": return {supported:false};
      case "get_connection_preferences": if (window.__sirinConnectionLoadFails) throw new Error("Saved connection preferences are unavailable"); return connectionPreferences[typeof args === "string" ? args : args.serverId] || defaultConnectionPreferences;
      case "set_connection_preferences": if (window.__sirinConnectionSaveFails) throw new Error("Connection preference save failed"); connectionPreferences[args.serverId] = args.preferences; localStorage.setItem("sirin-fixture-connection-preferences",JSON.stringify(connectionPreferences)); return args.preferences;
      case "get_app_preferences": return preferencesSnapshot();
      case "set_app_preferences": if (window.__sirinPreferenceFails) throw new Error("Preference save failed"); preferences = args.preferences; localStorage.setItem("sirin-fixture-preferences", JSON.stringify(preferences)); return preferencesSnapshot();
      case "request_notification_permission": return "granted";
      case "test_notification": return;
      case "list_servers": return window.__sirinScenario === "onboarding" ? [] : window.__sirinProfiles || [profile];
      case "update_server_presentation": if (args.name !== null) profile.name = args.name; if (args.favorite !== null) profile.favorite = args.favorite; return;
      case "local_status": if (window.__sirinLocalFails) throw new Error("Local status unavailable"); return { ...local(), ...(window.__sirinLocalOverride || {}) };
      case "subscribe_local_status": {
        let sequence = 0;
        const publish = () => args.onEvent.onmessage({generation:1,sequence:++sequence,
          stale:Boolean(window.__sirinLocalFails),status:{...local(),...(window.__sirinLocalOverride || {})}});
        statusSubscriptions.set(args.subscriptionId, setInterval(publish, 1000));
        publish(); return;
      }
      case "unsubscribe_local_status": clearInterval(statusSubscriptions.get(args.subscriptionId)); statusSubscriptions.delete(args.subscriptionId); return;
      case "local_component_update_status": return { install_available: true, update_required: !window.__sirinComponentUpdated };
      case "install_local_vpn_component":
        if (!args.confirmed || connected) throw new Error("Disconnect before updating the local VPN component.");
        window.__sirinComponentUpdated = true; return local();
      case "get_wifi_policy": return { policy: { enabled: false, server_id: id }, trusted_networks: [], current_network: "untrusted_wifi", can_trust_current: true, current_network_token: "synthetic-network", automation_status: "disabled" };
      case "current_network_profile": return "automatic";
      case "probe_host_key": return "SHA256:synthetic-onboarding-fingerprint";
      case "get_ssh_login":
        if (window.__sirinLoginDelay) await new Promise(resolve => setTimeout(resolve, window.__sirinLoginDelay));
        return window.__sirinSavedSshLogins?.[args.host] ?? null;
      case "save_ssh_login": {
        const login = { username: args.input.username, ssh_port: args.input.ssh_port, authentication: args.input.authentication, private_key_path: args.input.private_key_path };
        window.__sirinSavedSshLogins ??= {};
        window.__sirinSavedSshLogins[args.input.host] = login;
        return login;
      }
      case "forget_ssh_login": if (window.__sirinSavedSshLogins) delete window.__sirinSavedSshLogins[args.host]; return null;
      case "inspect_ssh_host": return { fingerprint: "SHA256:" + "A".repeat(43), status: window.__sirinSshTrust || "trusted" };
      case "trust_ssh_host": window.__sirinSshTrust = "trusted"; return;
      case "inspect_server_network": return { public_endpoint: args.input.ssh.host, endpoint_addresses: ["192.0.2.1"], ssh_local_address: null, exposure: "public_interface", assigned_addresses: [], required_ports: [{ protocol: "udp", port: 51820 }, { protocol: "udp", port: 443 }, { protocol: "tcp", port: 443 }], issues: [] };
      case "discard_vps_baseline": return;
      case "manage_vps_release":
        if (args.input.operation.action !== "status") throw new Error("Only release status is available in this visual fixture.");
        return { release: { installed: null, rollback_version: null, recovery_pending: false }, security_updates: { schema_version: 1, enabled: false, source: null, channel: "stable" }, automatic_outcome: "disabled", installed_binary_matches: false };
      case "repair_server": return { artifact_sha256: "synthetic-artifact", dns_upstream: { mode: "recursive" }, private_dns_records: [], events: [] };
      case "provision_server": return new Promise(() => {});
      case "key_rotation_pending": return false;
      case "subscribe_server_status": {
        const publish = async () => {
          try {
            const status = remoteStatus();
            args.onEvent.onmessage({kind:"status",status,mode:window.__sirinStreamMode || "live",management_latency_ms:null});
          } catch {
            args.onEvent.onmessage({kind:"state",state:"reconnecting"});
          }
        };
        const timer = setInterval(publish, 1000);
        statusSubscriptions.set(args.subscriptionId, timer);
        void publish();
        return;
      }
      case "unsubscribe_server_status": clearInterval(statusSubscriptions.get(args.subscriptionId)); statusSubscriptions.delete(args.subscriptionId); return;
      case "server_status": return remoteStatus();
      case "connect_server_with_policy":
      case "resume_server":
      case "connect_server": connected = true; return local();
      case "disconnect_server": connected = false; return local();
      case "server_configuration": return {port_forwarding_enabled:true};
      case "membership": if (window.__sirinMembership) return window.__sirinMembership; return {api_version:"v1",members:[{id:member,name:"You",role:"owner",administrator:false,devices:[{id:device,name:"My Linux desktop",identity_fingerprint:"SHA256:"+"A".repeat(43),client_tunnel_address:"10.77.0.2",peer_communication_enabled:false}]},{id:"guest",name:"Family",role:"member",administrator:false,devices:[{id:"phone",name:"Android phone",client_tunnel_address:"10.77.0.3",recent_handshake:true,peer_communication_enabled:false},{id:"laptop",name:"Work laptop",client_tunnel_address:"10.77.0.4",recent_handshake:false,peer_communication_enabled:false}]}],active_invitations:[],port_forwards:[]};
      case "discard_release_update": return;
      default: throw new Error("Unexpected visual fixture command: " + command);
    }
  }
};
