// Fictional data for screenshot coverage. No production command or identity is used.
export const id = "123e4567-e89b-42d3-a456-426614174000";
export const memberId = "223e4567-e89b-42d3-a456-426614174000";
export const deviceId = "323e4567-e89b-42d3-a456-426614174000";
export const fingerprint = "SHA256:"+"A".repeat(43);
export const clone = <T,>(value:T):T => JSON.parse(JSON.stringify(value));
export function merge(base:any, extra:any):any {
  if (!extra || typeof extra !== "object" || Array.isArray(extra)) return extra === undefined ? base : extra;
  const next={...base}; for (const [key,value] of Object.entries(extra)) next[key]=value && typeof value==='object' && !Array.isArray(value) ? merge(next[key]??{},value) : value;
  return next;
}
export const policy = { device_limit:5, expires_at_unix:null, weekly_access:[], invite_members:false, add_own_devices:true, manage_own_peer_communication:false, manage_own_port_forwards:false };
export const profile = {schema_version:1,id,name:"My private VPS",favorite:true,endpoint:{host:"vpn.example.com",wireguard_port:51820},
  client_tunnel_address:"10.77.0.2",server_tunnel_address:"10.77.0.1",role:"owner",member_id:memberId,device_id:deviceId,
  ipv6_tunnel_enabled:false,identity_reference:"screenshot-fixture",server_wireguard_public_key:"public-screenshot-example",
  pinned_server_certificate_pem:"public-screenshot-example",client_management_certificate_pem:"public-screenshot-example",
  obfuscated_udp:{port:443,server_public_key:"public-screenshot-example"},tcp_fallback:{port:443,server_public_key:"public-screenshot-example"},
  tls_like:{port:443,server_public_key:"public-screenshot-example",certificate_sha256:"a".repeat(64)},
  endpoint_generation:1,alternate_endpoint_hosts:["backup.example.com"],endpoint_discovery_port:443};
export const connectionPreferences = {transport:"automatic",network_profile:"automatic",policy:{kill_switch:false,automatic_reconnect:false,connect_on_startup:false},routing:{mode:"full_tunnel",included_routes:[],allow_lan:false},manual_mtu:null};
export const transportSetup = {public_host:"vpn.example.com",alternate_endpoint_hosts:["backup.example.com"],wireguard_port:51820,obfuscated_udp_port:443,tcp_tls_port:443,https:null,https_certificate_path:null,https_private_key_path:null,disable_https:false};
export const local = {state:"connected",interface_name:"sirinvpn0",server_id:id,traffic_metrics_supported:true,mtu_detection_supported:true,endpoint_updates_supported:true,
  kill_switch_state:"off",byte_counters_available:true,included_routes:[],counter_epoch:"catalog-session",tunnel_uptime_seconds:4321,rx_packets:412890,tx_packets:86712,
  rx_bytes:234580992,tx_bytes:35082421,ipv6_blocked:true,ipv6_tunneled:false,kill_switch_enabled:false,auto_reconnect_enabled:false,transport_fallback_enabled:false,routing_mode:"full_tunnel",allow_lan:false,transport:"direct_udp",
  supervisor_status_known:true,application_routing_supported:true,application_routing_backend:"linux_namespace",application_routing_ready:true,connection_control_supported:true,startup_service_enabled:false,connect_on_startup:false,
  transport_quality_supported:true,transport_quality:{sample:{transport:"direct_udp",probes_sent:8,probes_received:8,latency_micros:27400,jitter_micros:1200},selection:"observing",candidates_checked:1},
  mtu:{policy:{mode:"automatic"},configured:1420,suggested:1360,outcome:"measured"}};
export const remote = {api_version:"v1",server_name:profile.name,connection_state:"connected",interface_up:true,dns_healthy:true,dns_upstream:{mode:"recursive"},transport:"direct_udp",peer_count:4,peer_activity_supported:true,recently_active_peer_count:2,rx_bytes:234580992,tx_bytes:35082421,uptime_seconds:3645234,disk_used_bytes:12600000000,disk_total_bytes:100000000000,rx_packets:12458392,tx_packets:8911732,cpu_usage_basis_points:1240,memory_used_bytes:450000000,memory_total_bytes:2000000000,rx_bytes_per_second:15675000,tx_bytes_per_second:5398000,peer_communication_enabled:true,member_role:"owner",administrator:false,caller_role:"owner",caller_administrator:false,caller_device_id:deviceId,caller_identity_fingerprint:fingerprint};
export const members = {api_version:"v1", members:[
  {id:memberId,name:"You",role:"owner",administrator:false,policy,devices:[{id:deviceId,name:"My Linux desktop",identity_fingerprint:fingerprint,client_tunnel_address:"10.77.0.2",peer_communication_enabled:false,recent_handshake:true}]},
  {id:"admin-member",name:"Morgan",role:"member",administrator:true,policy,devices:[{id:"admin-device",name:"Morgan’s laptop",identity_fingerprint:fingerprint,client_tunnel_address:"10.77.0.3",peer_communication_enabled:true,recent_handshake:true}]},
  {id:"family-member",name:"Family",role:"member",administrator:false,policy,devices:[{id:"phone-device",name:"Android phone",identity_fingerprint:fingerprint,client_tunnel_address:"10.77.0.4",peer_communication_enabled:false,recent_handshake:true},{id:"laptop-device",name:"Work laptop",identity_fingerprint:fingerprint,client_tunnel_address:"10.77.0.5",peer_communication_enabled:false,recent_handshake:false}]},
], active_invitations:[],port_forwards:[]};
export const networkPreflight={public_endpoint:"vpn.example.com",endpoint_addresses:["192.0.2.12"],ssh_local_address:"192.0.2.12",exposure:"public_interface",assigned_addresses:[{interface:"eth0",address:"192.0.2.12",prefix_length:24,public:true}],required_ports:[{protocol:"udp",port:51820},{protocol:"udp",port:443},{protocol:"tcp",port:443}],issues:[{code:"docker",blocking:false,message:"Docker networking is present. Existing container networking remains in place."}]};
export const repair={artifact_sha256:"b".repeat(64),server_identity_fingerprint:fingerprint,dns_upstream:{mode:"recursive"},private_dns_records:[],network_preflight:networkPreflight,events:[]};
export const invitationPreview={server_name:profile.name,host:profile.endpoint.host,server_identity_fingerprint:fingerprint,expires_at_unix:1900000000,recipient_names:true,creates_member:true,member_name:"Invited member",device_name:"New device",access_level:"member"};
export const release={release_version:"1.0.2",release_sequence:"2",channel:"stable",security_update:true,manifest_sha256:"c".repeat(64),artifact_sha256:"d".repeat(64),artifact_target:"x86_64-unknown-linux-gnu",artifact_size_bytes:18000000,action:"upgrade",can_install:true,baseline_required:false};
export const releaseCandidate={...release,current_version:"1.0.1",trust_policy_sequence:"1",root_key_id_sha256:"a".repeat(64),release_key_id_sha256:"b".repeat(64),artifact_file_name:"SirinVPN_1.0.2_amd64.deb",newer_than_running:true,debian_install_available:true,windows_install_available:false,appimage_install_available:false,baseline_bind_available:false,baseline_bound:true,installer_kind:"debian"};
export const check=(code:string,label:string,level:string,message:string)=>({code,label,level,message});
export const diagnostics={api_version:"v1",checks:[check("local_backend","Local VPN service","pass","The native VPN service responded to the current status request."),check("local_tunnel","Selected VPN connection","pass","The selected server has an active VPN tunnel."),check("local_protection","Current traffic protection","warning","The kill switch is off. Enable it in connection settings if traffic must remain blocked outside the VPN."),check("dns_resolver_response","VPS private resolver response","pass","Valid DNS response in 28 ms. No query history is retained."),check("external_reachability","Provider firewall and public reachability","warning","Local listeners cannot establish public reachability. Review the provider firewall if a transport fails.")]};
export function initialState(options:any={}) {
  const state:any={platform:"desktop",connected:options.connected!==false,profiles:[clone(profile)],preferences:clone(connectionPreferences),
    appPreferences:{preferences:{start_on_login:false,launch_minimized:false,close_to_tray:false,notifications:false,animations:false},startup_available:true,tray_available:true,notification_permission:"prompt"},
    local:clone(local),remote:clone(remote),members:clone(members),configuration:{port_forwarding_enabled:true,member_lifecycle_enabled:true,member_policies_enabled:true,reusable_invitations_enabled:true,recipient_names_enabled:true,recovery_keys_enabled:true},
    wifi:{policy:{enabled:false,server_id:id},trusted_networks:[],current_network:"untrusted_wifi",can_trust_current:true,current_network_token:"screenshot-network",network_names:{"screenshot-network":"Home hotspot"},automation_status:"disabled"},
    sshInspection:{host:"vpn.example.com",port:22,fingerprint,status:"unknown",previous_fingerprint:null},savedLogin:null,diagnostics:clone(diagnostics),invitationPreview:clone(invitationPreview),
    releaseCandidate:clone(releaseCandidate),releaseConfigured:false,releaseVersion:"1.0.1",releaseSource:"",releaseAutomatic:false,releasePending:false,releaseMatches:true,
    recoverySettings:{policy:{administrator_member_ids:[]},key:null,enrollment_finishing:false,can_issue_key:true},pendingRotation:false,pendingOwnerRecovery:null,errors:{},holds:[],responses:{},calls:[],unknown:[],
    fileOpen:"/home/demo/Documents/sirinvpn-device.sirinbackup",fileSave:"/home/demo/Documents/sirinvpn-device.sirinbackup",componentUpdate:false};
  if(options.empty){state.profiles=[];state.connected=false;}
  if(options.profile)state.profiles[0]=merge(state.profiles[0],options.profile);
  if(options.role==='admin'||options.role==='member'){state.profiles[0]&&(state.profiles[0].role='member');state.remote.member_role='member';state.remote.caller_role='member';state.remote.administrator=options.role==='admin';state.remote.caller_administrator=options.role==='admin';}
  if(options.profileCount){state.profiles=Array.from({length:options.profileCount},(_,i)=>({...clone(profile),id:i?id.slice(0,-2)+String(i).padStart(2,'0'):id,name:i?['Amsterdam VPS','Family network','Travel VPN'][((i-1)%3)]+(i>3?' '+i:''):profile.name,favorite:i<2}));}
  if(options.longNames){for(const p of state.profiles)p.name=('My private international travel and family network - '+p.name).slice(0,64).trim();}
  if(options.emptyMember)state.members.members[2].devices=[];
  if(options.suspendedMember)state.members.members[2].suspended=true;
  if(options.limitedMember)state.members.members[2].policy={...clone(policy),device_limit:2,expires_at_unix:1900000000,weekly_access:[{start_minute:540,end_minute:1020},{start_minute:1980,end_minute:2460}]};
  if(options.delegated){state.members.members[0].policy={...clone(policy),invite_members:true,manage_own_peer_communication:true,manage_own_port_forwards:true};}
  if(options.activeInvitation)state.members.active_invitations=[{id:'example-invitation',member_name:'Travel companion',device_name:'New phone',recipient_names:true,administrator:false,expires_at_unix:1900000000,max_uses:options.activeInvitation==='reusable'?10:1,uses_remaining:options.activeInvitation==='reusable'?7:1,...(options.activeInvitation==='device'?{target_member_id:'family-member',member_name:'Family'}:{}),member_policy:clone(policy)}];
  if(options.diagnosticPreset==='all-pass')state.diagnostics.checks=state.diagnostics.checks.map((c:any)=>({...c,level:'pass',message:'This check completed successfully.'}));
  if(options.diagnosticPreset==='failures')state.diagnostics.checks=[check('local_tunnel','Current VPN tunnel','fail','No authenticated handshake was observed. Reconnect, then run diagnostics again.'),check('dns_resolver_response','Private DNS resolver','fail','The private resolver did not respond.'),...state.diagnostics.checks.slice(2)];
  if(options.diagnosticPreset==='warnings-only')state.diagnostics.checks=state.diagnostics.checks.filter((c:any)=>c.level==='warning');
  if(options.diagnosticPreset==='empty')state.diagnostics.checks=[];
  return merge(state,options);
}
