import * as D from './data';
import {exampleQr,recoveryQr} from './qr';
export class CatalogBridge {
  state:any = D.initialState();
  ready=false;
  prompts:any[]=[];
  originalDialogs={confirm:window.confirm.bind(window),prompt:window.prompt.bind(window),alert:window.alert.bind(window)};
  get role(){return this.state.remote.member_role==='owner'?'owner':this.state.remote.administrator?'admin':'member';}
  local(){return D.merge(this.state.local,this.state.connected?{}:{state:'disconnected',server_id:null,transport:null,byte_counters_available:false,rx_bytes:0,tx_bytes:0,counter_epoch:null,tunnel_uptime_seconds:null,ipv6_blocked:false});}
  watchLocal(callback:any){
    let sequence=0;
    const send=()=>{this.state.calls.push({name:'localStatus',args:[]});if(this.state.holds.includes('localStatus'))return;callback({status:this.local(),sequence:++sequence,generation:1,phase:this.state.connected?'connected':'disconnected',stale:!!this.state.errors.localStatus});};
    const first=window.setTimeout(send,0),timer=window.setInterval(send,500);
    return()=>{window.clearTimeout(first);window.clearInterval(timer);};
  }
  watch(_serverId:string,callback:any){
    const send=()=>{this.state.calls.push({name:'serverStatus',args:[_serverId]});if(this.state.errors.serverStatus){callback({kind:'state',state:'reconnecting'});return;}callback({kind:'status',status:D.clone(this.state.remote),mode:this.state.streamMode??'live',management_latency_ms:28});};
    const timer=window.setInterval(send,2000),first=window.setTimeout(send,20);return()=>{window.clearTimeout(first);window.clearInterval(timer);};
  }
  operationError(name:string) {
    if (/listServers|ListProfiles|SecurityStatus|IdentityStatus/.test(name)) return 'Protected local storage could not be opened. Unlock this device and retry.';
    if (/import|recover.*package/i.test(name)) return 'The encrypted file could not be opened. Check its password and file integrity.';
    if (/export|chooseSaveFile/i.test(name)) return 'The selected local destination could not be written. Choose another destination.';
    if (/Preferences|Presentation|Metadata/.test(name)) return 'Local preferences could not be saved. Check storage access and retry.';
    if (/Release|Baseline/.test(name)) return 'The requested package could not be verified. Check the release source and signature.';
    return 'The requested VPS operation could not complete. Check the connection and current server state before retrying.';
  }
  async native(command:string,args:any){
    if(command==='plugin:event|listen')return 1;
    if(command==='plugin:window|is_maximized')return !!this.state.maximized;
    if(command==='plugin:window|is_focused')return true;
    if(command==='plugin:window|inner_size')return{width:innerWidth,height:innerHeight};
    if(command==='plugin:window|scale_factor')return devicePixelRatio;
    if(command==='plugin:notification|is_permission_granted')return true;
    return null;
  }
  async call(name:string,args:any[]=[]):Promise<any>{
    const state=this.state;
    const previousOwner=state.members.members.find((member:any)=>member.role==='owner')?.id;
    const result=await this.dispatch(name,args);
    if(this.state!==state)return result;
    const fail=(condition:boolean,message:string)=>{if(!condition)(state.fixtureErrors??=[]).push(`${name}: ${message}`);};
    if(name==='transferOwnership'){
      const owner=state.members.members.find((member:any)=>member.devices.some((device:any)=>device.id===args[1]));
      fail(owner?.role==='owner','destination must become Owner');
      fail(state.members.members.filter((member:any)=>member.role==='owner').length===1,'exactly one Owner membership');
      const previous=state.members.members.find((member:any)=>member.id===previousOwner);
      fail(previous?.id===owner?.id || previous?.role==='member' && previous?.administrator===true,'previous Owner remains Admin');
      const caller=state.members.members.find((member:any)=>member.id===D.memberId);
      fail(state.remote.member_role===caller?.role && state.remote.administrator===caller?.administrator,'caller role must match refreshed management state');
    }
    if(name==='removePortForward')fail(!state.members.port_forwards.some((port:any)=>port.protocol===args[1] && port.public_port===args[2]),'requested port remains open');
    return result;
  }
  private async dispatch(name:string,args:any[]=[]):Promise<any>{
    const s=this.state;s.calls.push({name,args:D.clone(args)});
    if(s.holds.includes(name))return new Promise(()=>{});
    if(s.errors[name])throw new Error(s.errors[name] === 'The VPS could not be reached. Check the connection and try again.' ? this.operationError(name) : s.errors[name]);
    if(Object.prototype.hasOwnProperty.call(s.responses,name))return D.clone(s.responses[name]);
    switch(name){
      case 'clientPlatform':return s.platform;
      case 'listServers':return D.clone(s.profiles);
      case 'getAppPreferences':return D.clone(s.appPreferences);
      case 'setAppPreferences':s.appPreferences.preferences=args[0];return D.clone(s.appPreferences);
      case 'requestNotificationPermission':s.appPreferences.notification_permission='granted';return 'granted';
      case 'testNotification':return;
      case 'getConnectionPreferences':return D.clone(s.preferences);
      case 'setConnectionPreferences':s.preferences=args[1];return D.clone(s.preferences);
      case 'localStatus':return this.local();
      case 'serverStatus':return D.clone(s.remote);
      case 'currentNetworkProfile':return 'automatic';
      case 'serverConfiguration':return D.clone(s.configuration);
      case 'membership':return D.clone(s.members);
      case 'connect':case 'connectWithPolicy':case 'resume':s.connected=true;return this.local();
      case 'disconnect':s.connected=false;s.local.kill_switch_enabled=false;s.local.auto_reconnect_enabled=false;s.local.kill_switch_state='off';return this.local();
      case 'getWifiPolicy':return D.clone(s.wifi);
      case 'setWifiPolicy':s.wifi.policy=args[0];return;
      case 'trustCurrentWifi':s.wifi.trusted_networks=s.wifi.trusted_networks.filter((n:any)=>n.id!==args[0]);s.wifi.trusted_networks.push({id:args[0],label:args[1]});s.wifi.current_network='trusted_wifi';return;
      case 'forgetTrustedWifi':s.wifi.trusted_networks=s.wifi.trusted_networks.filter((n:any)=>n.id!==args[0]);if(s.wifi.current_network_token===args[0])s.wifi.current_network='untrusted_wifi';return;
      case 'localComponentUpdateStatus':return{install_available:true,update_required:s.componentUpdate};
      case 'installLocalVpnComponent':s.componentUpdate=false;return this.local();
      case 'keyRotationPending':return s.pendingRotation;
      case 'availableEndpointUpdate':return null;
      case 'inspectSshHost':return D.clone(s.sshInspection);
      case 'probeHostKey':return D.fingerprint;
      case 'trustSshHost':s.sshInspection.status='trusted';return;
      case 'getSshLogin':return D.clone(s.savedLogin);
      case 'saveSshLogin':s.savedLogin={...args[0],saved:true};return D.clone(s.savedLogin);
      case 'forgetSshLogin':s.savedLogin=null;return;
      case 'inspectServerNetwork':return D.clone(D.networkPreflight);
      case 'provisionServer':s.profiles=[D.clone(D.profile)];return{profile:D.clone(D.profile),events:[{message:'Server software installed and services verified.',step:'complete'}],network_preflight:D.clone(D.networkPreflight),dns_upstream:{mode:'recursive'},private_dns_records:[]};
      case 'repairServer':return D.clone(D.repair);
      case 'previewInvitation':return D.clone(s.invitationPreview);
      case 'joinServer':s.profiles=[{...D.clone(D.profile),role:'member'}];return D.clone(s.profiles[0]);
      case 'createInvitation':return{invitation_id:'example-invitation',expires_at_unix:Math.floor(Date.now()/1000)+(args[3]??3600),code:'sirin1.'+'SCREENSHOT-EXAMPLE-'.repeat(80),qr_svg:exampleQr};
      case 'cancelInvitation':s.members.active_invitations=[];return;
      case 'renameDevice':for(const m of s.members.members)for(const d of m.devices)if(d.id===args[1])d.name=args[2];return D.clone(s.members);
      case 'revokeDevice':for(const m of s.members.members)m.devices=m.devices.filter((d:any)=>d.id!==args[1]);return D.clone(s.members);
      case 'updateDevicePeerCommunication':for(const m of s.members.members)for(const d of m.devices)if(d.id===args[1])d.peer_communication_enabled=args[2];return D.clone(s.members);
      case 'updateMemberPolicy':for(const m of s.members.members)if(m.id===args[1])m.policy=args[2];return D.clone(s.members);
      case 'updateMemberAccess':for(const m of s.members.members)if(m.id===args[1])m.administrator=args[2];return D.clone(s.members);
      case 'updateMemberSuspension':for(const m of s.members.members)if(m.id===args[1])m.suspended=args[2];return D.clone(s.members);
      case 'revokeMemberDevices':for(const m of s.members.members)if(m.id===args[1])m.devices=[];return D.clone(s.members);
      case 'transferOwnership':{
        for(const m of s.members.members){if(m.devices.some((d:any)=>d.id===args[1])){m.role='owner';m.administrator=false;}else if(m.role==='owner'){m.role='member';m.administrator=true;}}
        const caller=s.members.members.find((member:any)=>member.id===D.memberId);
        if(caller){s.remote.member_role=caller.role;s.remote.administrator=caller.administrator;s.remote.caller_role=caller.role;s.remote.caller_administrator=caller.administrator;for(const profile of s.profiles){profile.role=caller.role;profile.administrator=caller.administrator;}}
        return D.clone(s.members);
      }
      case 'createPortForward':s.members.port_forwards.push({id:'example-port',protocol:args[1],public_port:args[2],device_id:args[3],device_port:args[4]});return D.clone(s.members);
      case 'removePortForward':s.members.port_forwards=s.members.port_forwards.filter((port:any)=>port.protocol!==args[1] || port.public_port!==args[2]);return D.clone(s.members);
      case 'chooseOpenFile':return s.fileOpen;
      case 'chooseSaveFile':return s.fileSave;
      case 'exportServerBackup':case 'exportRecoveryPackage':return;
      case 'importServerBackup':s.profiles=[D.clone(D.profile)];return D.clone(D.profile);
      case 'exportVpsBackup':return{server_id:D.id,server_name:D.profile.name,path:s.fileSave,bytes:18432,artifact_sha256:'a'.repeat(64),events:[]};
      case 'restoreVpsBackup':return{profile:D.clone(D.profile),server_id:D.id,server_name:D.profile.name,events:[],network_preflight:D.clone(D.networkPreflight),artifact_sha256:'a'.repeat(64),dns_upstream:{mode:'recursive'},private_dns_records:[],replaced_existing_installation:false,server_identity_fingerprint:D.fingerprint};
      case 'removeServer':case 'uninstallServer':s.profiles=[];return;
      case 'updateServerPresentation':s.profiles[0].name=args[1]??s.profiles[0].name;s.profiles[0].favorite=args[2]??s.profiles[0].favorite;return;
      case 'rotateDeviceKeys':s.pendingRotation=false;return{profile:D.clone(D.profile),server_id:D.id,device_id:D.deviceId,identity_fingerprint:D.fingerprint,reconnected:true};
      case 'createEndpointUpdate':return{code:'sirm1.'+'SIGNED-EXAMPLE-'.repeat(45),host:'new-vps.example.com',generation:2,server_id:D.id,previous_endpoint:D.clone(D.profile.endpoint),endpoint:{host:'new-vps.example.com',wireguard_port:51820},server_name:D.profile.name};
      case 'publishEndpointUpdate':case 'applyEndpointUpdate':return{profile:{...D.clone(D.profile),endpoint:{...D.profile.endpoint,host:'new-vps.example.com'}},reconnected:true,transport:'direct_udp'};
      case 'recoverySettings':case 'getRecoverySettings':return D.clone(s.recoverySettings);
      case 'updateRecoveryPolicy':s.recoverySettings.policy.administrator_member_ids=args[1];return D.clone(s.recoverySettings);
      case 'createRecoveryKey':s.recoverySettings.key={recovery_id:'example-recovery-key',identity_fingerprint:D.fingerprint};return{key:'sirr1.'+'RECOVERY-EXAMPLE-'.repeat(45),qr_svg:recoveryQr,recovery_id:'example-recovery-key'};
      case 'revokeRecoveryKey':s.recoverySettings.key=null;return D.clone(s.recoverySettings);
      case 'previewRecoveryKey':return{existing_profile:false,preview:{server_id:D.id,server_name:D.profile.name,host:D.profile.endpoint.host,recovery_id:'example-recovery-key',server_identity_fingerprint:D.fingerprint}};
      case 'recoverOwnerAccess':s.profiles=[D.clone(D.profile)];return D.clone(D.profile);
      case 'importRecoveryPackage':return this.call('createRecoveryKey',[]);
      case 'diagnostics':return D.clone(s.diagnostics);
      case 'discardVpsBaseline':case 'discardReleaseUpdate':return;
      case 'releaseUpdateStatus':return{installer_kind:s.releaseCandidate.installer_kind,rollback_version:s.releaseConfigured?'1.0.0':null,baseline_required:!s.releaseConfigured};
      case 'checkReleaseUpdate':return D.clone(s.releaseCandidate);
      case 'installReleaseUpdate':s.releaseConfigured=true;return {...D.clone(s.releaseCandidate),baseline_bound:!!s.releaseCandidate.baseline_bind_available};
      case 'rollbackReleaseUpdate':return;
      case 'prepareVpsBaseline':return{...D.clone(D.release),artifact:{sha256:D.release.artifact_sha256,target:D.release.artifact_target,size_bytes:D.release.artifact_size_bytes}};
      case 'installVpsBaseline':s.releaseConfigured=true;s.releaseVersion='1.0.2';return;
      case 'manageVpsRelease':{
        const op=args[0].operation;
        if(op.action==='check')return{...D.clone(D.release),baseline_required:!s.releaseConfigured,action:s.releaseConfigured?'upgrade':'initialize'};
        if(op.action==='install'){s.releaseConfigured=true;s.releaseVersion='1.0.2';}
        if(op.action==='configure'){s.releaseAutomatic=op.enabled;s.releaseSource=op.source??'';}
        if(op.action==='recover')s.releasePending=false;
        return{release:{installed:s.releaseConfigured?{active_release_version:s.releaseVersion,active_release_sequence:'1',highest_accepted_release_sequence:'1',channel:'stable',active_artifact:{sha256:'a'.repeat(64),target:D.release.artifact_target}}:null,rollback_version:s.releaseConfigured?'1.0.0':null,recovery_pending:s.releasePending},security_updates:{schema_version:1,enabled:s.releaseAutomatic,source:s.releaseSource||null,channel:'stable'},automatic_outcome:s.releaseAutomatic?'no_new_security_release':'disabled',installed_binary_matches:s.releaseMatches};
      }
      case 'launchVpnApplication':return{process_id:4242,completed:false};
      default:s.unknown.push(name);throw new Error('Screenshot fixture has no response for '+name);
    }
  }
}
