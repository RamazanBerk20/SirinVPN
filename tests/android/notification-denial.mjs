// Uses only ordinary connection/traffic on an already-authorized Member profile.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';
const pkg='org.sirinvpn.client',permission='android.permission.POST_NOTIFICATIONS';
assert(Number(adb('shell','getprop','ro.build.version.sdk'))>=33);
const granted=adb('shell','dumpsys','package',pkg).includes(permission+': granted=true');
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}}).catch(e=>({error:String(e)}))`);
try {
  adb('shell','pm','revoke',pkg,permission);await delay(1200);await openApp();
  assert.equal((await call('get_app_preferences')).ok.notification_permission,'denied');
  const profiles=(await call('list_servers')).ok.filter(p=>p.role==='member'&&p.endpoint.host!=='10.0.2.2');
  assert.equal(profiles.length,1,'Requires exactly one already-authorized Member profile');
  const p=profiles[0],preferences=(await call('get_connection_preferences',{serverId:p.id})).ok;
  const connected=await call('connect_server_with_policy',{serverId:p.id,preferences:{...preferences,transport:'direct_udp',policy:{...preferences.policy,automatic_reconnect:false}}});
  assert(!connected.error,connected.error);
  await delay(1000);
  assert.equal((await call('android_snapshot')).ok.phase,'connected');
  assert.match(adb('shell','dumpsys','activity','services',pkg),/isForeground=true/);
  assert.match(adb('shell','run-as',pkg,'/system/bin/ping','-n','-c','3','-w','6',p.server_tunnel_address),/3 received/);
  assert((await call('server_status',{serverId:p.id})).ok);
  writeFileSync(`target/android-evidence/notification-denial-${serial}.json`,JSON.stringify({serial,passed:true,notificationPermissionDenied:true,foregroundServiceRetained:true,ordinaryUidReplies:3,pinnedManagement:true,scope:'Authorized Member connection only; no administration'},null,2));
  console.log('Notification permission denial preserves the foreground VPN and verified ordinary-UID traffic.');
} finally {
  try {await call('disconnect_server')} finally {if(granted)adb('shell','pm','grant',pkg,permission)}
}
