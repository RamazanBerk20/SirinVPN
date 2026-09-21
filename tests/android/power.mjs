// Emulator-only screen-off/Doze evidence; this does not establish OEM behavior.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';
const pkg='org.sirinvpn.client';
await openApp();
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
const profiles=(await call('list_servers')).ok;
assert.equal(profiles.length,1,'Use a clean emulator containing only the disposable profile');
const profile=profiles[0];assert.equal(profile.name,'Android isolated VPS');assert.equal(profile.endpoint.host,'10.0.2.2');
const original=(await call('get_connection_preferences',{serverId:profile.id})).ok;
assert(!(await call('connect_server_with_policy',{serverId:profile.id,preferences:{...original,transport:'direct_udp',manual_mtu:1420}})).error);
const before=(await call('android_snapshot')).ok,pid=adb('shell','pidof',pkg+':vpn');
assert.equal(before.phase,'connected');
try {
  adb('shell','input','keyevent','KEYCODE_HOME');
  adb('shell','dumpsys','battery','unplug');
  adb('shell','input','keyevent','KEYCODE_SLEEP');
  adb('shell','dumpsys','deviceidle','force-idle');
  assert.match(adb('shell','dumpsys','deviceidle'),/mState=IDLE\b/);
  await delay(20000);
  assert.equal(adb('shell','pidof',pkg+':vpn'),pid);
  assert.match(adb('shell','run-as',pkg,'/system/bin/ping','-n','-c','3','-w','5',profile.server_tunnel_address),/3 received/);
} finally {
  adb('shell','dumpsys','deviceidle','unforce');
  adb('shell','dumpsys','battery','reset');
  adb('shell','input','keyevent','KEYCODE_WAKEUP');
  adb('shell','wm','dismiss-keyguard');
  await openApp();await call('set_connection_preferences',{serverId:profile.id,preferences:original});
}
await openApp();
const after=(await call('android_snapshot')).ok;
assert.equal(after.generation,before.generation);assert.equal(after.phase,'connected');
assert((await call('server_status',{serverId:profile.id})).ok);
writeFileSync(`target/android-evidence/power-${serial}.json`,JSON.stringify({serial,passed:true,screenOff:true,forcedDoze:true,observationSeconds:20,ordinaryUidReplies:3,sameServiceProcess:true,sameGeneration:true,pinnedManagement:true},null,2));
console.log('Screen-off and forced Doze retained the tunnel and passed ordinary-UID traffic.');
