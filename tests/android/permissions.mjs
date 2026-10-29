// Isolated emulator only. No real endpoint is contacted; permission tests use an invalid profile ID.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';
const pkg='org.sirinvpn.client',out='target/android-evidence/phone-polish';
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
async function start(command,args={}) {
  await evaluate(`(()=>{window.__permissionResult=null;window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}}).then(r=>window.__permissionResult=r);return true})()`);
  await delay(600);
}
async function result() {
  for(let i=0;i<40;i++){const value=await evaluate('window.__permissionResult');if(value)return value;await delay(250);}
  throw Error('Permission callback did not finish');
}
function nodes() {
  adb('shell','uiautomator','dump','/data/local/tmp/sirin-permissions.xml');
  return adb('exec-out','cat','/data/local/tmp/sirin-permissions.xml').match(/<node\b[^>]*>/g)??[];
}
function tap(suffix) {
  const node=nodes().find(n=>n.includes(':id/'+suffix+'"'));
  assert(node,'Expected Android permission control: '+suffix);
  const [l,t,r,b]=node.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/).slice(1).map(Number);
  adb('shell','input','tap',String((l+r)>>1),String((t+b)>>1));
}
function reset(permission) {
  adb('shell','pm','revoke',pkg,'android.permission.'+permission);
  adb('shell','pm','clear-permission-flags',pkg,'android.permission.'+permission,'user-set','user-fixed');
}
await openApp();
const state=(await call('android_snapshot')).ok;
assert(['disconnected','paused','failed'].includes(state.phase));
assert(!state.always_on,'Do not interrupt a VPN');
adb('shell','am','force-stop',pkg);
// Reset only our one-shot prompt marker, preserving all user preferences/profiles.
const file='shared_prefs/presentation.xml';
const prefs=adb('shell','run-as',pkg,'sh','-c',`if [ -f ${file} ]; then cat ${file}; fi`).replace(/\s*<boolean name="notification_permission_requested" value="(?:true|false)"\s*\/>/,'');
if(prefs)execFileSync(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'shell',`run-as ${pkg} sh -c 'cat > ${file}'`],{input:prefs});
reset('POST_NOTIFICATIONS');await openApp();
const invalid={serverId:'permission-test-missing-profile'};
await start('connect_server',invalid);tap('permission_deny_button');await delay(700);
// If this emulator has no prior VPN consent, decline that independent OS prompt.
if(nodes().some(n=>n.includes('com.android.vpndialogs')))tap('button2');
const denied=(await result()).error;
assert(denied,'The invalid profile or declined VPN consent must fail');
assert.doesNotMatch(denied,/notification/i,'Notification denial must continue to VPN consent/validation');
assert.equal((await call('get_app_preferences')).ok.notification_permission,'denied');
await start('connect_server',invalid);await delay(400);
assert(!nodes().some(n=>n.includes('permission_deny_button')),'Do not repeatedly request notifications');
if(nodes().some(n=>n.includes('com.android.vpndialogs')))tap('button2');
assert((await result()).error);
await call('disconnect_server');
await start('test_notification');tap('permission_allow_button');assert('ok' in await result());
assert.equal((await call('get_app_preferences')).ok.notification_permission,'granted');
assert.equal((await call('request_notification_permission')).ok,'granted');
assert(adb('shell','dumpsys','activity','activities').split('\n').some(line=>line.includes('ResumedActivity')&&line.includes(pkg+'/.MainActivity')),'An already granted request must leave the app in the foreground');
writeFileSync(out+'/permissions.json',JSON.stringify({serial,passed:true,notificationPromptOnFirstConnect:true,notificationDenialContinues:true,noRepeatedAutomaticPrompt:true,testNotificationRequestsPermission:true,grantedRequestDoesNotNeedSettings:true},null,2)+'\n');
console.log('PASS: notification first-connect/deny/retry/test flows.');
