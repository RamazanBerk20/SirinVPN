import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { adb,delay,evaluate,openApp,serial } from './bridge.mjs';

const packageName='org.sirinvpn.client', rows=[];
// Debug emulator root is used only to observe kernel interfaces. Traffic runs as the app UID.
adb('root');adb('wait-for-device');
const tun=()=>/\btun\d+:/.test(adb('shell','ip','-o','link','show'));
const noActivity=()=>assert(!/ActivityRecord\{[^}]*org\.sirinvpn\.client\/.MainActivity/.test(adb('shell','dumpsys','activity','activities')),'Action opened the Activity');
async function waitTunnel(expected) {
  for(let n=0;n<60;n++) {if(tun()===expected) return;await delay(500);}
  throw Error('Kernel TUN state did not change');
}
async function tap(text) {
  adb('shell','uiautomator','dump','/data/local/tmp/sirin-controls.xml');
  const xml=adb('exec-out','cat','/data/local/tmp/sirin-controls.xml');
  const node=xml.match(/<node\b[^>]*>/g)?.find(n=>n.includes('clickable="true"') && (n.includes(`text="${text}"`) || n.includes(`content-desc="${text}"`)));
  assert(node,'Native control was not visible: '+text);
  const [x1,y1,x2,y2]=node.match(/bounds="([^"]+)"/)[1].match(/\d+/g).map(Number);
  adb('shell','input','tap',String((x1+x2)>>1),String((y1+y2)>>1));
  await delay(1200);
}
async function tile(label,connected) {
  adb('shell','cmd','statusbar','expand-settings');await delay(800);
  await tap('SirinVPN, '+label);await waitTunnel(connected);noActivity();
  adb('shell','cmd','statusbar','collapse');
  await delay(700);
}
function record(name,traffic=false) {
  rows.push({name,tunPresent:tun(),activityAbsent:true,privateTraffic:traffic});
  writeFileSync('target/android-evidence/native-controls.json',JSON.stringify({serial,rows},null,2));
}
adb('shell','cmd','statusbar','collapse');await openApp();
const before=await evaluate(`(async()=>{
  const call=(command,args={})=>window.__TAURI_INTERNALS__.invoke('android_call',{command,args});
  const s=(await call('android_snapshot')).ok;
  if(s.phase!=='connected') throw Error('Connect an authorized isolated test profile first');
  const profiles=(await call('list_servers')).ok;
  return {generation:s.generation,privateAddress:profiles.find(p=>p.id===s.status.server_id).server_tunnel_address};
})()`);
assert.match(before.privateAddress,/^10\./);
const traffic=()=>assert.match(adb('shell','run-as',packageName,'/system/bin/ping','-n','-c','2','-w','3',before.privateAddress),/2 received/);
adb('shell','input','keyevent','KEYCODE_APP_SWITCH');await delay(1200);
adb('shell','input','swipe','160','430','160','40','160');await delay(1800);
let ui;try {ui=adb('shell','pidof',packageName)} catch {} // Android may already reclaim the removed UI.
if(ui) adb('shell','run-as',packageName,'kill','-9',ui);
await delay(800);
noActivity();traffic();record('UI removed; UI process absent',true);
await tile('Connected',false);record('Tile disconnected');
await tile('Disconnected',true);await delay(3000);traffic();record('Tile connected without Activity',true);
adb('shell','cmd','statusbar','expand-notifications');await delay(800);
await tap('Disconnect');await waitTunnel(false);noActivity();record('Notification disconnected without Activity');
assert.match(adb('shell','dumpsys','window'),/mCurrentFocus=.*NotificationShade/,'Disconnect collapsed the notification panel');
adb('shell','cmd','statusbar','collapse');
await tile('Disconnected',true);await delay(3000);traffic();record('Tile reconnected after notification action',true);
await openApp();
const after=await evaluate(`(async()=>{const c=(command,args={})=>window.__TAURI_INTERNALS__.invoke('android_call',{command,args});
  const s=(await c('android_snapshot')).ok;return {phase:s.phase,generation:s.generation,managementResponded:!!(await c('server_status',{serverId:s.status.server_id})).ok};})()`);
assert.equal(after.phase,'connected');assert(after.managementResponded);assert(after.generation>before.generation);
console.log('Native tile and notification actions passed with no Activity and real private traffic.');
