import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';
const pkg='org.sirinvpn.client';
async function nodes() {
  // Reboot changes adbd from root to shell; discard any root-owned old dump.
  adb('shell','rm','-f','/data/local/tmp/sirin-reboot.xml');
  assert.match(adb('shell','uiautomator','dump','/data/local/tmp/sirin-reboot.xml'),/dumped/);
  return (adb('exec-out','cat','/data/local/tmp/sirin-reboot.xml').match(/<node\b[^>]*>/g)??[])
    .map(node=>Object.fromEntries([...node.matchAll(/([\w-]+)="([^"]*)"/g)].map(m=>[m[1],m[2]])));
}
async function tap(label) {
  let n;
  for(let i=0;i<10&&!n;i++) {n=(await nodes()).find(n=>n.text===label||n['content-desc']===label);if(!n)await delay(500)}
  assert(n,label);
  const [x,y,r,b]=n.bounds.match(/\d+/g).map(Number);adb('shell','input','tap',String((x+r)>>1),String((y+b)>>1));await delay(600);
}
async function alwaysOn(enabled) {
  adb('shell','am','start','-a','android.settings.VPN_SETTINGS','-f','0x10008000');await delay(700);
  if(!(await nodes()).some(n=>n.text==='Always-on VPN')) await tap('Settings');
  const list=await nodes(),index=list.findIndex(n=>n.text==='Always-on VPN');assert(index>=0);
  const control=list.slice(index).find(n=>n.checkable==='true');assert(control);
  if((control.checked==='true')!==enabled) await tap('Always-on VPN');
}
await openApp();
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
const profiles=(await call('list_servers')).ok;assert.equal(profiles.length,1);
const p=profiles[0];assert.equal(p.name,'Android isolated VPS');assert.equal(p.endpoint.host,'10.0.2.2');
assert(!(await call('connect_server',{serverId:p.id})).error);
const boot=adb('shell','cat','/proc/sys/kernel/random/boot_id');
try {
  await alwaysOn(true);adb('reboot');
  let ready=false;
  for(let n=0;n<60;n++) {
    await delay(1000);
    try {if(adb('shell','cat','/proc/sys/kernel/random/boot_id')!==boot && adb('shell','getprop','sys.boot_completed')==='1') {ready=true;break}} catch {}
  }
  assert(ready,'Emulator reboot did not complete');
  adb('shell','input','keyevent','KEYCODE_WAKEUP');adb('shell','wm','dismiss-keyguard');
  assert.notEqual(adb('shell','cat','/proc/sys/kernel/random/boot_id'),boot);
  adb('shell','wm','size','320x640');
  let replies='';
  for(let n=0;n<15;n++) {
    try {replies=adb('shell','run-as',pkg,'/system/bin/ping','-n','-c','2','-w','3',p.server_tunnel_address);if(/2 received/.test(replies))break} catch {}
    await delay(1000);
  }
  assert.match(replies,/2 received/);
  assert(!/ActivityRecord\{[^}]*org\.sirinvpn\.client\/.MainActivity/.test(adb('shell','dumpsys','activity','activities')));
  await openApp();
  for(let n=0;n<30 && (await call('android_snapshot')).ok.phase!=='connected';n++) await delay(500);
  assert.equal((await call('android_snapshot')).ok.phase,'connected');
  assert((await call('server_status',{serverId:p.id})).ok);
  writeFileSync(`target/android-evidence/reboot-${serial}.json`,JSON.stringify({serial,passed:true,systemAlwaysOn:true,newBoot:true,trafficBeforeMainActivity:true,pinnedManagement:true,limitation:'No device lock PIN configured; pre-unlock and OEM policies not established.'},null,2));
  console.log('System Always-on reconstructed the tunnel after a real reboot, before MainActivity.');
} catch(error) {console.error('Reboot verification failed:',error.message);throw error}
finally {await alwaysOn(false);await openApp()}
