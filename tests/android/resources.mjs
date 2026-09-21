import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {writeFileSync} from 'node:fs';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';
const pkg='org.sirinvpn.client';
adb('root');adb('wait-for-device'); // Emulator process fault injection and /proc observation only.
await openApp();
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
const profiles=(await call('list_servers')).ok;assert.equal(profiles.length,1);
const p=profiles[0];assert.equal(p.name,'Android isolated VPS');assert.equal(p.endpoint.host,'10.0.2.2');
const preferences=(await call('get_connection_preferences',{serverId:p.id})).ok;
assert(!(await call('connect_server_with_policy',{serverId:p.id,preferences:{...preferences,transport:'direct_udp',manual_mtu:1420}})).error);
await delay(8000);
const pid=adb('shell','pidof',pkg+':vpn'),ui=adb('shell','pidof',pkg);
adb('shell','input','keyevent','KEYCODE_HOME');
try {adb('shell','kill','-9',ui)} catch {
  // Android can reclaim the UI itself as soon as Home makes it invisible.
  let current='';try {current=adb('shell','pidof',pkg)} catch {}
  assert.notEqual(current,ui,'The UI process could not be terminated');
}
const hz=Number(adb('shell','getconf','CLK_TCK'));assert(hz>0);
function usage() {
  const stat=adb('shell','run-as',pkg,'cat',`/proc/${pid}/stat`).split(') ')[1].split(' ');
  const status=adb('shell','run-as',pkg,'cat',`/proc/${pid}/status`);
  return {milliseconds:performance.now(),ticks:Number(stat[11])+Number(stat[12]),rssKiB:Number(status.match(/VmRSS:\s+(\d+)/)[1])};
}
const rows=[];
for(const active of [false,true]) {
  const before=usage();let traffic;
  if(active) traffic=spawn(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'shell','run-as',pkg,'/system/bin/ping','-n','-c','100','-i','0.2','-w','24',p.server_tunnel_address],{stdio:'ignore'});
  await delay(21000);const after=usage();
  if(traffic) {if(traffic.exitCode===null) await new Promise(resolve=>traffic.on('close',resolve));assert.equal(traffic.exitCode,0)}
  assert.equal(adb('shell','pidof',pkg+':vpn'),pid);
  const seconds=(after.milliseconds-before.milliseconds)/1000;
  rows.push({workload:active?'100 ordinary-UID private ICMP probes':'Connected; UI process absent',seconds,oneCoreCpuPercent:((after.ticks-before.ticks)/hz)/seconds*100,rssKiB:after.rssKiB});
}
writeFileSync(`target/android-evidence/resources-${serial}.json`,JSON.stringify({serial,scope:'Short emulator observation; no battery, throughput-capacity or physical-device claim',rows},null,2));
console.log('Recorded OS CPU/RSS with UI process absent, idle and during bounded ordinary-UID traffic.');
