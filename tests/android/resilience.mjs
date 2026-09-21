import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { adb,delay,evaluate,openApp,serial } from './bridge.mjs';

const pkg='org.sirinvpn.client', rows=[];
const id=JSON.parse(adb('exec-out','run-as',pkg,'cat','no_backup/acceptance-vps-result.json')).server_id;
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
const state=async()=>{const response=await call('android_snapshot');assert(response.ok);return response.ok};
const pid=()=>adb('shell','pidof',pkg+':vpn');
function record(name,s,extra={}) {
  rows.push({name,phase:s.phase,generation:s.generation,privateTraffic:s.phase==='connected',...extra});
  writeFileSync('target/android-evidence/resilience.json',JSON.stringify({serial,fixture:'disposable local VPS',rows},null,2));
  console.log(name+': '+s.phase);
}
async function waitPhase(...phases) {
  for(let n=0;n<70;n++) {try {const s=await state();if(phases.includes(s.phase)) return s}catch{};await delay(500)}
  throw Error('Native controller did not reach '+phases.join('/'));
}
await openApp();
const profiles=(await call('list_servers')).ok,p=profiles.find(p=>p.id===id);
assert.equal(p.name,'Android isolated VPS');assert.equal(p.endpoint.host,'10.0.2.2');
const original=(await call('get_connection_preferences',{serverId:id})).ok;
const prefs={...original,policy:{...original.policy,automatic_reconnect:true}};
const traffic=()=>assert.match(adb('shell','run-as',pkg,'/system/bin/ping','-n','-c','2','-w','4',p.server_tunnel_address),/2 received/);
try {
  assert(!(await call('set_connection_preferences',{serverId:id,preferences:prefs})).error);
  assert(!(await call('connect_saved',{serverId:id})).error);await waitPhase('connected');traffic();
  let before=await state(), service=pid();record('Baseline',before);
  for(let attempt=0;attempt<4;attempt++) {
    assert(!(await call('disconnect_server')).error);
    assert(!(await call('connect_saved',{serverId:id})).error);
    await waitPhase('connected');traffic();
  }
  before=await state();service=pid();record('Rapid service stop/start retains the new tunnel',before);
  adb('shell','settings','put','system','accelerometer_rotation','0');
  adb('shell','settings','put','system','user_rotation','1');await delay(1500);
  adb('shell','settings','put','system','user_rotation','0');await delay(1500);
  assert.equal(pid(),service);assert.equal((await state()).generation,before.generation);traffic();record('Rotation preserves session',await state());
  adb('shell','svc','wifi','disable');adb('shell','svc','data','disable');
  record('Network loss',await waitPhase('waiting_for_network'));
  adb('shell','svc','wifi','enable');
  await waitPhase('connected');traffic();record('Network return reconnects',await state());
  before=await state();service=pid();
  adb('shell','run-as',pkg,'kill','-9',service);
  // A service death reconstructs a new session; it cannot preserve old packets.
  await delay(3500);await openApp();await waitPhase('connected');traffic();
  assert.notEqual(pid(),service);assert((await state()).generation>before.generation);record('VPN process death and permitted restart',await state());
  adb('shell','svc','wifi','disable');adb('shell','svc','data','disable');await waitPhase('waiting_for_network');
  assert(!(await call('disconnect_server')).error);
  adb('shell','svc','wifi','enable');await delay(8000);
  assert(['paused','disconnected'].includes((await state()).phase));record('Explicit stop cancels reconnect',await state());
  assert(!(await call('connect_saved',{serverId:id})).error);await waitPhase('connected');traffic();
  adb('shell','am','force-stop',pkg);await delay(2500);await openApp();await delay(2500);
  assert.notEqual((await state()).phase,'connected');record('Force stop remains stopped after reopening',await state());
  assert(!(await call('connect_saved',{serverId:id})).error);await waitPhase('connected');traffic();
  adb('shell','cmd','activity','stop-app',pkg);await delay(2500);await openApp();await delay(2500);
  assert.notEqual((await state()).phase,'connected');record('OS foreground-service Stop remains stopped',await state());
} finally {
  adb('shell','svc','wifi','enable');adb('shell','svc','data','enable');
  adb('shell','settings','put','system','user_rotation','0');
  await openApp();await call('set_connection_preferences',{serverId:id,preferences:original});
}
