import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {dirname} from 'node:path';
import {execFileSync} from 'node:child_process';
import {adb,evaluate,openApp,delay,serial} from './bridge.mjs';

const fixture=JSON.parse(readFileSync(process.argv[2]??'.cache/android-vps-20260920b/fixture.json'));
const enrollment=JSON.parse(adb('exec-out','run-as','org.sirinvpn.client','cat','no_backup/acceptance-vps-result.json'));
assert.equal(fixture.fixture,enrollment.fixture);assert.equal(fixture.host,'10.0.2.2');
const ssh=command=>execFileSync('ssh',['-i',fixture.private_key_source,'-p',String(fixture.ssh_port),
  '-o','HostKeyAlias=android-vps','-o','UserKnownHostsFile='+dirname(fixture.private_key_source)+'/known-hosts',
  '-o','GlobalKnownHostsFile=/dev/null','-o','StrictHostKeyChecking=yes','-o','BatchMode=yes','sirin@127.0.0.1',command],{encoding:'utf8'}).trim();
assert.equal(ssh('cat /etc/sirinvpn-acceptance-fixture'),fixture.fixture);
// A freshly installed/force-stopped test UID must first enter Android's normal
// running state; run-as alone does not clear stopped-package network policy.
adb('shell','am','start','-n','org.sirinvpn.client.test/org.sirinvpn.client.CatalogActivity');await delay(1500);
await openApp();
const call=async(command,args={})=>{
  const r=await evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
  if(r.error) throw Error(command+': '+r.error);return r.ok;
};
const id=enrollment.server_id,p=(await call('list_servers')).find(p=>p.id===id);
assert.equal(p.name,'Android isolated VPS');assert.equal(p.endpoint.host,'10.0.2.2');
const original=await call('get_connection_preferences',{serverId:id}),rows=[];
// Keep the ordinary test app visible: Android may block a cached/frozen UID
// independently of the VPN. The VPN app remains foreground through its service.
adb('shell','am','start','-n','org.sirinvpn.client.test/org.sirinvpn.client.CatalogActivity');await delay(1500);
const base={...original,transport:'direct_udp',manual_mtu:1280,android_applications:null,
  routing:{mode:'full_tunnel',included_routes:[],allow_lan:false}};
const connect=async preferences=>{await call('connect_server_with_policy',{serverId:id,preferences});await delay(1000)};
function ping(pkg,host,expected) {
  let ok=false;
  try {ok=/2 received/.test(adb('shell','run-as',pkg,'/system/bin/ping','-n','-c','2','-w','3',host))}catch{}
  assert.equal(ok,expected,`${pkg} traffic to ${host}`);
}
function passed(name) {
  rows.push({name,passed:true});console.log(name+': passed');
  writeFileSync('target/android-evidence/routing.json',JSON.stringify({serial,fixture:'disposable local VPS',rows},null,2));
}
try {
  for(const ip of ['198.18.0.1','198.18.0.2','10.99.0.1']) ssh(`sudo ip address add ${ip}/32 dev lo`);
  await connect(base);
  for(const pkg of ['org.sirinvpn.client','org.sirinvpn.client.test']) ping(pkg,'198.18.0.1',true);
  ping('org.sirinvpn.client','10.99.0.1',true);passed('Full tunnel routes both ordinary application UIDs');
  await connect({...base,routing:{mode:'selected_routes',included_routes:['198.18.0.1/32'],allow_lan:false}});
  ping('org.sirinvpn.client','198.18.0.1',true);ping('org.sirinvpn.client','198.18.0.2',false);
  ping('org.sirinvpn.client',p.server_tunnel_address,true);passed('Selected subnet and exact private management/DNS route');
  await connect({...base,routing:{...base.routing,allow_lan:true}});
  ping('org.sirinvpn.client','10.99.0.1',false);ping('org.sirinvpn.client',p.server_tunnel_address,true);
  passed('LAN bypass retains private management/DNS access');
  const routing={mode:'selected_applications',included_routes:[],allow_lan:false};
  await connect({...base,routing,android_applications:{mode:'include',packages:['org.sirinvpn.client.test']}});
  ping('org.sirinvpn.client.test','198.18.0.1',true);ping('org.sirinvpn.client',p.server_tunnel_address,true);
  passed('Included application is routed alongside required management traffic');
  await connect({...base,routing,android_applications:{mode:'exclude',packages:['org.sirinvpn.client.test']}});
  ping('org.sirinvpn.client.test','198.18.0.1',false);ping('org.sirinvpn.client',p.server_tunnel_address,true);
  passed('Excluded application bypasses VPN while controller traffic remains routed');
  await connect(base);
  const s=await call('android_snapshot');assert(s.status.ipv6_blocked);
  assert.match(adb('shell','ip','-6','route','show','table','all'),/default dev tun/);
  passed('IPv6 disabled profile installs IPv6 containment route (not external leak proof)');
} finally {
  for(const ip of ['198.18.0.1','198.18.0.2','10.99.0.1']) ssh(`sudo ip address del ${ip}/32 dev lo`);
  await connect(original);
}
