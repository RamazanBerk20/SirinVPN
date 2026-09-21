import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';
adb('root');adb('wait-for-device'); // Observe kernel MTU only; application traffic remains unprivileged.
await openApp();
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
const profiles=(await call('list_servers')).ok;assert.equal(profiles.length,1);
const p=profiles[0];assert.equal(p.name,'Android isolated VPS');assert.equal(p.endpoint.host,'10.0.2.2');assert.equal(p.role,'owner');
const original=(await call('get_connection_preferences',{serverId:p.id})).ok;
const preferences={...original,transport:'direct_udp',manual_mtu:1280,routing:{mode:'selected_routes',included_routes:['10.77.0.0/24'],allow_lan:false},android_applications:null};
assert(!(await call('connect_server_with_policy',{serverId:p.id,preferences})).error);
await delay(2500);
const before=(await call('android_snapshot')).ok,pid=adb('shell','pidof','org.sirinvpn.client:vpn');
for(const command of ['apply_endpoint_update','publish_endpoint_update']) {
  assert((await call(command,{input:{server_id:p.id,code:'sirm1.invalid'}})).error);
  const after=(await call('android_snapshot')).ok;
  assert.equal(after.phase,'connected');assert.equal(after.status.counter_epoch,before.status.counter_epoch);
  assert.equal(adb('shell','pidof','org.sirinvpn.client:vpn'),pid);
  assert((await call('server_status',{serverId:p.id})).ok);
}
let rotation=await call('rotate_device_keys',{input:{server_id:p.id,confirmed:true}}),resumed=false;
if(rotation.error && (await call('key_rotation_pending',{serverId:p.id})).ok) {
  // Exercise the explicit Resume outcome of a retained transaction, rather
  // than inventing a new rotation after a possibly committed server change.
  await delay(1500);rotation=await call('rotate_device_keys',{input:{server_id:p.id,confirmed:true}});resumed=true;
}
assert(!rotation.error,'Rotation/resumption did not complete');
assert((await call('server_status',{serverId:p.id})).ok);
const after=(await call('android_snapshot')).ok;
assert.equal(after.status.routing_mode,'selected_routes');assert.equal(after.status.transport,'direct_udp');
assert.match(adb('shell','ip','-o','link','show'),/tun\d+:.*mtu 1280/);
const intent=adb('exec-out','run-as','org.sirinvpn.client','cat','shared_prefs/connection-intent.xml');
assert.match(intent,/manual_mtu[^0-9]*1280/);
assert.match(intent,/selected_routes/);
await call('set_connection_preferences',{serverId:p.id,preferences:original});
writeFileSync(`target/android-evidence/transitions-${serial}.json`,JSON.stringify({serial,passed:true,invalidEndpointCodeRetainsTunnel:true,invalidPublicationRetainsTunnel:true,counterEpochRetained:true,keyRotationPreservesActiveRoutingAndMtu:true,restartIntentPreservesActivePolicy:true,resumedRetainedRotation:resumed},null,2));
console.log('Rejected endpoint operations retain the tunnel; identity rotation retains active routing/MTU and restart policy.');
