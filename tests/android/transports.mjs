import { writeFileSync } from 'node:fs';
import { openApp,evaluate,delay,serial } from './bridge.mjs';
await openApp();
const results=[];
const serverId=await evaluate(`(async()=>{const s=(await window.__TAURI_INTERNALS__.invoke('android_call',{command:'android_snapshot',args:{}})).ok;return s.status.server_id ?? s.quick_profile;})()`);
if(!serverId) throw Error('Select an authorized test server first');
const transports=['direct_udp','obfuscated_udp','tcp_fallback','tls_like']
  .filter(t=>t!=='obfuscated_udp'||!process.argv.includes('--without-obfuscated-udp'));
for(const transport of transports) {
  const result=await evaluate(`(async()=>{
    const call=(command,args={})=>window.__TAURI_INTERNALS__.invoke('android_call',{command,args});
    const snapshot=(await call('android_snapshot')).ok;
    const serverId=${JSON.stringify(serverId)};
    const prefs=(await call('get_connection_preferences',{serverId})).ok;
    const result=await call('connect_server_with_policy',{serverId,preferences:{...prefs,policy:{...prefs.policy,automatic_reconnect:false},transport:${JSON.stringify(transport)}}});
    if(result.error) return {error:result.error};
    const status=await call('server_status',{serverId});
    const local=(await call('android_snapshot')).ok.status;
    return {transport:local.transport,managementResponded:!!status.ok,rx:local.rx_bytes,tx:local.tx_bytes};
  })()`);
  results.push({requested:transport,...result});
  writeFileSync(process.env.SIRIN_TRANSPORT_EVIDENCE ?? 'target/android-evidence/transports.json',JSON.stringify({serial,requestedTransports:transports,results},null,2));
  if(!result) throw Error('No native response');
  await delay(500);
}
await evaluate(`(async()=>{
  const call=(command,args={})=>window.__TAURI_INTERNALS__.invoke('android_call',{command,args});
  const snapshot=(await call('android_snapshot')).ok;
  return call('connect_saved',{serverId:${JSON.stringify(serverId)}});
})()`);
const failed=results.filter(r=>!r.managementResponded || r.transport!==r.requested).map(r=>r.requested);
if(failed.length) throw Error('Transports not verified: '+failed.join(', '));
console.log('All requested transports reached the pinned private management endpoint.');
