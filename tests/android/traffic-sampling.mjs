// Production UI in the isolated catalog APK; deterministic counters, no network traffic.
import assert from 'node:assert/strict';
import {mkdirSync,writeFileSync} from 'node:fs';
import {adb,evaluate,delay,serial} from './bridge.mjs';

const out='target/android-evidence/traffic-sampling';
mkdirSync(out,{recursive:true});
adb('shell','am','start','-n','org.sirinvpn.client.test/org.sirinvpn.client.CatalogActivity');
await delay(1800);
await evaluate(`(async()=>{
  const c=window.__catalog;
  c.watchLocal=callback=>{c.trafficReceive=callback;return()=>{};};
  await c.mount({platform:'android',local:{counter_sampled_at_ms:10000,rx_bytes:1024,tx_bytes:512,tunnel_uptime_seconds:10}});
  c.trafficSequence=0;
  c.sendTraffic=patch=>{Object.assign(c.state.local,patch);c.trafficReceive({status:c.local(),sequence:++c.trafficSequence,generation:1,phase:c.state.local.state,stale:false});};
  c.sendTraffic({});
})()`,9224);
const rows=[];
async function sample(name,patch,expected) {
  await evaluate(`window.__catalog.sendTraffic(${JSON.stringify(patch)})`,9224);
  await delay(80);
  const rates=await evaluate(`Array.from(document.querySelectorAll('.device-traffic .metric')).slice(0,2).map(el=>el.querySelector('strong').textContent)`,9224);
  assert.deepEqual(rates,expected,name);
  rows.push({name,rates});
}
await sample('initial reading',{},['Sampling…','Sampling…']);
await sample('second reading',{counter_sampled_at_ms:12000,rx_bytes:5120,tx_bytes:1536,tunnel_uptime_seconds:12},['2.0 KB/s','512 B/s']);
for(let n=0;n<12;n++) await sample('repeated status '+n,{},['2.0 KB/s','512 B/s']);
await sample('new reading after status burst',{counter_sampled_at_ms:14000,rx_bytes:13312,tx_bytes:3584,tunnel_uptime_seconds:14},['4.0 KB/s','1.0 KB/s']);
await sample('idle reading',{counter_sampled_at_ms:16000,tunnel_uptime_seconds:16},['0 B/s','0 B/s']);
await sample('reconnected',{counter_epoch:'new-session',counter_sampled_at_ms:18000,rx_bytes:0,tx_bytes:0,tunnel_uptime_seconds:0},['Sampling…','Sampling…']);
await sample('reconnected second reading',{counter_sampled_at_ms:20000,rx_bytes:2048,tx_bytes:1024,tunnel_uptime_seconds:2},['1.0 KB/s','512 B/s']);
await sample('counter failure',{byte_counters_available:false},['Unavailable','Unavailable']);
await sample('first reading after recovery',{byte_counters_available:true,counter_sampled_at_ms:22000,rx_bytes:4096,tx_bytes:2048,tunnel_uptime_seconds:4},['Sampling…','Sampling…']);
await sample('recovered readings',{counter_sampled_at_ms:24000,rx_bytes:8192,tx_bytes:4096,tunnel_uptime_seconds:6},['2.0 KB/s','1.0 KB/s']);
writeFileSync(out+'/presentation.json',JSON.stringify({serial,scope:'Production UI with synthetic counter observations in the separate test APK',passed:true,rows},null,2)+'\n');
console.log(`PASS: ${rows.length} traffic display checks, including duplicate updates, idle, reconnect and recovery.`);
