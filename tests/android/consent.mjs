import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {adb,delay,openApp,evaluate,serial} from './bridge.mjs';

// Start after policy.mjs has revoked consent, with the isolated profile retained.
const pkg='org.sirinvpn.client',rows=[];
const tun=()=>/\btun\d+:/.test(adb('shell','ip','-o','link','show'));
async function nodes() {
  adb('shell','uiautomator','dump','/data/local/tmp/sirin-consent.xml');
  return (adb('exec-out','cat','/data/local/tmp/sirin-consent.xml').match(/<node\b[^>]*>/g)??[])
    .map(n=>Object.fromEntries([...n.matchAll(/([\w-]+)="([^"]*)"/g)].map(m=>[m[1],m[2]])));
}
async function tap(label) {
  const node=(await nodes()).find(n=>n.text===label||n['content-desc']===label||label==='SirinVPN'&&n['content-desc']?.startsWith('SirinVPN,'));assert(node,label);
  const [x,y,r,b]=node.bounds.match(/\d+/g).map(Number);adb('shell','input','tap',String((x+r)>>1),String((y+b)>>1));await delay(700);
}
async function tile() {
  adb('shell','cmd','statusbar','expand-settings');await delay(800);await tap('SirinVPN');
  assert((await nodes()).some(n=>n.text==='Connection request'));
}
function noMain() {assert(!/ActivityRecord\{[^}]*org\.sirinvpn\.client\/.MainActivity/.test(adb('shell','dumpsys','activity','activities')))}
function passed(name) {rows.push({name,passed:true});writeFileSync(`target/android-evidence/consent-${serial}.json`,JSON.stringify({serial,rows},null,2));console.log(name+': passed')}
assert(!tun(),'Begin with revoked consent and no active tunnel');
if((await nodes()).some(n=>n.text==='Connection request')) await tap('Cancel');
await openApp();
assert(await evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:'list_servers',args:{}}).then(r=>r.ok.length===1&&r.ok[0].name==='Android isolated VPS'&&r.ok[0].endpoint.host==='10.0.2.2')`));
// No tunnel exists. Remove the old Activity before a new explicit tile request;
// this is a consent test, not evidence for Recents survival (lifecycle.mjs).
adb('shell','am','force-stop',pkg);await delay(1000);noMain();
await tile();
noMain();await tap('Cancel');assert(!tun());noMain();passed('Tile requests native consent without MainActivity; denial leaves no TUN');
await tile();noMain();await tap('OK');
for(let n=0;n<40&&!tun();n++) await delay(500);
assert(tun());await delay(2500);noMain();
const service=adb('shell','pidof',pkg+':vpn');passed('Granting consent connects from the tile without MainActivity');
await openApp();
const result=await evaluate(`(async()=>{const c=(command,args={})=>window.__TAURI_INTERNALS__.invoke('android_call',{command,args});const s=(await c('android_snapshot')).ok;const p=(await c('list_servers')).ok.find(p=>p.id===s.status.server_id);if(p?.name!=='Android isolated VPS'||p.endpoint.host!=='10.0.2.2') throw Error('Fixture guard');return {phase:s.phase,privateTraffic:!!(await c('server_status',{serverId:p.id})).ok}})()`);
assert.equal(result.phase,'connected');assert(result.privateTraffic);assert.equal(adb('shell','pidof',pkg+':vpn'),service);
passed('Reattachment retains VPN process and pinned private management access');
