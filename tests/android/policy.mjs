// Android-owned policy, changed only through Settings on an isolated emulator.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {spawn,execFileSync} from 'node:child_process';
import {createServer} from 'node:http';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';

const pkg='org.sirinvpn.client',rows=[];
async function nodes() {
  adb('shell','uiautomator','dump','/data/local/tmp/sirin-policy.xml');
  return (adb('exec-out','cat','/data/local/tmp/sirin-policy.xml').match(/<node\b[^>]*>/g)??[])
    .map(node=>Object.fromEntries([...node.matchAll(/([\w-]+)="([^"]*)"/g)].map(m=>[m[1],m[2]])));
}
async function tap(label) {
  const n=(await nodes()).find(n=>n.text===label||n['content-desc']===label);assert(n,'Missing native control: '+label);
  const [x,y,r,b]=n.bounds.match(/\d+/g).map(Number);adb('shell','input','tap',String((x+r)>>1),String((y+b)>>1));await delay(700);
}
async function settings() {
  adb('shell','am','start','-a','android.settings.VPN_SETTINGS','-f','0x10008000');await delay(700);
  if(!(await nodes()).some(n=>n.text==='Always-on VPN')) await tap('Settings');
}
async function toggle(label,enabled) {
  const list=await nodes(),index=list.findIndex(n=>n.text===label);assert(index>=0,label);
  const control=list.slice(index).find(n=>n.checkable==='true');assert(control);
  if((control.checked==='true')!==enabled) {
    await tap(label);
    const confirm=(await nodes()).find(n=>['Turn on','TURN ON','OK'].includes(n.text));
    if(confirm) await tap(confirm.text);
  }
}
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
const state=async()=>(await call('android_snapshot')).ok;
function passed(name,extra={}) {
  rows.push({name,passed:true,...extra});writeFileSync(`target/android-evidence/policy-${serial}.json`,JSON.stringify({serial,rows},null,2));console.log(name+': passed');
}
const server=createServer((_,res)=>{res.writeHead(200,{'Connection':'close'});res.end('sirin-isolated-network-probe')});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const port=server.address().port;
async function probe() {
  return await new Promise(resolve=>{
    const child=spawn(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'shell','run-as',pkg+'.test','/system/bin/toybox','nc','-w','3','10.0.2.2',String(port)]);
    let output='';child.stdout.on('data',data=>output+=data);child.stderr.resume();child.stdin.on('error',()=>{});
    child.stdin.end('GET / HTTP/1.0\r\nHost: acceptance\r\n\r\n');
    const timeout=setTimeout(()=>child.kill(),5000);
    child.on('close',()=>{clearTimeout(timeout);resolve(output.includes('sirin-isolated-network-probe'))});
  });
}
await openApp();
const profiles=(await call('list_servers')).ok;
assert.equal(profiles.length,1,'Use a clean boundary-test emulator with only the disposable profile');
const p=profiles[0];assert.equal(p.name,'Android isolated VPS');assert.equal(p.endpoint.host,'10.0.2.2');
const original=(await call('get_connection_preferences',{serverId:p.id})).ok;
let forgotten=false;
try {
  await settings();await toggle('Block connections without VPN',false);await toggle('Always-on VPN',false);
  await openApp();assert(!(await call('disconnect_server')).error);assert.equal((await state()).phase,'paused');
  await settings();await toggle('Always-on VPN',true);
  await openApp();
  for(let n=0;n<30;n++) {
    const current=await state();if(current.phase==='connected' && current.always_on) break;
    await delay(500);
  }
  const before=await state();assert(before.always_on);assert.equal(before.phase,'connected');
  assert((await call('server_status',{serverId:p.id})).ok,'Pinned private management endpoint');
  assert((await call('disconnect_server')).error);assert.equal((await state()).generation,before.generation);
  passed('Always-on starts the native tunnel and rejects ordinary Disconnect');
  const preferences={...original,transport:'direct_udp',routing:{mode:'selected_applications',included_routes:[],allow_lan:false},android_applications:{mode:'exclude',packages:[pkg+'.test']}};
  assert(!(await call('connect_server_with_policy',{serverId:p.id,preferences})).error);
  adb('shell','am','start','-n',pkg+'.test/org.sirinvpn.client.CatalogActivity');await delay(1500);
  assert(await probe(),'Excluded ordinary UID cannot reach controlled endpoint before lockdown');
  passed('Excluded app can reach the controlled host without lockdown');
  await settings();await toggle('Block connections without VPN',true);
  writeFileSync(`target/android-evidence/lockdown-${serial}.png`,execFileSync(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'exec-out','screencap','-p']));
  adb('shell','am','start','-n',pkg+'.test/org.sirinvpn.client.CatalogActivity');await delay(1500);
  assert(!await probe(),'Excluded app escaped Android lockdown');
  await openApp();assert((await state()).lockdown);assert((await call('server_status',{serverId:p.id})).ok);
  passed('Lockdown blocks excluded UID while pinned management traffic succeeds');
  await settings();await toggle('Block connections without VPN',false);await toggle('Always-on VPN',false);
  await tap('Forget VPN');
  const confirm=(await nodes()).find(n=>['Forget','FORGET'].includes(n.text));if(confirm) await tap(confirm.text);
  await openApp();await delay(1500);assert.notEqual((await state()).phase,'connected');
  forgotten=true;
  passed('Forgetting the VPN revokes consent and stops the tunnel');
} finally {
  if(!forgotten) {await settings();await toggle('Block connections without VPN',false);await toggle('Always-on VPN',false)}
  await openApp();await call('set_connection_preferences',{serverId:p.id,preferences:original});
  server.close();
}
