// Real app UI and Android configuration changes, with a disposable profile.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';

const pkg='org.sirinvpn.client',rows=[];
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
const state=async()=>(await call('android_snapshot')).ok;
async function click(text,selector='button') {
  assert(await evaluate(`(()=>{const b=[...document.querySelectorAll(${JSON.stringify(selector)})].find(b=>b.innerText.trim()===${JSON.stringify(text)}&&b.getClientRects().length);if(!b)return false;b.scrollIntoView({block:'center'});b.click();return true})()`),text);
  await delay(600);
}
function shot(name) {
  const path=`target/android-evidence/ui-${serial}-${name}.png`;
  writeFileSync(path,execFileSync(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'exec-out','screencap','-p']));return path;
}
function passed(name,extra={}) {rows.push({name,passed:true,...extra});writeFileSync(`target/android-evidence/ui-${serial}.json`,JSON.stringify({serial,rows},null,2));console.log(name+': passed')}
await openApp();
const profiles=(await call('list_servers')).ok;
assert.equal(profiles.length,1);assert.equal(profiles[0].name,'Android isolated VPS');assert.equal(profiles[0].endpoint.host,'10.0.2.2');
const before=await state();assert.equal(before.phase,'connected');
const vpnPid=adb('shell','pidof',pkg+':vpn');
const originalFont=adb('shell','settings','get','system','font_scale');
const originalRotation=adb('shell','settings','get','system','user_rotation');
const originalAuto=adb('shell','settings','get','system','accelerometer_rotation');
try {
  await click('Home','.bottom-navigation button');
  await click('Settings','.bottom-navigation button');
  await click('General','button[role=tab]');
  assert(await evaluate(`document.body.innerText.includes('Android VPN controls')&&!document.body.innerText.includes('Startup & window')&&!document.body.innerText.includes('Local VPN component')`));
  if(Number(adb('shell','getprop','ro.build.version.sdk'))<33) {
    await click('Add Quick Settings tile');
    assert(await evaluate(`document.body.innerText.includes('Open Quick Settings, tap Edit')`));
  }
  passed('Android settings and older-version tile instructions', {screenshot:shot('settings')});
  await click('Connection','button[role=tab]');
  const original=(await call('get_connection_preferences',{serverId:profiles[0].id})).ok;
  const checkbox='input[aria-label="Automatic reconnect"]';
  const value=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(checkbox)});e.click();return e.checked})()`);
  await delay(300);assert(await evaluate(`document.body.innerText.includes('Save preferences')`));
  const dimensions=()=>evaluate(`({width:innerWidth,total:document.documentElement.scrollWidth,heading:document.querySelector('h1').getBoundingClientRect().height,checked:document.querySelector(${JSON.stringify(checkbox)}).checked})`);
  const initial=await dimensions();
  adb('shell','settings','put','system','font_scale','2');await delay(1400);
  const large=await dimensions();assert.equal(large.checked,value);assert(large.heading>initial.heading*1.5,'System font scale was not applied');
  assert(large.total<=large.width+1,'Document overflow at 200%');
  passed('200% font scale retains the draft without horizontal document overflow',{before:initial,after:large,screenshot:shot('font-200')});
  adb('shell','settings','put','system','accelerometer_rotation','0');
  adb('shell','settings','put','system','user_rotation','1');await delay(1400);
  assert.equal((await dimensions()).checked,value);
  assert.equal((await state()).generation,before.generation);
  passed('Landscape rotation retains the preference draft and tunnel generation',{screenshot:shot('landscape')});
  adb('shell','settings','put','system','user_rotation','0');
  adb('shell','settings','put','system','font_scale','1');await delay(1000);
  adb('shell','input','keyevent','KEYCODE_BACK');await delay(700);
  assert(await evaluate(`document.querySelector('.bottom-navigation [aria-current=page]')?.innerText.trim()==='Home'`));
  await click('Settings','.bottom-navigation button');
  await click('Connection','button[role=tab]');assert.equal((await dimensions()).checked,value);
  assert.deepEqual((await call('get_connection_preferences',{serverId:profiles[0].id})).ok,original);
  await click('Discard');
  passed('System Back keeps an unsaved connection draft; only explicit Save changes stored preferences');
  await click('Servers','.bottom-navigation button');await click('Add server');
  assert(await evaluate(`!!document.querySelector('[role=dialog]')`));
  adb('shell','input','keyevent','KEYCODE_BACK');await delay(800);
  assert(await evaluate(`!document.querySelector('[role=dialog]')`));
  assert.equal((await state()).generation,before.generation);assert.equal(adb('shell','pidof',pkg+':vpn'),vpnPid);
  assert((await call('server_status',{serverId:profiles[0].id})).ok);
  passed('Back dismisses a modal and retains the original VPN with pinned management traffic');
} finally {
  adb('shell','settings','put','system','font_scale',originalFont==='null'?'1':originalFont);
  adb('shell','settings','put','system','user_rotation',originalRotation==='null'?'0':originalRotation);
  adb('shell','settings','put','system','accelerometer_rotation',originalAuto==='null'?'1':originalAuto);
}
