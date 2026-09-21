// Real native surfaces on a clean, disposable-profile emulator. No sharing is sent.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';
const pkg='org.sirinvpn.client',rows=[];
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
async function nodes() {
  adb('shell','rm','-f','/data/local/tmp/sirin-native-flow.xml');
  assert.match(adb('shell','uiautomator','dump','/data/local/tmp/sirin-native-flow.xml'),/dumped/);
  return (adb('exec-out','cat','/data/local/tmp/sirin-native-flow.xml').match(/<node\b[^>]*>/g)??[])
    .map(node=>Object.fromEntries([...node.matchAll(/([\w-]+)="([^"]*)"/g)].map(m=>[m[1],m[2]])));
}
async function tap(label) {
  const n=(await nodes()).find(n=>label instanceof RegExp?label.test(n.text)||label.test(n['content-desc']):n.text===label||n['content-desc']===label);
  assert(n,'Native control missing: '+label);
  const [x,y,r,b]=n.bounds.match(/\d+/g).map(Number);adb('shell','input','tap',String((x+r)>>1),String((y+b)>>1));await delay(600);
}
async function begin(command,args={}) {
  await evaluate(`window.nativeFlowResult=null;window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}}).then(r=>window.nativeFlowResult=r,e=>window.nativeFlowResult={error:String(e)});true`);
  await delay(800);
}
async function result() {
  for(let n=0;n<30;n++) {const r=await evaluate('window.nativeFlowResult');if(r!==null)return r;await delay(300)}
  throw Error('Native result did not arrive');
}
function passed(name) {rows.push({name,passed:true});writeFileSync(`target/android-evidence/native-flows-${serial}.json`,JSON.stringify({serial,rows},null,2));console.log(name+': passed')}
await openApp();
const profiles=(await call('list_servers')).ok;assert.equal(profiles.length,1);
const profile=profiles[0];assert.equal(profile.name,'Android isolated VPS');assert.equal(profile.endpoint.host,'10.0.2.2');assert.equal(profile.role,'owner');
assert(!(await call('connect_server',{serverId:profile.id})).error);
await begin('android_secret_input',{label:'Acceptance password',minimumLength:12});
const field=(await nodes()).find(n=>n.class==='android.widget.EditText');assert(field);
const [x,y,r,b]=field.bounds.match(/\d+/g).map(Number);adb('shell','input','tap',String((x+r)>>1),String((y+b)>>1));
adb('shell','input','text','fixture-only-password');adb('shell','input','keyevent','KEYCODE_BACK');await delay(300);
assert.match(adb('shell','dumpsys','window','windows'),/\bSECURE\b/);
await tap(/^Use value$/i);const password=(await result()).ok;assert.match(password,/^native-secret:/);
assert(!JSON.stringify(await evaluate('window.nativeFlowResult')).includes('fixture-only-password'));
passed('Protected native input exposes only an opaque handle and sets FLAG_SECURE');
await begin('android_secret_input',{label:'Cancelled input'});await tap(/^Cancel$/i);assert.equal((await result()).error,'Cancelled');
passed('Native cancellation preserves its specific error through the bridge');
const recovery=(await call('recovery_settings',{serverId:profile.id})).ok;assert(!recovery.key,'Do not replace an existing recovery key');
const key=(await call('create_recovery_key',{input:{server_id:profile.id,confirmed:true}})).ok;assert(key);
try {
  assert(!(await call('android_show_secret',{reference:key.key})).error);
  assert((await nodes()).some(n=>n['content-desc']==='Protected QR code'));
  assert.match(adb('shell','dumpsys','window','windows'),/\bSECURE\b/);
  await tap(/^Close$/i);passed('Recovery QR opens in the protected native viewer');
} finally {assert(!(await call('revoke_recovery_key',{serverId:profile.id,recoveryId:key.recovery_id})).error)}
await begin('android_save_document',{options:{defaultPath:'sirin-acceptance.sirinbackup'}});
await tap(/^Save$/i);const uri=(await result()).ok;assert.match(uri,/^content:/);
assert(!(await call('export_server_backup',{input:{server_id:profile.id,path:uri,password,confirmed:true}})).error);
passed('Android SAF creates a selected content URI and the real service writes an encrypted backup');
assert(!(await call('android_share_document',{uri})).error);await delay(1000);
assert.match(adb('shell','dumpsys','activity','activities'),/ChooserActivity/);
adb('shell','input','keyevent','KEYCODE_BACK');await delay(800);
passed('The exported encrypted file opens the Android share chooser; sharing is cancelled');
await begin('android_open_document',{options:{}});await tap('sirin-acceptance.sirinbackup');
const opened=(await result()).ok;assert.match(opened,/^content:/);
assert((await call('import_server_backup',{input:{path:opened,password,confirmed:true}})).error,'Existing profile must not be overwritten');
passed('Android SAF selects the exported file; duplicate import is rejected');
await begin('android_open_document',{options:{}});adb('shell','input','keyevent','KEYCODE_BACK');assert.equal((await result()).ok,null);
passed('SAF cancellation returns no document');
await call('disconnect_server');
adb('shell','pm','revoke',pkg,'android.permission.CAMERA');await openApp();
await begin('android_scan_code');await tap(/^Deny$|^Don.t allow$/i);
assert.match((await result()).error,/Camera permission was not granted/);
passed('Camera denial explains secure manual entry and does not enroll anything');
