// Requires target/android-update-fixtures/{update,unsigned}.apk and the test APK.
// Only cancels installation; no candidate is ever approved or installed.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {writeFileSync} from 'node:fs';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';
const pkg='org.sirinvpn.client';
await openApp();
assert(await evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:'list_servers',args:{}}).then(r=>r.ok.length===1&&r.ok[0].name==='Android isolated VPS'&&r.ok[0].endpoint.host==='10.0.2.2')`));
async function nodes() {
  adb('shell','uiautomator','dump','/data/local/tmp/sirin-apk.xml');
  return (adb('exec-out','cat','/data/local/tmp/sirin-apk.xml').match(/<node\b[^>]*>/g)??[])
    .map(n=>Object.fromEntries([...n.matchAll(/([\w-]+)="([^"]*)"/g)].map(m=>[m[1],m[2]])));
}
function tap(n) {const [x,y,r,b]=n.bounds.match(/\d+/g).map(Number);adb('shell','input','tap',String((x+r)>>1),String((y+b)>>1))}
adb('shell','am','start','-a','android.settings.MANAGE_UNKNOWN_APP_SOURCES','-d','package:'+pkg);await delay(800);
let list=await nodes();const toggle=list.find(n=>n.checkable==='true');assert(toggle);
if(toggle.checked!=='true') {tap(list.find(n=>n.text==='Allow from this source'));await delay(800)}
await openApp();
for(const [source,target] of [['update','acceptance-update'],['unsigned','acceptance-unsigned']]) {
  adb('push',`target/android-update-fixtures/${source}.apk`,`/data/local/tmp/${target}.apk`);
  adb('shell','run-as',pkg,'cp',`/data/local/tmp/${target}.apk`,`no_backup/${target}.apk`);
}
const child=spawn(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'shell','am','instrument','-w','-r','-e','class','org.sirinvpn.client.ApkAcceptanceTest',pkg+'.test/androidx.test.runner.AndroidJUnitRunner']);
let output='';child.stdout.on('data',data=>output+=data);child.stderr.on('data',data=>output+=data);
const completion=new Promise(resolve=>child.on('close',code=>{writeFileSync('/tmp/sirin-android-apk-instrumentation.log',output);resolve(code)}));
let cancelled=false;
for(let n=0;n<25;n++) {
  await delay(600);list=await nodes();
  const cancel=list.find(n=>n.text.toLowerCase()==='cancel'&&n.package?.includes('packageinstaller'));
  if(cancel) {tap(cancel);cancelled=true;break}
  if(child.exitCode!==null) break;
}
assert(cancelled,'Android update approval did not appear');
assert.equal(await completion,0);assert.match(output,/OK \(1 test\)/);assert(!output.includes('FAILURES'));
writeFileSync(`target/android-evidence/apk-${serial}.json`,JSON.stringify({serial,passed:true,installedVersionPreserved:true,
  checks:['same-version rejection','different package rejection','unsigned package rejection','matching debug signer and higher version admitted to Android approval','user cancellation removes installer session']},null,2));
console.log('APK identity/version checks and real Android installation cancellation passed.');
