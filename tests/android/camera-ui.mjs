import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';
const pkg='org.sirinvpn.client';
adb('shell','input','keyevent','KEYCODE_BACK');
adb('shell','pm','revoke',pkg,'android.permission.CAMERA');
if(Number(adb('shell','getprop','ro.build.version.sdk'))>=30)
  adb('shell','pm','clear-permission-flags',pkg,'android.permission.CAMERA','user-set','user-fixed');
await openApp();
await evaluate('location.reload()');
for(let i=0;i<50;i++) {
  if(await evaluate('Boolean(document.querySelector(".mobile-add-server, .bottom-navigation"))'))break;
  await delay(300);
}
async function click(text) {
  assert(await evaluate(`(()=>{const b=[...document.querySelectorAll('button')].find(b=>b.innerText.trim()===${JSON.stringify(text)});if(!b)return false;b.click();return true})()`),text);
  await delay(400);
}
if (!await evaluate('Boolean(document.querySelector(".mobile-add-server"))')) {
  await click('Servers');await click('Add server');
}
assert(await evaluate(`(()=>{const b=document.querySelector('.mobile-add-server .invitation-choice');if(!b)return false;b.click();return true})()`));
await delay(400);await click('Scan QR code');
await delay(700);
adb('shell','rm','-f','/data/local/tmp/sirin-camera.xml');
assert.match(adb('shell','uiautomator','dump','/data/local/tmp/sirin-camera.xml'),/dumped/);
const node=(adb('exec-out','cat','/data/local/tmp/sirin-camera.xml').match(/<node\b[^>]*>/g)??[])
  .find(n=>/text="(?:Deny|Don.t allow)"/.test(n));
assert(node,'Camera permission dialog is missing');
const [x,y,r,b]=node.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/).slice(1).map(Number);
adb('shell','input','tap',String((x+r)>>1),String((y+b)>>1));await delay(700);
assert.match(await evaluate(`document.querySelector('[role="alert"]')?.textContent??''`),/Camera permission was not granted/);
assert(await evaluate(`[...document.querySelectorAll('button')].some(b=>b.innerText.trim()==='Enter securely'&&!b.disabled)`));
// Use the emulator's blank/default scene: an immediately decoded QR would close it.
adb('shell','pm','grant',pkg,'android.permission.CAMERA');
await click('Scan QR code');await delay(1000);
const cameraActive=()=>adb('shell','dumpsys','media.camera').split('== Camera service events log')[0].includes('Client Package Name: '+pkg);
assert(cameraActive(),'Camera must open; use a blank emulator camera scene');
adb('shell','input','keyevent','KEYCODE_HOME');await delay(1200);
assert(!cameraActive(),'Camera must release when the Activity leaves the foreground');
await openApp();await delay(1000);
assert(cameraActive(),'Camera must resume on returning to the scanner');
adb('shell','input','keyevent','KEYCODE_BACK');await delay(800);
assert(!cameraActive(),'Camera must release on cancellation');
assert.match(await evaluate(`document.querySelector('[role="alert"]')?.textContent??''`),/Scanning cancelled/);
writeFileSync(`target/android-evidence/camera-ui-${serial}.json`,JSON.stringify({serial,passed:true,nativePermissionDenied:true,visibleReactError:true,secureManualEntryAvailable:true,cameraOpened:true,backgroundReleased:true,resumed:true,cancelled:true},null,2));
console.log('Camera denial is visible; the native camera opens, releases on Home, resumes and cancels with Back.');
