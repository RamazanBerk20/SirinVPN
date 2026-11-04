// Dedicated API 31 emulator only: temporarily revert its WebView update to the factory build, older than Chrome 111.
import assert from 'node:assert/strict';
import {existsSync,writeFileSync} from 'node:fs';
import {adb,delay,serial} from './bridge.mjs';
assert.equal(adb('shell','getprop','ro.build.version.sdk'),'31');
const apk='.cache/android-tools/WebViewGoogle.apk';assert(existsSync(apk));
const before=adb('shell','dumpsys','webviewupdate');assert.match(before,/133\.0/);
try {
  adb('shell','am','force-stop','org.sirinvpn.client');
  assert.match(adb('uninstall','com.google.android.webview'),/Success/);
  await delay(1000);
  const reverted=adb('shell','dumpsys','webviewupdate');const factory=Number(reverted.match(/Current WebView package.*?, ([0-9]+)\./)?.[1]);
  assert(factory<111,'Factory WebView is already new enough: '+factory);
  adb('shell','am','start','-n','org.sirinvpn.client/.MainActivity');await delay(3000);
  adb('shell','rm','-f','/data/local/tmp/sirin-webview.xml');
  assert.match(adb('shell','uiautomator','dump','/data/local/tmp/sirin-webview.xml'),/dumped/);
  const ui=adb('exec-out','cat','/data/local/tmp/sirin-webview.xml');
  assert.match(ui,/Update Android System WebView/);assert.match(ui,/Open WebView settings/i);
  writeFileSync(`target/android-evidence/webview-${serial}.json`,JSON.stringify({serial,passed:true,factoryWebView:factory,nativeExplanationVisible:true,settingsActionVisible:true},null,2));
  console.log(`Factory WebView ${factory} displays the native update explanation.`);
} finally {
  assert.match(adb('install','-r',apk),/Success/);
  await delay(1000);assert.match(adb('shell','dumpsys','webviewupdate'),/Current WebView package.*133\./);
}
