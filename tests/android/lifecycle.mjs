import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const serial = process.env.ANDROID_SERIAL ?? 'emulator-5560';
if (!/^emulator-\d+$/.test(serial)) throw Error('This test only targets an isolated emulator.');
const adb = (...args) => execFileSync(`${process.env.ANDROID_HOME ?? process.env.HOME + '/Android/Sdk'}/platform-tools/adb`, ['-s',serial,...args], {encoding:'utf8'}).trim();
const delay = ms => new Promise(r => setTimeout(r,ms));
async function observe() {
  adb('shell','am','start','-n','org.sirinvpn.client/.MainActivity');
  await delay(1600);
  const pid=adb('shell','pidof','org.sirinvpn.client');
  adb('forward','tcp:9223','localabstract:webview_devtools_remote_'+pid);
  const pages=await (await fetch('http://127.0.0.1:9223/json')).json();
  const ws=new WebSocket(pages.find(p=>p.type==='page').webSocketDebuggerUrl);
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{ws.close();reject(Error('Native snapshot timed out'));},25000);
    ws.onopen=()=>ws.send(JSON.stringify({id:1,method:'Runtime.evaluate',params:{
      expression:'(async()=>{const call=(command,args={})=>window.__TAURI_INTERNALS__.invoke("android_call",{command,args});const s=(await call("android_snapshot")).ok;const r=await call("server_status",{serverId:s.status.server_id});return {phase:s.phase,generation:s.generation,rx:s.status.rx_bytes,tx:s.status.tx_bytes,uptime:s.status.tunnel_uptime_seconds,managementResponded:!!r.ok};})()',awaitPromise:true,returnByValue:true}}));
    ws.onmessage=e=>{const r=JSON.parse(e.data);if(r.id===1){clearTimeout(timer);ws.close();resolve(r.result?.result?.value);}};
    ws.onerror=()=>{clearTimeout(timer);reject(Error('WebView observer disconnected'));};
  });
}
const before=await observe();
if (before.phase!=='connected' || !before.managementResponded) throw Error('Connect an authorized test profile first.');
const service=adb('shell','pidof','org.sirinvpn.client:vpn');
const check = (label, status) => {
 if (adb('shell','pidof','org.sirinvpn.client:vpn') !== service || status.generation !== before.generation || status.phase !== 'connected' || !status.managementResponded) throw Error(label+' changed or lost the tunnel');
 return {test:label,passed:true,...status};
};
const results=[{test:'baseline',...before}];
adb('shell','input','keyevent','KEYCODE_HOME');await delay(2000);
results.push(check('Home and reopen',await observe()));
const ui=adb('shell','pidof','org.sirinvpn.client');
adb('shell','run-as','org.sirinvpn.client','kill','-9',ui);await delay(2000);
results.push(check('UI process SIGKILL and reopen',await observe()));
adb('shell','input','keyevent','KEYCODE_APP_SWITCH');await delay(1200);
adb('shell','input','swipe','160','430','160','40','160');await delay(1800);
const tasks=adb('shell','dumpsys','activity','recents');
if (/Recent #\d+:.*org\.sirinvpn\.client/.test(tasks)) throw Error('Recents gesture did not remove the task');
results.push(check('Recents swipe and reopen',await observe()));
writeFileSync('target/android-evidence/lifecycle.json',JSON.stringify({serial,api:adb('shell','getprop','ro.build.version.sdk'),results},null,2));
console.log(results.map(r=>r.test+': passed').join('\n'));
