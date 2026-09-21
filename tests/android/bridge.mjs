import { execFileSync } from 'node:child_process';
export const serial = process.env.ANDROID_SERIAL ?? 'emulator-5560';
if (!/^emulator-\d+$/.test(serial)) throw Error('Only isolated emulators are permitted by this test.');
const nativePort=3663+Number(serial.slice('emulator-'.length));
export const adb=(...args)=>{
  if(args[0]==='shell' && args.length>2) args=['shell',args.slice(1).map(value=>"'"+String(value).replaceAll("'","'\"'\"'")+"'").join(' ')];
  return execFileSync(`${process.env.ANDROID_HOME ?? process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,...args],{encoding:'utf8'}).trim();
};
export const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
export async function openApp() {
  adb('shell','am','start','-n','org.sirinvpn.client/.MainActivity');await delay(1500);
  adb('forward','tcp:'+nativePort,'localabstract:webview_devtools_remote_'+adb('shell','pidof','org.sirinvpn.client'));
  for(let n=0;n<40;n++) {
    try {
      // The JS object appears before the Rust/native bridge finishes a cold start.
      if(await evaluate(`window.__TAURI_INTERNALS__?.invoke('android_call',{command:'android_snapshot',args:{}}).then(r=>Boolean(r.ok?.phase)).catch(()=>false)`)) return;
    } catch { /* The WebView can navigate while the app finishes loading. */ }
    await delay(300);
  }
  throw Error('Production Android bridge did not initialize');
}
export async function evaluate(expression,port=nativePort) {
  // ADB daemon/device restarts drop port forwards independently of the WebView.
  const packageName=port===9224?'org.sirinvpn.client.test':'org.sirinvpn.client';
  adb('forward','tcp:'+port,'localabstract:webview_devtools_remote_'+adb('shell','pidof',packageName));
  const pages=await (await fetch('http://127.0.0.1:'+port+'/json')).json();
  const ws=new WebSocket(pages.find(page=>page.type==='page').webSocketDebuggerUrl);
  return new Promise((resolve,reject)=>{
    const timeout=setTimeout(()=>{ws.close();reject(Error('Native request timed out'));},90000);
    ws.onopen=()=>ws.send(JSON.stringify({id:1,method:'Runtime.evaluate',params:{expression,awaitPromise:true,returnByValue:true}}));
    ws.onmessage=e=>{const result=JSON.parse(e.data);if(result.id===1){clearTimeout(timeout);ws.close();
      if(result.error || result.result?.exceptionDetails || !result.result?.result) reject(Error('Android evaluation failed or its observer was replaced'));else resolve(result.result.result.value);}};
    ws.onerror=()=>{clearTimeout(timeout);reject(Error('WebView observer unavailable'));};
  });
}
