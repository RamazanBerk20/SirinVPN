// Real Android WebView rendering, fictional API responses. No tunnel claims.
import {readFileSync,writeFileSync,appendFileSync,mkdirSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {adb,evaluate,delay,serial} from './bridge.mjs';

const out='target/android-catalog-evidence',log=out+'/results.jsonl';
mkdirSync(out,{recursive:true});
const manifest=JSON.parse(readFileSync('target/screenshot-catalog-2026-09-20/manifest.json'));
const filter=new RegExp(process.argv[2]??'.');
const cases=manifest.scenarios.filter(s=>filter.test(s.family+'/'+s.id));
const bundleSha256=createHash('sha256').update(readFileSync('target/android-catalog/catalog.js')).digest('hex');
const call=async(method,...args)=>{
  const result=await evaluate(`Promise.resolve().then(()=>window.__catalog.${method}(${args.map(a=>JSON.stringify(a)).join(',')})).then(value=>({value}),error=>({error:String(error.message)}))`,9224);
  if(result.error) throw Error(result.error);return result.value;
};
adb('shell','am','start','-n','org.sirinvpn.client.test/org.sirinvpn.client.CatalogActivity');await delay(1800);
adb('forward','tcp:9224','localabstract:webview_devtools_remote_'+adb('shell','pidof','org.sirinvpn.client.test'));
for(let n=0;n<30 && !await evaluate('!!window.__catalog?.ready',9224);n++) await delay(300);
if(!await evaluate('!!window.__catalog?.ready',9224)) throw Error('Android catalog unavailable');
if(!await evaluate('document.characterSet==="UTF-8"',9224)) throw Error('Catalog must preserve Unicode');
if(!await evaluate('[...document.styleSheets].some(s=>s.href?.endsWith("catalog.css")) && getComputedStyle(document.body).backgroundColor==="rgb(4, 8, 21)"',9224)) throw Error('Production stylesheet did not load');
const previous=new Map();
if(process.argv.includes('--resume')) {
  try {for(const line of readFileSync(log,'utf8').trim().split('\n')) {const row=JSON.parse(line);previous.set(row.key,row)}}catch{}
}
function shot(path) {
  const png=execFileSync(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'exec-out','screencap','-p']);
  writeFileSync(out+'/'+path,png);
  return {path:out+'/'+path,sha256:createHash('sha256').update(png).digest('hex')};
}
async function capture(row,suffix='') {
  await call('settled');const ports=await call('scrollPorts');
  for(const port of ports) await call('scroll',port.index,0);
  const stem=row.key+suffix;
  row.files.push(shot(stem+'--top.png'));
  for(const p of ports) {
    if(p.height<60 || p.box.width<50) continue;
    const max=p.total-p.height,count=p.tag==='TEXTAREA'?1:Math.ceil(max/Math.max(80,p.height*.72));
    for(let n=1;n<=count;n++) {await call('scroll',p.index,Math.round(max*n/count));row.files.push(shot(`${stem}--scroll-${p.index}-${n}.png`))}
    await call('scroll',p.index,0);
  }
}
for(const [index,s] of cases.entries()) {
  const key=s.family+'/'+s.id;
  if(previous.get(key)?.success && previous.get(key)?.bundleSha256===bundleSha256) continue;
  const row={key,bundleSha256,renderer:'Android system WebView in isolated test APK',serial,scope:'fictional presentation only',success:false,files:[]};
  mkdirSync(out+'/'+s.family,{recursive:true});
  // Native desktop snapshots do not have replay actions. They need explicit
  // native Android evidence, never a generic Home screenshot passed as parity.
  if(!Object.hasOwn(s,'actions')) {
    row.disposition='native_equivalent_requires_separate_evidence';
    appendFileSync(log,JSON.stringify(row)+'\n');continue;
  }
  if(/local-component|update-local-vpn-component|retained-appimage|application-launch|launch-application|launched-command|startup-|activate-startup/.test(key) ||
      s.actions.some(a=>/Start on system startup|Launch minimized|Close to tray/.test(a.css??''))) {
    row.disposition='android_native_workflow_requires_separate_evidence';
    row.adaptation='Android system VPN policy, package routing or APK replacement owns this desktop-specific outcome. See docs/android/scenarios.json; a desktop fixture is not native verification.';
    appendFileSync(log,JSON.stringify(row)+'\n');continue;
  }
  try {
    const actions=s.actions.flatMap(action=>{
      if(action.text==='Add server') {
        row.adaptation='Add server is reached through the Servers destination on Android.';
        return [{js:`(()=>{if(![...document.querySelectorAll('button')].some(b=>b.innerText.trim()==='Add server' && b.getClientRects().length)){const nav=[...document.querySelectorAll('.bottom-navigation button')].find(b=>b.innerText.trim()==='Servers');if(!nav) throw Error('Mobile Servers navigation missing');nav.click()}})()`},action];
      }
      if(action.css==='input[aria-label="Kill switch"]') {
        row.adaptation='Preference save/dirty/error workflow uses Automatic reconnect; kill switch is verified separately in Android Settings.';
        return {...action,css:'input[aria-label="Automatic reconnect"]'};
      }
      if(action.text==='Enlarge invitation QR code' || action.text==='Enlarge recovery QR code') {
        const kind=action.text.includes('invitation')?'invitation':'recovery';
        row.adaptation='Native protected QR/secret viewer; this fixture proves invocation only. Native view requires separate evidence.';
        return {...action,text:`View or share ${kind} securely`};
      }
      if(action.text==='SSH agent') {
        row.adaptation='OS SSH-agent authentication uses a user-selected private key on Android; the same host-trust/operation outcome is exercised.';
        return [{...action,text:'Private key'},{js:`(()=>{const b=[...document.querySelectorAll('button')].find(b=>/Choose SSH key|SSH key selected/.test(b.innerText));if(!b) throw Error('Native SSH key picker missing');b.click()})()`}];
      }
      return action;
    });
    const state={...s.state,platform:'android'};
    if(s.family==='app-updates' || /app-update|app-release|appimage|windows-update/.test(s.id)) {
      state.releaseCandidate={...state.releaseCandidate,installer_kind:state.releaseCandidate?.installer_kind==='unsupported'?'unsupported':'android',
        artifact_file_name:'SirinVPN.apk',artifact_target:'x86_64-linux-android',android_install_available:true,
        debian_install_available:false,appimage_install_available:false,windows_install_available:false};
      row.adaptation='Signed Android APK verification and user-approved installation replace desktop package mechanisms.';
    }
    await call('mount',state);
    await call('actions',actions);
    row.observed=await call('inspect');
    const required=new Set([...(s.required_calls??[]),...Object.keys(s.state?.errors??{}),...(s.state?.holds??[])]);
    for(const a of s.actions) {Object.keys(a.patch?.errors??{}).forEach(x=>required.add(x));(a.patch?.holds??[]).forEach(x=>required.add(x))}
    let missing=[...required].filter(x=>!row.observed.calls.includes(x));
    for(let n=0;missing.length&&n<20;n++) {
      await delay(100);row.observed=await call('inspect');missing=[...required].filter(x=>!row.observed.calls.includes(x));
    }
    if(missing.length) throw Error('Unexercised fixture operations: '+missing.join(', '));
    const errors=await evaluate('window.__catalog.state.fixtureErrors??[]',9224);
    if(errors.length || row.observed.unknown.length) throw Error(JSON.stringify({errors,unknown:row.observed.unknown}));
    row.assertions=[];
    for(const a of [...(s.assertions??[]),...(s.expect?[{text:s.expect}]:[])]) {
      if(a.text==='Scan recovery QR') {
        const invoked=await evaluate(`window.__catalog.prompts.some(p=>p.kind==='android_show_secret')`,9224);
        if(!invoked) throw Error('Protected native QR viewer was not requested');
        row.nativeVerification='Invocation observed; protected native viewer requires separate evidence.';
      } else row.assertions.push(await call('assertVisible',a));
    }
    if(row.observed.text.length<12) throw Error('Empty screen');
    if(row.observed.overflow) throw Error('Horizontal document overflow');
    await capture(row);
    if(s.expand && await evaluate('!!document.querySelector("details:not([open])")',9224)) {await call('act',{details:'open'});await capture(row,'--expanded')}
    row.success=true;
  } catch(e) {
    row.error=String(e.message);
    try {row.observed=await call('inspect');row.files.push(shot(key+'--failure.png'))}catch{}
  }
  appendFileSync(log,JSON.stringify(row)+'\n');
  console.log(`${index+1}/${cases.length} ${row.success?'OK':'FAIL'} ${key}${row.error?' '+row.error:''}`);
  if(row.error && /fetch failed|WebView observer unavailable|observer was replaced/.test(row.error)) throw Error('Renderer connection lost; resume after restoring it.');
}
