// Real emulator WebView, fictional profiles in the separate test APK. No VPN mutations.
import assert from 'node:assert/strict';
import {mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {adb,evaluate,delay,serial} from './bridge.mjs';
const out='target/android-evidence/mobile-redesign';
mkdirSync(out,{recursive:true});
const results=[];
const call=async(method,...args)=>{
  const response=await evaluate(`Promise.resolve().then(()=>window.__catalog.${method}(${args.map(a=>JSON.stringify(a)).join(',')})).then(value=>({value}),e=>({error:e.message}))`,9224);
  if(response.error) throw Error(method+': '+response.error);return response.value;
};
async function shot(name) {
  await call('settled');await delay(500);
  const info=await call('inspect');
  assert.equal(info.overflow,false,`${name}: horizontal overflow`);
  assert.deepEqual(info.unknown,[],`${name}: unsupported fixture operation`);
  const path=`${out}/${name}.png`;
  writeFileSync(path,execFileSync(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'exec-out','screencap','-p']));
  results.push({name,path,width:info.width,height:info.height,overflow:info.overflow,scope:'fictional presentation in Android WebView'});
  const ports=await call('scrollPorts');
  for(const port of ports) {
    if(port.height<100)continue;
    await call('scroll',port.index,port.total);await delay(250);
    writeFileSync(`${out}/${name}-scroll-${port.index}.png`,execFileSync(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'exec-out','screencap','-p']));
    await call('scroll',port.index,0);
  }
  console.log('PASS '+name);
}
async function mount(state={}) { await call('mount',{platform:'android',...state});await delay(500); }
async function click(selector) { await call('act',{css:selector}); }
for(const [width,height,scale] of [[390,844,1],[320,640,1],[390,844,2]]) {
  const prefix=`${width}x${height}-font${scale}`;
  adb('shell','settings','put','system','font_scale',String(scale));
  adb('shell','wm','size',`${width}x${height}`);adb('shell','wm','density','160');
  adb('shell','am','force-stop','org.sirinvpn.client.test');
  adb('shell','am','start','-n','org.sirinvpn.client.test/org.sirinvpn.client.CatalogActivity');
  await delay(1800);
  await evaluate(`document.documentElement.dataset.fontScale='${scale===2?'large':'normal'}'`,9224);
  await mount({empty:true});await shot(prefix+'-welcome');
  for(const [index,kind] of ['invitation','vps','backup','recovery'].entries()) {
    await click(`.mobile-add-server .mobile-list-row:nth-child(${index+1})`);
    assert.equal(await evaluate('document.querySelectorAll("[role=dialog]").length',9224),1);
    await shot(prefix+'-'+kind);
    await click('[aria-label="Back to connection options"]');
  }
  await mount();
  assert.equal(await evaluate('!!document.querySelector(".server-metrics")',9224),false);
  await shot(prefix+'-home');
  await click('.mobile-home-links button:last-child');await shot(prefix+'-connection-details');
  await click('.mobile-page-header button');
  assert.equal(await evaluate('location.hash',9224),'#home');
  await call('act',{text:'Settings'});await shot(prefix+'-settings');
  for(const category of ['General','Connection','Network','Keys & recovery','VPS maintenance']) {
    await click(`.mobile-choice-list button[aria-label="${category}"]`);
    await shot(prefix+'-settings-'+category.toLowerCase().replaceAll(/[^a-z]+/g,'-'));
    await click('.mobile-page-header button');
    assert.equal(await evaluate('location.hash',9224),'#settings');
  }
  await mount({profileCount:4,longNames:true});await call('act',{text:'Servers'});await shot(prefix+'-servers');
  await click('.collection-row > button:last-child');await shot(prefix+'-server-actions');
  await call('act',{text:'Rename locally'});await shot(prefix+'-rename');
  await mount();await call('act',{text:'Devices'});await shot(prefix+'-devices-owner');
  await click('.device-row-header > .icon-button');await shot(prefix+'-device-actions');
  await mount({role:'member'});await call('act',{text:'Devices'});await shot(prefix+'-devices-member');
  await mount({connected:false});await shot(prefix+'-disconnected');
}
adb('shell','settings','put','system','font_scale','1');
adb('shell','wm','size','390x844');
writeFileSync(out+'/presentation.json',JSON.stringify({bundleSha256:createHash('sha256').update(readFileSync('target/android-catalog/catalog.js')).digest('hex'),results},null,2));
writeFileSync(out+'/index.html','<!doctype html><meta charset="utf-8"><title>SirinVPN Android redesign</title><style>body{background:#080f1d;color:#e8efff;font:16px system-ui;margin:32px}main{display:flex;flex-wrap:wrap;gap:24px}figure{margin:0;max-width:390px}img{width:100%;border:1px solid #31425e;border-radius:16px}figcaption{margin:12px 0}</style><h1>Android redesign</h1><p>Fictional presentation fixtures, rendered in Android WebView. These images do not verify VPN connectivity.</p><main>'+results.map(r=>`<figure><figcaption>${r.name}</figcaption><img loading="lazy" src="${r.name}.png"></figure>`).join('')+'</main>');
