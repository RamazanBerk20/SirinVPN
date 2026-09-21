import { assertVisible, settled, visibleBox } from "./visibility";
import React from 'react';
import {createRoot} from 'react-dom/client';
import '@fontsource-variable/inter';
import '@fontsource-variable/jetbrains-mono';
import '../../../apps/desktop/src/styles.css';
import App from '../../../apps/desktop/src/App';
import {clearMembershipCache} from '../../../apps/desktop/src/features/devices/membershipCache';
import {CatalogBridge} from './bridge';
import {initialState,merge} from './data';
const catalog:any=new CatalogBridge();
(window as any).__catalog=catalog;
const root=createRoot(document.getElementById('root')!);
let generation=0;
const normalize=(value:string)=>(value??'').replace(/\s+/g,' ').trim();
const visible=(el:Element)=>el.getClientRects().length>0&&getComputedStyle(el).visibility!=='hidden';
const delay=(ms=120)=>new Promise(resolve=>setTimeout(resolve,ms));
catalog.assertVisible=assertVisible;
catalog.settled=settled;
catalog.mount=async(options:any={})=>{
  root.render(null);await delay(20);clearMembershipCache();
  catalog.ready=false;catalog.state=initialState(options);catalog.prompts=[];
  localStorage.clear();history.replaceState(null,'','#home');
  document.documentElement.style.fontSize='';
  root.render(<App key={++generation}/>);
  await delay(550);await document.fonts.ready;for(const el of document.querySelectorAll('*'))if(el.scrollTop)el.scrollTop=0;catalog.ready=true;return catalog.inspect();
};
catalog.inspect=()=>({title:document.title,text:document.body.innerText,unknown:catalog.state.unknown,calls:catalog.state.calls.map((c:any)=>c.name),dialogs:catalog.prompts,
  controls:Array.from(document.querySelectorAll('button,input,select,textarea,summary')).filter(visible).map((el:any)=>({tag:el.tagName,text:normalize(el.innerText),aria:el.getAttribute('aria-label'),type:el.type,disabled:el.disabled,placeholder:el.placeholder,value:el.value,label:normalize(el.closest('label')?.innerText??''),options:el instanceof HTMLSelectElement?Array.from(el.options).map(o=>({value:o.value,label:o.label})):undefined})),
  width:innerWidth,height:innerHeight,overflow:document.documentElement.scrollWidth>innerWidth});
catalog.find=(action:any)=>{
  const scope=action.scope?document.querySelector(action.scope):document;
  if(!scope)throw Error('Missing scope '+action.scope);
  if(action.css){const found=Array.from(scope.querySelectorAll(action.css)).filter(visible);const el=found[action.index??0];if(!el)throw Error('Missing selector '+action.css);return el;}
  let found:Array<any>=[];
  if(action.label){
    const labels=Array.from(scope.querySelectorAll('label')).filter(visible).filter((el:any)=>action.exact?normalize(el.innerText)===action.label:normalize(el.innerText).startsWith(action.label));
    found=labels.map((el:any)=>el.querySelector('input,select,textarea')??document.getElementById(el.htmlFor)).filter(Boolean);
  }else{
    found=Array.from(scope.querySelectorAll(action.role?`[role="${action.role}"]`: 'button,summary,[role="menuitem"],a,input[type="checkbox"]')).filter(visible).filter((el:any)=>{
      const text=normalize(el.getAttribute('aria-label')||el.innerText||'');return action.exact===false?text.includes(action.text):text===action.text;
    });
  }
  if(!found.length)throw Error('Missing control '+JSON.stringify(action));return found[action.index??0];
};
catalog.act=async(action:any)=>{
  if(action.patch){catalog.state=merge(catalog.state,action.patch);await delay(action.wait??100);return;}
  if(action.hash){history.pushState(null,'',action.hash);dispatchEvent(new PopStateEvent('popstate'));await delay();return;}
  if(action.details){for(const el of document.querySelectorAll('details'))(el as HTMLDetailsElement).open=action.details==='open';await delay();return;}
  if(action.js){(0,eval)(action.js);await delay(action.wait??120);return;}
  if(action.wait){await delay(action.wait);return;}
  let el:any;
  for(let attempt=0;attempt<30;attempt++){
    try{el=catalog.find(action);break;}catch(error){if(attempt===29)throw error;await delay(100);}
  }
  for(let attempt=0;el.matches(':disabled')&&!action.allowDisabled&&attempt<10;attempt++){await delay(100);el=catalog.find(action);}
  if((el.matches(':disabled')||el.getAttribute("aria-disabled")==="true")&&!action.allowDisabled)throw Error('Control disabled '+JSON.stringify(action));
  el.scrollIntoView({block:'center',inline:'nearest'});await settled();
  if(!visibleBox(el))throw Error('Control is clipped or obscured '+JSON.stringify(action));
  if(action.fill!==undefined){
    const proto=el instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:el instanceof HTMLSelectElement?HTMLSelectElement.prototype:HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto,'value')!.set!.call(el,action.fill);el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));
  }else if(action.check!==undefined){if(el.checked!==action.check)el.click();}
  else el.click();
  await delay(action.settle??180);
};
catalog.actions=async(actions:any[])=>{for(const action of actions)await catalog.act(action);await settled();return catalog.inspect();};
window.confirm=(message)=>{catalog.prompts.push({kind:'confirm',message});return catalog.state.confirmResponse??true;};
catalog.confirm=(message:string,options:any)=>{catalog.prompts.push({kind:'confirm',message,options});return catalog.state.confirmResponse??true;};
window.prompt=(message,value)=>{catalog.prompts.push({kind:'prompt',message,value});return catalog.state.promptResponse??'Renamed device';};
window.alert=(message)=>{catalog.prompts.push({kind:'alert',message});};
Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async(value:string)=>{
  if(catalog.state.clipboardError)throw Error('Clipboard unavailable');catalog.clipboard=value;
}}});
catalog.scrollPorts=()=>{
 for(const el of document.querySelectorAll('[data-catalog-scroll]'))el.removeAttribute('data-catalog-scroll');
 const dialogs=Array.from(document.querySelectorAll('[role="dialog"]')).filter(visible);const front=document.querySelector('[role="menu"]')??dialogs.at(-1);
 return Array.from(new Set([document.scrollingElement,...document.querySelectorAll('*')])).filter((el:any)=>el&&(!front||front.contains(el)||front===el)&&visible(el)&&el.scrollHeight>el.clientHeight+4&&(el===document.scrollingElement||['auto','scroll'].includes(getComputedStyle(el).overflowY))).map((el:any,index)=>{
  el.setAttribute('data-catalog-scroll',String(index));return{index,tag:el.tagName,class:el.className,height:el.clientHeight,total:el.scrollHeight,top:el.scrollTop,box:el.getBoundingClientRect().toJSON()};
 });
};
catalog.scroll=async(index:number,top:number)=>{const el=document.querySelector(`[data-catalog-scroll="${index}"]`)!;el.scrollTop=top;await delay(160);return el.scrollTop;};
catalog.nativeDialog=(item:any)=>setTimeout(()=>catalog.originalDialogs[item.kind](item.message,item.value),100);
catalog.mount({platform:'desktop'});
