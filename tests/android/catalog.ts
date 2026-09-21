// Presentation fixtures only. This entry is packaged exclusively in the test APK.
import '../ui/catalog/main';
import '../../apps/desktop/src/styles/mobile-native.css';
import { id } from '../ui/catalog/data';
document.documentElement.classList.add('android');
const catalog=(window as any).__catalog;
const local=catalog.local.bind(catalog);
catalog.local=()=>({...local(),application_routing_backend:'android_packages',startup_service_enabled:false});
const call=catalog.call.bind(catalog);
catalog.call=async(name:string,args:any[]=[])=>{
  const result=await call(name,args);
  if(name==='releaseUpdateStatus') return {...result,installer_kind:'android',rollback_version:null};
  if(name==='getAppPreferences' || name==='setAppPreferences') return {...result,startup_available:false,tray_available:false};
  return result;
};
const native=catalog.native.bind(catalog);
catalog.native=async(command:string,args:any={})=>{
  if(command==='android_call') return {ok:await catalog.native(args.command,args.args)};
  if(command==='android_snapshot') return {status:catalog.local(),phase:catalog.state.connected?'connected':'disconnected',generation:1,sequence:1,quick_profile:id,operation:null};
  if(command==='android_confirm') return catalog.confirm(args.message,args.options);
  if(command==='android_save_document') return catalog.call('chooseSaveFile',[args.options]);
  if(command==='android_open_document') return catalog.call('chooseOpenFile',[args.options]);
  if(command==='android_secret_input') return catalog.protectedValue ?? 'native-secret:fictional-catalog-value';
  if(command==='android_show_secret' || command==='android_copy_secret' || command==='android_share_document') {
    catalog.prompts.push({kind:command,fixture:true});return null;
  }
  if(command==='android_choose_applications') return {mode:'include',packages:['com.example.mail']};
  if(command==='android_add_tile') {catalog.prompts.push({kind:command,fixture:true});return 'Open Quick Settings, tap Edit, and add SirinVPN.';}
  if(command==='android_vpn_settings' || command==='android_notification_settings') {catalog.prompts.push({kind:command,fixture:true});return null;}
  return native(command,args);
};
const act=catalog.act.bind(catalog);
catalog.act=async(action:any)=>{
  if(action.fill!==undefined && action.label) {
    const button=Array.from(document.querySelectorAll<HTMLButtonElement>('button[aria-label]')).find(button=>button.getAttribute('aria-label')==='Enter '+action.label);
    if(button) {catalog.protectedValue='native-secret:fictional-catalog-'+action.fill.length;button.scrollIntoView({block:'center'});button.click();await new Promise(resolve=>setTimeout(resolve,200));return;}
  }
  return act(action);
};
void catalog.mount({platform:'android'});
