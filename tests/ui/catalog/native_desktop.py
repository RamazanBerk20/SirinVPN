"""Capture native WebKit dialogs and native Tauri menu previews in the isolated shell."""
import json,os,subprocess,time,sys,re
from pathlib import Path
from capture import Engine,Inspector,OUT
from scenarios import scenarios

class NativeDesktop(Engine):
 def __init__(self):
  self.platform='desktop';self.browser=False;self.playwright=None;self.inspector=Inspector(int(os.environ.get('SIRINVPN_CATALOG_INSPECTOR','9238')))
  self.inspector.evaluate("location.href='http://127.0.0.1:1420/?platform=desktop&native='+Date.now()");time.sleep(2)
  from webkit_inspector import wait_for
  wait_for(lambda:self.inspector.evaluate('Boolean(window.__catalog?.ready)'))
  self.window=subprocess.check_output(['xdotool','search','--onlyvisible','--name','^SirinVPN$'],env=self.env,text=True).split()[0]
  subprocess.run(['xdotool','windowmove',self.window,'0','0','windowsize',self.window,'1280','900','windowfocus',self.window],env=self.env,check=True)
  time.sleep(.4)
  self.inspector.evaluate("history.replaceState(null,'','/')")
 @property
 def env(self):return {**os.environ,'DISPLAY':os.environ.get('SIRINVPN_CATALOG_DISPLAY',':87')}
 def shot(self,path):
  path.parent.mkdir(parents=True,exist_ok=True)
  subprocess.run(['import','-window',getattr(self,'capture_window','root'),str(path)],env=self.env,check=True,timeout=20)
  import hashlib
  return {'path':str(path.relative_to(OUT)),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
 def dismiss(self):
  visible=subprocess.check_output(['xdotool','search','--onlyvisible','--name','.'],env=self.env,text=True).split()
  for wid in reversed(visible):
   if wid!=self.window and any(word in subprocess.check_output(['xdotool','getwindowname',wid],env=self.env,text=True) for word in ['Choose an encrypted','Save encrypted','Choose a private']):subprocess.run(['xdotool','windowfocus',wid,'key','Escape'],env=self.env);time.sleep(.08)
  subprocess.run(['xdotool','key','Escape'],env=self.env,check=True);time.sleep(.15)
 def native_dialog(self,prompt):
  if prompt['kind']=='confirm' and prompt.get('options'):
   options=prompt['options']
   args={'title':options.get('title','SirinVPN'),'message':prompt['message'],'kind':options.get('kind','warning'),'buttons':{'OkCancelCustom':[options.get('okLabel','OK'),options.get('cancelLabel','Cancel')]}}
   self.inspector.evaluate("setTimeout(()=>window.__TAURI_INTERNALS__.invoke('plugin:dialog|message',"+json.dumps(args)+").then(v=>window.__nativeDialogResult=v).catch(e=>window.__nativeError=String(e)),100)")
   time.sleep(.6)
   return
  self.inspector.evaluate("(()=>{window.__nativeFrame?.remove();const f=document.createElement('iframe');f.style.display='none';document.body.append(f);window.__nativeFrame=f;setTimeout(()=>f.contentWindow["+json.dumps(prompt['kind'])+"]("+json.dumps(prompt['message'])+","+json.dumps(prompt.get('value',''))+"),100)})()")
  time.sleep(.4)
 def menu(self,items):
  rid=self.inspector.invoke('plugin:menu|new',{'kind':'Menu','options':{'items':items},'handler':'__CHANNEL__:1'})[0]
  self.inspector.evaluate("setTimeout(()=>window.__TAURI_INTERNALS__.invoke('plugin:menu|popup',"+json.dumps({'rid':rid,'kind':'Menu','window':'main','at':{'Logical':{'x':820,'y':60}}})+").catch(e=>window.__nativeError=String(e)),100)")
  time.sleep(.45)


def record(result):
 with (OUT/'native-results.jsonl').open('a') as f:f.write(json.dumps(result,ensure_ascii=False)+'\n')
 print(result['id'], 'OK' if result['success'] else result.get('error'),flush=True)

def main():
 e=NativeDesktop();cases={c['id']:c for c in scenarios('desktop')}
 # Use the actual production confirmation strings recorded by the API fixture journeys.
 observed={}
 for line in (OUT/'desktop-results.jsonl').read_text().splitlines():
  item=json.loads(line)
  if item.get('observed',{}).get('dialogs'):observed[item['id']]=item
 unique=set()
 for key,item in observed.items():
  if os.environ.get('CATALOG_ONLY_TRAY'):continue
  if key not in cases:continue
  prompts=item['observed']['dialogs']
  for n,prompt in enumerate(prompts):
   identity=(prompt['kind'],prompt['message'])
   if identity in unique:continue
   unique.add(identity)
   case=cases[key];result={'id':'native-'+key+f'-{n+1}','family':'native-confirmations','platform':'desktop','success':False,'description':prompt['message'],'data_source':'Production confirmation text; fictional fixture data','renderer':'Native WebKitGTK JavaScript dialog in isolated Tauri debug shell','files':[]}
   try:
    e.call('mount',{**case['state'],'confirmResponse':False,'promptResponse':'','platform':'desktop'})
    snapshot=e.call('actions',case['actions'])
    current=next((p for p in snapshot['dialogs'] if p['message']==prompt['message']),prompt)
    if current.get('options'):result['renderer']='Native Tauri GTK confirmation dialog'
    e.native_dialog(current)
    result['files']=[e.shot(OUT/'desktop/native-confirmations'/(result['id']+'.png'))]
    e.dismiss();result['success']=True
   except Exception as error:result['error']=str(error);e.dismiss()
   record(result)
 # Native tray menu renderer; captions and enabled states mirror model.rs/build_menu.
 def row(text,enabled=True,**kw):return {'text':text,'enabled':enabled,**kw}
 sep={'item':'Separator'}
 states=[
  ('disconnected','Disconnected','Kill switch: Off','Connect to My private VPS','Quit app',False,False,False,False),
  ('connected','Connected to My private VPS','Kill switch: Armed','Disconnect…','Quit app (VPN keeps running)',True,False,False,False),
  ('connecting','Connecting to My private VPS','Kill switch: Armed','Cancel connection…','Quit app (connection service keeps running)',True,False,True,False),
  ('recovering','Reconnecting to My private VPS','Kill switch: Blocking traffic','Stop reconnecting…','Quit app (recovery keeps running)',True,False,True,False),
  ('paused','Connection paused · My private VPS','Kill switch: Blocking traffic','Resume connection','Quit app (connection stays paused)',True,False,True,False),
  ('unavailable','Connection status unavailable','Kill switch: Status unknown',None,'Quit app (VPN status unknown)…',False,False,False,False),
  ('busy','Connected to My private VPS','Kill switch: Armed','Disconnect…','Quit app (VPN keeps running)',True,True,False,False),
  ('component-update','Connected to My private VPS','Kill switch: Status unknown',None,'Quit app (VPN keeps running)',True,False,False,True),
  ('interrupted','Connection interrupted · My private VPS','Kill switch: Enforcement failed','Cancel connection…','Quit app (connection service keeps running)',True,False,True,False),
 ]
 for name,status,protection,primary,quitlabel,active,busy,extra,update in states:
  result={'id':'native-tray-menu-'+name,'family':'native-tray','platform':'desktop','success':False,'description':status,'data_source':'Native menu preview using production tray labels and synthetic state; network actions are unbound','renderer':'Tauri native GTK menu','files':[]}
  try:
   e.call('mount',{'platform':'desktop','connected':active or name=='unavailable','componentUpdate':update,'local':{'state':'unknown' if name=='unavailable' else 'degraded' if name in ['paused','interrupted'] else 'connecting' if name in ['connecting','recovering'] else 'connected' if active else 'disconnected','kill_switch_enabled':active and not update,'kill_switch_state':'unknown' if name=='unavailable' or update else 'failed' if name=='interrupted' else 'blocking' if name in ['recovering','paused'] else 'armed' if active else 'off','supervisor_status_known':name!='unavailable','auto_reconnect_enabled':name in ['recovering','paused'],'waiting_for_user':name=='paused','recovery_in_progress':name=='recovering','connection_control_supported':not update}})
   items=[row(status),row(protection)]
   if busy:items+=[row('Connection operation in progress…',False)]
   items+=[sep,row('Open SirinVPN')]
   if primary:items+=[row(primary,not busy)]
   if extra:items+=[row('Disconnect…',not busy)]
   if active and not extra and not update:items+=[row('Reconnect',not busy)]
   if update:items+=[row('Review local VPN component update…')]
   servers=[row('My private VPS',not active and not busy and name!='unavailable',checked=active),row('Travel VPN',not busy and not update and name!='unavailable',checked=False),sep,row('Manage servers…')]
   items+=[{'text':'Switch server' if active else 'Connect to server','items':servers},sep,row('Connection settings…'),row('Settings…'),row('Diagnostics…'),sep,row(quitlabel,not busy)]
   if active:items+=[row('Disconnect and quit…',not busy and not update)]
   e.menu(items)
   result['files']=[e.shot(OUT/'desktop/native-tray'/(result['id']+'.png'))]
   e.dismiss();result['success']=True
  except Exception as error:result['error']=str(error);e.dismiss()
  record(result)
 # Native file pickers use a dedicated folder containing only fictional examples.
 folder=Path('/tmp/SirinVPN-Screenshot-Examples-2026-09-20');folder.mkdir(exist_ok=True)
 (folder/'example-device.sirinbackup').write_text('Fictional screenshot fixture. No private identity.')
 for action,title,extensions in [('open','Choose an encrypted device backup',['sirinbackup']),('save','Save encrypted device backup',['sirinbackup']),('open','Choose an encrypted VPS backup',['sirvps']),('save','Save encrypted VPS backup',['sirvps']),('open','Choose an encrypted recovery package',['sirrec']),('save','Save encrypted recovery package',['sirrec'])]:
  if os.environ.get('CATALOG_ONLY_TRAY'):continue
  key='native-file-'+action+'-'+extensions[0]
  result={'id':key,'family':'native-file-dialogs','platform':'desktop','success':False,'description':title,'renderer':'Native Tauri file dialog','data_source':'Dedicated fictional example directory','files':[]}
  try:
   e.call('mount',{'platform':'desktop'})
   options={'title':title,'defaultPath':str(folder/('example.'+extensions[0])),'filters':[{'name':'SirinVPN encrypted backup','extensions':extensions}]}
   e.inspector.evaluate("setTimeout(()=>window.__TAURI_INTERNALS__.invoke('plugin:dialog|"+action+"',"+json.dumps({'options':options})+").then(v=>window.__fileOutcome=v).catch(err=>window.__fileError=String(err)),100)")
   time.sleep(1)
   result['files']=[e.shot(OUT/'desktop/native-file-dialogs'/(key+'.png'))]
   e.dismiss();result['success']=True
  except Exception as error:result['error']=str(error);e.dismiss()
  record(result)
 e.close()

if __name__=='__main__':main()
