"""Native GTK selectors, server submenus, and compact window layouts."""
import os,json,time,subprocess
from pathlib import Path
from native_desktop import NativeDesktop,record
from capture import OUT
from scenarios import scenarios, click, fill, settings

e=NativeDesktop();cases={c['id']:c for c in scenarios('desktop')}
for key,items,state in [
 ('no-saved-servers',[{'text':'Disconnected'},{'text':'Kill switch: Off'},{'item':'Separator'},{'text':'Open SirinVPN'},{'text':'Add server…'},{'text':'Connect to server','items':[{'text':'Manage servers'}]},{'text':'Settings'},{'item':'Separator'},{'text':'Quit app'}],{'empty':True}),
 ('legacy-session',[{'text':'Connected to My private VPS'},{'text':'Kill switch: On'},{'text':'More controls on next connection','enabled':False},{'item':'Separator'},{'text':'Open SirinVPN'},{'text':'Disconnect…'},{'text':'Switch server','items':[{'text':'My private VPS','checked':True,'enabled':False},{'text':'Travel VPN','enabled':False},{'text':'Manage servers'}]},{'text':'Settings'},{'text':'Quit app · VPN keeps running'},{'text':'Disconnect and quit…'}],{}),
]:
 r={'id':'native-tray-menu-'+key,'platform':'desktop','family':'native-tray','description':key.replace('-',' ')+' tray menu','success':False,'files':[],'renderer':'Tauri native GTK menu','data_source':'Production tray labels and synthetic state; actions unbound'}
 try:
  e.call('mount',state);e.menu(items);r['files']=[e.shot(OUT/'desktop/native-tray'/(r['id']+'.png'))];r['success']=True
 except Exception as err:r['error']=str(err)
 record(r);e.dismiss()
for active in [False,True]:
 key='native-tray-server-submenu-'+('connected' if active else 'disconnected')
 e.call('mount',{'platform':'desktop','connected':active,'profileCount':3})
 e.menu([{'text':'Connected to My private VPS' if active else 'Disconnected'},{'text':'Switch server' if active else 'Connect to server','items':[{'text':'My private VPS','checked':active,'enabled':not active},{'text':'Amsterdam VPS'},{'text':'Travel VPN'},{'item':'Separator'},{'text':'Manage servers'}]},{'text':'Settings'}])
 subprocess.run(['xdotool','mousemove','915','99'],env=e.env,check=True);time.sleep(.8)
 record({'id':key,'platform':'desktop','family':'native-tray','description':'Native tray server submenu','success':True,'files':[e.shot(OUT/'desktop/native-tray'/(key+'.png'))],'renderer':'Tauri native GTK menu','data_source':'Native menu preview with production labels and fictional server data; actions unbound'})
 e.dismiss()

# Preview native-only tray confirmations without invoking any VPN action.
# Each entry is (key, dialog title, confirm button, message), as in native.tray.confirm.* of native.json.
disconnect_message='Any traffic block is lifted, and the VPN stays off until you connect again. Other devices stay connected.'
tray_prompts=[
 ('disconnect','Disconnect the VPN?','Disconnect',disconnect_message),
 ('disconnect-and-quit','Disconnect and quit?','Disconnect and quit',disconnect_message),
 ('quit-status-unknown','Quit SirinVPN?','Quit','Status unknown\nClosing the app doesn’t stop the VPN, reconnecting or the kill switch.'),
]
for enabled in [False,True]:
 message='The kill switch keeps blocking traffic until you reconnect or disconnect.' if enabled else 'The kill switch is off, so traffic bypasses the VPN until you reconnect.'
 tray_prompts.append(('pause-protection-'+str(enabled).lower(),'Stop connection attempts?','Stop attempts',message))
 message='Your current settings carry over. The kill switch stays on during the switch.' if enabled else 'Your current settings carry over. The kill switch is off, so traffic may bypass the VPN during the switch.'
 tray_prompts.append(('switch-protection-'+str(enabled).lower(),'Switch to Travel VPN?','Switch',message))
for key,title,label,message in tray_prompts:
 r={'id':'native-tray-confirm-'+key,'platform':'desktop','family':'native-confirmations','description':label+' tray confirmation','success':False,'files':[],'renderer':'Native Tauri dialog','data_source':'Production tray confirmation text; action is unbound'}
 try:
  e.call('mount',{'platform':'desktop'})
  e.native_dialog({'kind':'confirm','message':message,'options':{'title':title,'okLabel':label,'cancelLabel':'Cancel','kind':'info'}})
  r['files']=[e.shot(OUT/'desktop/native-confirmations'/(r['id']+'.png'))];r['success']=True
 except Exception as err:r['error']=str(err)
 record(r);e.dismiss()

# Use only the private app bus, served by an isolated native notification daemon.
pid=subprocess.check_output(['xdotool','getwindowpid',e.window],env=e.env,text=True).strip()
bus=next(item.split('=',1)[1] for item in (Path('/proc')/pid/'environ').read_bytes().decode().split('\0') if item.startswith('DBUS_SESSION_BUS_ADDRESS='))
notification_env={**e.env,'DBUS_SESSION_BUS_ADDRESS':bus}
for key,body in [('connected','VPN connected'),('disconnected','VPN disconnected'),('recovering','Connection interrupted. Reconnecting…'),('unavailable','Couldn’t read the VPN status. Open SirinVPN to check.'),('test','Notifications are ready. Connection alerts will appear here.')]:
 r={'id':'native-notification-'+key,'platform':'desktop','family':'native-notifications','description':body,'success':False,'files':[],'renderer':'Native Xfce notification daemon in isolated X session','data_source':'Production notification title, body and icon; simulated connection transition'}
 try:
  e.call('mount',{'platform':'desktop','connected':key!='disconnected'})
  subprocess.run(['notify-send','--app-name=SirinVPN','--icon='+str(Path(__file__).resolve().parents[3]/'apps/desktop/src-tauri/icons/128x128.png'),'--expire-time=1800','SirinVPN',body],env=notification_env,check=True,timeout=10)
  time.sleep(.7)
  r['files']=[e.shot(OUT/'desktop/native-notifications'/(r['id']+'.png'))];r['success']=True
  time.sleep(1.6)
 except Exception as err:r['error']=str(err)
 record(r)
for key,actions,target,state in [
 ('invitation-access',[{'text':'Devices'},{'text':'Invite member'}],{'css':'select','index':0},{}),
 ('invitation-lifetime',[{'text':'Devices'},{'text':'Invite member'}],{'css':'select','index':1},{}),
 ('wifi-server',settings('desktop','general'),{'css':'select[aria-label="Auto-connect server"]'},{'profileCount':4}),
 ('port-protocol',settings('desktop','network'),{'label':'Protocol'},{}),
 ('port-target-device',settings('desktop','network'),{'css':'.port-forward-form select','index':1},{}),
 ('weekly-access-day',cases['weekly-day-time-controls']['actions'],{'label':'Day 1'},cases['weekly-day-time-controls']['state']),
 ('vps-release-channel',cases['installed-release-and-schedule']['actions'],{'label':'Release channel'},cases['installed-release-and-schedule']['state']),
 ]:
 r={'id':'native-select-'+key,'platform':'desktop','family':'native-selects','description':key.replace('-',' ').capitalize()+' expanded selection','files':[],'success':False,'renderer':'Native WebKitGTK control','data_source':'Unchanged production UI with fictional API responses'}
 try:
  e.call('mount',{'platform':'desktop',**state});e.call('actions',actions);e.call('act',{'wait':600})
  b=e.evaluate('(()=>{const el=window.__catalog.find('+json.dumps(target)+');el.scrollIntoView({block:"center"});return el.getBoundingClientRect().toJSON()})()')
  subprocess.run(['xdotool','mousemove',str(round(b['x']+b['width']/2)),str(round(b['y']+b['height']/2)),'click','1'],env=e.env,check=True);time.sleep(.5)
  r['files']=[e.shot(OUT/'desktop/native-selects'/(r['id']+'.png'))];r['success']=True
 except Exception as err:r['error']=str(err)
 e.dismiss();record(r)
# Native popups are separate windows, so capture the complete isolated display.
e.capture_window='root'
for key,actions,target,state in [
 ('access-expiration-calendar',cases['device-limit-and-expiration']['actions'],{'css':'input[type="datetime-local"]'},cases['device-limit-and-expiration']['state']),
 ('weekly-time-picker',cases['weekly-day-time-controls']['actions'],{'css':'input[type="time"]'},cases['weekly-day-time-controls']['state']),
]:
 r={'id':'native-'+key,'platform':'desktop','family':'native-selects','description':key.replace('-',' '),'success':False,'files':[],'renderer':'Native WebKitGTK date/time input','data_source':'Production control with fictional data'}
 try:
  e.call('mount',state);e.call('actions',actions)
  b=e.evaluate('(()=>{const el=window.__catalog.find('+json.dumps(target)+');el.scrollIntoView({block:"center"});el.focus();return el.getBoundingClientRect().toJSON()})()')
  subprocess.run(['xdotool','mousemove',str(round(b['right']-15)),str(round(b['y']+b['height']/2)),'click','1'],env=e.env,check=True);time.sleep(.6)
  r['files']=[e.shot(OUT/'desktop/native-selects'/(r['id']+'.png'))];r['success']=True
 except Exception as err:r['error']=str(err)
 record(r);e.dismiss()

for key,scenario,selector in [
 ('minimize-window','connected-home','[title="Minimize"]'),
 ('maximize-window','connected-home','[title="Maximize"]'),
 ('close-window','connected-home','.titlebar-close'),
 ('resume-policy','recovery-waiting-for-user','[title^="Resume with the current"]'),
 ('busy-dialog-close','install-authenticated-app-release-in-progress','[title="Wait for the current task to finish"]'),
]:
 r={'id':'tooltip-'+key,'platform':'desktop','family':'tooltips','description':key.replace('-',' ')+' tooltip','success':False,'files':[],'renderer':'Native WebKitGTK tooltip','data_source':'Production title attribute'}
 try:
  c=cases[scenario];e.call('mount',c['state']);e.call('actions',c['actions'])
  b=e.evaluate('(()=>{const el=document.querySelector('+json.dumps(selector)+');el.scrollIntoView({block:"center"});return el.getBoundingClientRect().toJSON()})()')
  subprocess.run(['xdotool','mousemove',str(round(b['x']+b['width']/2)),str(round(b['y']+b['height']/2))],env=e.env,check=True);time.sleep(1.3)
  r['files']=[e.shot(OUT/'desktop/tooltips'/(r['id']+'.png'))];r['success']=True
 except Exception as err:r['error']=str(err)
 record(r)
 subprocess.run(['xdotool','mousemove','1275','895'],env=e.env,check=True)

subprocess.run(['xdotool','windowsize',e.window,'900','680'],env=e.env,check=True);time.sleep(.4)
e.capture_window=e.window
for key in ['connected-home','disconnected-home','saved-server-list','owner-device-list','general-settings','connection-settings','network-settings','recovery-settings','maintenance-settings','first-launch-my-vps','first-launch-invitation','first-launch-backup','first-launch-recovery-key','first-launch-app-settings','invitation-created-qr-and-code','invitation-enlarged-qr','member-policy-editor','weekly-day-time-controls','recovery-qr-enlarged','create-offline-recovery-key-completed','device-export-ready','vps-backup-ssh-details','vps-restore-ssh-details','vps-repair-ssh-details','first-release-verified','desktop-app-update-dialog','desktop-verify-app-release-completed','rotate-device-keys','move-devices-to-a-new-vps-address','remove-saved-server-or-uninstall-sirinvpn','diagnostic-report-failures','https-transport-fields','application-launch-arguments','os-wifi-names-existing-trust-records','os-wifi-names-unavailable','os-wifi-names-unbroken']:
 if key not in cases:continue
 c=cases[key];r={**c,'id':'compact-'+key,'platform':'desktop','family':'compact-window','success':False,'files':[],'renderer':'Native WebKitGTK at compact window size','data_source':'Unchanged production UI with fictional API responses'}
 try:
  e.call('mount',{'platform':'desktop',**c['state']});r['observed']=e.call('actions',c['actions']);r['files']=e.capture(r)
  if c.get('expand'):
   e.call('act',{'details':'open'});r['files']+=e.capture(r,'--expanded-details')
  r['success']=True
 except Exception as err:r['error']=str(err)
 record(r)
subprocess.run(['xdotool','windowsize',e.window,'1280','900'],env=e.env,check=True)
e.close()
