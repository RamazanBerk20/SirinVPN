import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdirSync,writeFileSync} from 'node:fs';
import {adb,delay,serial} from './bridge.mjs';

const pkg='org.sirinvpn.client',out='target/android-evidence/notification-shade';
const marker='no_backup/notification-test-stage';
mkdirSync(out,{recursive:true});
adb('shell','run-as',pkg,'rm','-f',marker);
adb('shell','pm','grant',pkg,'android.permission.POST_NOTIFICATIONS');
adb('shell','cmd','notification','post','-t','Unrelated notification','sirin-shade-test','Keep this notification visible');
const child=spawn(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,[
  '-s',serial,'shell','am','instrument','-w','-e','class','org.sirinvpn.client.NotificationActionTest',
  pkg+'.test/androidx.test.runner.AndroidJUnitRunner']);
let log='',finished=false,pinSet=false;
child.stdout.on('data',s=>{log+=s;});child.stderr.on('data',s=>{log+=s;});
const completion=new Promise(resolve=>child.on('exit',code=>{finished=true;resolve(code);}));
async function stage(value) {
  for(let n=0;n<240;n++) {
    assert(!finished,log);
    if(adb('shell','run-as',pkg,'sh','-c','cat '+marker+' 2>/dev/null || true')===value)return;
    await delay(250);
  }
  throw Error('Native stage timed out: '+value);
}
function nodes() {
  adb('shell','uiautomator','dump','/data/local/tmp/sirin-shade-test.xml');
  return [...adb('exec-out','cat','/data/local/tmp/sirin-shade-test.xml').matchAll(/<node\b[^>]*>/g)]
    .map(([n])=>Object.fromEntries([...n.matchAll(/([\w-]+)="([^"]*)"/g)].map(m=>[m[1],m[2]])));
}
const bounds=node=>node.bounds.match(/\d+/g).map(Number);
function tap(node) {
  assert(node,'Notification control was not visible');
  const [x,y,r,b]=bounds(node);adb('shell','input','tap',String((x+r)>>1),String((y+b)>>1));
}
try {
  for(const [phase,label] of [['connected','Disconnect'],['reconnecting','Stop attempts']]) {
    await stage(phase);
    adb('shell','cmd','statusbar','collapse');adb('shell','cmd','statusbar','expand-notifications');await delay(500);
    let visible=nodes();
    const button=()=>visible.find(n=>n.text.toLowerCase()===label.toLowerCase()&&n.clickable==='true');
    if(!button()) {
      const name=visible.find(n=>['android:id/title','android:id/app_name_text'].includes(n['resource-id'])&&n.text==='SirinVPN');
      assert(name,'SirinVPN notification was not visible');
      const [,y,,b]=bounds(name),middle=(y+b)/2;
      tap(visible.find(n=>n['resource-id']==='android:id/expand_button'&&bounds(n)[1]<=middle&&bounds(n)[3]>=middle));
      await delay(400);visible=nodes();
    }
    tap(button());await stage(phase+'-done');await delay(500);
    assert.match(adb('shell','dumpsys','window'),/mCurrentFocus=.*NotificationShade/,'Action collapsed the panel');
    assert(adb('shell','cmd','notification','list').includes('sirin-shade-test'),'Other notification was removed');
    console.log('PASS: '+label+' removes its notification and keeps the panel and other notification.');
    adb('shell','cmd','statusbar','collapse');
    adb('shell','run-as',pkg,'sh','-c','echo continue > '+marker);
  }
  await stage('lock');
  pinSet=true;adb('shell','locksettings','set-pin','2468');
  adb('shell','input','keyevent','KEYCODE_SLEEP');
  assert.equal(await completion,0);assert.match(log,/OK \(1 test\)/);
  writeFileSync(out+'/results.json',JSON.stringify({serial,passed:true,disconnectKeepsPanelOpen:true,stopAttemptsKeepsPanelOpen:true,unrelatedNotificationRetained:true,foregroundNotificationRemoved:true,lockedActionsRequireAuthentication:true,olderActionCannotBypassLock:true,noEndpointContacted:true},null,2)+'\n');
  console.log('PASS: lock authentication and stale unlocked-action guard.');
} finally {
  writeFileSync(out+'/instrumentation.log',log);
  if(!finished)adb('shell','am','force-stop',pkg);
  if(pinSet)adb('shell','locksettings','clear','--old','2468');
  adb('shell','input','keyevent','KEYCODE_WAKEUP');adb('shell','wm','dismiss-keyguard');
}
