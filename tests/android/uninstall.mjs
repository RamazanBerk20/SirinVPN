import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {dirname} from 'node:path';
import {execFileSync} from 'node:child_process';
import {adb,openApp,evaluate,serial} from './bridge.mjs';
const fixture=JSON.parse(readFileSync(process.argv[2]));
const enrolled=JSON.parse(adb('exec-out','run-as','org.sirinvpn.client','cat','no_backup/acceptance-vps-result.json'));
assert.equal(fixture.fixture,enrolled.fixture);assert.equal(fixture.host,'10.0.2.2');
const ssh=command=>execFileSync('ssh',['-i',fixture.private_key_source,'-p',String(fixture.ssh_port),'-o','HostKeyAlias=android-vps',
  '-o','UserKnownHostsFile='+dirname(fixture.private_key_source)+'/known-hosts','-o','GlobalKnownHostsFile=/dev/null',
  '-o','StrictHostKeyChecking=yes','-o','BatchMode=yes','sirin@127.0.0.1',command],{encoding:'utf8'}).trim();
assert.equal(ssh('cat /etc/sirinvpn-acceptance-fixture'),fixture.fixture);
await openApp();
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
const profiles=(await call('list_servers')).ok;assert.equal(profiles.length,1);
const p=profiles[0];assert.equal(p.id,enrolled.server_id);assert.equal(p.role,'owner');assert.equal(p.name,'Android isolated VPS');assert.equal(p.endpoint.host,'10.0.2.2');
assert(!(await call('disconnect_server')).error);
const input={server_id:p.id,host:fixture.host,ssh_port:fixture.ssh_port,username:fixture.username,authentication:'saved',host_key_sha256:fixture.host_key_sha256};
assert((await call('uninstall_server',{input:{...input,confirmed:false}})).error);
assert.equal(ssh('systemctl is-active sirinvpn-server'),'active');
assert.equal((await call('list_servers')).ok.length,1);
assert(!(await call('uninstall_server',{input:{...input,confirmed:true}})).error);
assert.equal((await call('list_servers')).ok.length,0);
assert.equal(ssh('test ! -e /etc/sirinvpn && test ! -e /usr/local/lib/sirinvpn/sirinvpn-server && cat /etc/sirinvpn-acceptance-fixture'),fixture.fixture);
writeFileSync(`target/android-evidence/uninstall-${serial}.json`,JSON.stringify({serial,fixture:'disposable local VPS',passed:true,confirmationRequired:true,serverInstallationRemoved:true,localProfileRemoved:true,sshAndGuestRetained:true},null,2));
console.log('Unconfirmed uninstall was refused; confirmed fixture-only uninstall removed SirinVPN and retained SSH/the guest.');
