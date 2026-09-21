import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { adb, evaluate, openApp, serial } from './bridge.mjs';

// Administrative tests are allowed only on vps_lab.py's disposable, pinned guest.
const fixture=JSON.parse(readFileSync(process.argv[2] ?? '.cache/android-vps-20260920/fixture.json'));
const enrolled=JSON.parse(adb('exec-out','run-as','org.sirinvpn.client','cat','no_backup/acceptance-vps-result.json'));
assert.equal(fixture.fixture,enrolled.fixture);
assert.equal(fixture.host,'10.0.2.2');
const marker=execFileSync('ssh',['-i',fixture.private_key_source,'-p',String(fixture.ssh_port),
  '-o','HostKeyAlias=android-vps','-o','UserKnownHostsFile='+dirname(fixture.private_key_source)+'/known-hosts',
  '-o','GlobalKnownHostsFile=/dev/null','-o','StrictHostKeyChecking=yes','-o','BatchMode=yes',
  'sirin@127.0.0.1','cat /etc/sirinvpn-acceptance-fixture'],{encoding:'utf8'}).trim();
assert.equal(marker,fixture.fixture);
await openApp();
const rows=[];
async function check(name,expression) {
  const result=await evaluate(`(async()=>{try {${expression};return {passed:true}} catch(e) {return {error:String(e.message)}}})()`);
  assert.equal(result?.error,undefined,name+': '+result?.error);
  assert(result?.passed,name);
  rows.push({name,passed:true});
  writeFileSync('target/android-evidence/owner.json',JSON.stringify({serial,fixture:'disposable local VPS',rows},null,2));
  console.log(name+': passed');
}
await check('Owner connection and capabilities',`
  window.acceptance={id:${JSON.stringify(enrolled.server_id)}};
  acceptance.call=async(command,args={})=>{const r=await window.__TAURI_INTERNALS__.invoke('android_call',{command,args});if(r.error) throw Error(command+': '+r.error);return r.ok};
  acceptance.assert=(value,message)=>{if(!value) throw Error(message)};
  const a=acceptance,p=(await a.call('list_servers')).find(p=>p.id===a.id);
  a.assert(p?.name==='Android isolated VPS' && p.endpoint.host==='10.0.2.2' && p.role==='owner','Fixture guard');
  await a.call('connect_saved',{serverId:a.id});
  const status=await a.call('server_status',{serverId:a.id});a.assert(status.caller_role==='owner','Owner authority');
  const membership=await a.call('membership',{serverId:a.id});
  a.device=membership.members.find(m=>m.role==='owner').devices[0];
  a.originalName=a.device.name;
`);
await check('Device rename, peer permission and port mapping',`
  const a=acceptance,input={server_id:a.id,device_id:a.device.id};
  let m=await a.call('rename_device',{input:{...input,name:'Android acceptance device'}});
  a.assert(m.members.some(m=>m.devices.some(d=>d.id===a.device.id&&d.name==='Android acceptance device')),'Renamed device');
  await a.call('rename_device',{input:{...input,name:a.originalName}});
  m=await a.call('update_device_peer_communication',{input:{...input,enabled:true}});
  a.assert(m.members.some(m=>m.devices.some(d=>d.id===a.device.id&&d.peer_communication_enabled)),'Peer permission');
  await a.call('update_device_peer_communication',{input:{...input,enabled:!!a.device.peer_communication_enabled}});
  m=await a.call('create_port_forward',{input:{...input,protocol:'tcp',public_port:46001,device_port:8080,confirmed:true}});
  a.assert(m.port_forwards.some(p=>p.public_port===46001),'Port mapping');
  m=await a.call('remove_port_forward',{input:{server_id:a.id,protocol:'tcp',public_port:46001}});
  a.assert(!(m.port_forwards??[]).some(p=>p.public_port===46001),'Port mapping removed');
`);
await check('Reusable invitation, preview and cancellation',`
  const a=acceptance;
  const invitation=await a.call('create_invitation',{input:{server_id:a.id,member_name:'Disposable member',device_name:'Disposable device',expires_in_seconds:3600,max_uses:2,member_policy:{device_limit:2},recipient_names:true,administrator:false}});
  const preview=await a.call('preview_invitation',{code:invitation.code});
  a.assert(preview.access_level==='member'&&preview.recipient_names,'Invitation preview');
  let m=await a.call('membership',{serverId:a.id});a.assert(m.active_invitations.some(i=>i.id===invitation.invitation_id&&i.uses_remaining===2),'Reusable invitation');
  await a.call('cancel_invitation',{serverId:a.id,invitationId:invitation.invitation_id});
  m=await a.call('membership',{serverId:a.id});a.assert(!m.active_invitations.some(i=>i.id===invitation.invitation_id),'Invitation cancelled');
`);
await check('Recovery key creation, replacement and revocation',`
  const a=acceptance;
  let r=await a.call('create_recovery_key',{input:{server_id:a.id,confirmed:true}});
  const preview=await a.call('preview_recovery_key',{input:{key:r.key}});a.assert(preview.existing_profile,'Recovery preview');
  r=await a.call('create_recovery_key',{input:{server_id:a.id,confirmed:true,replace_recovery_id:r.recovery_id}});
  const state=await a.call('revoke_recovery_key',{serverId:a.id,recoveryId:r.recovery_id});a.assert(!state.key,'Recovery key revoked');
`);
await check('Device identity rotation and authenticated reconnect',`
  const a=acceptance;
  await a.call('rotate_device_keys',{input:{server_id:a.id,confirmed:true}});
  a.assert(!await a.call('key_rotation_pending',{serverId:a.id}),'Rotation committed');
  a.assert((await a.call('server_status',{serverId:a.id})).caller_role==='owner','Rotated owner authority');
`);
