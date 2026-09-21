import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {dirname} from 'node:path';
import {execFileSync,spawn} from 'node:child_process';
import {adb,evaluate,openApp,delay,serial} from './bridge.mjs';

const fixture=JSON.parse(readFileSync(process.argv[2]??'.cache/android-vps-20260920b/fixture.json'));
const enrollment=JSON.parse(adb('exec-out','run-as','org.sirinvpn.client','cat','no_backup/acceptance-vps-result.json'));
assert.equal(fixture.fixture,enrollment.fixture);assert.equal(fixture.host,'10.0.2.2');
const sshArgs=['-i',fixture.private_key_source,'-p',String(fixture.ssh_port),'-o','HostKeyAlias=android-vps',
  '-o','UserKnownHostsFile='+dirname(fixture.private_key_source)+'/known-hosts','-o','GlobalKnownHostsFile=/dev/null',
  '-o','StrictHostKeyChecking=yes','-o','BatchMode=yes','sirin@127.0.0.1'];
const ssh=command=>execFileSync('ssh',[...sshArgs,command],{encoding:'utf8'}).trim();
assert.equal(ssh('cat /etc/sirinvpn-acceptance-fixture'),fixture.fixture);
const port=fixture.transport.wireguard_port;assert(Number.isInteger(port)&&port>1024&&port<65536);
await openApp();
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
const state=async()=>(await call('android_snapshot')).ok;
const id=enrollment.server_id,p=(await call('list_servers')).ok.find(p=>p.id===id);
assert.equal(p.name,'Android isolated VPS');assert.equal(p.endpoint.host,'10.0.2.2');
const prefs=(await call('get_connection_preferences',{serverId:id})).ok;
const rows=[];let ping,monitoring=true,injected=false;
const rollback=process.argv.includes('--rollback');
let fault;
try {
  // Impair only the disposable guest's direct UDP replies. Other carriers and
  // SSH retain their normal path. This does not touch host or university policy.
  ssh('sudo /usr/sbin/tc qdisc replace dev ens3 root handle 1: prio');
  ssh('sudo /usr/sbin/tc qdisc add dev ens3 parent 1:3 handle 30: netem delay 90ms');
  ssh(`sudo /usr/sbin/tc filter add dev ens3 protocol ip parent 1: prio 1 flower ip_proto udp src_port ${port} flowid 1:3`);
  const connected=await call('connect_server_with_policy',{serverId:id,preferences:{...prefs,transport:'automatic',manual_mtu:null}});
  assert(!connected.error,connected.error);const before=await state();
  assert.equal(before.status.transport,'direct_udp');
  const service=adb('shell','pidof','org.sirinvpn.client:vpn');
  const tun=adb('shell','ip','-o','link','show').split('\n').find(x=>/tun\d/.test(x))?.split(':')[0];assert(tun);
  if(rollback) fault=(async()=>{
    // The winning relay is opened on 51825 only after the independent comparisons.
    // Block its server input before all eight active-path confirmations can pass.
    while(monitoring) {
      if(/:CA71\s/.test(adb('shell','cat','/proc/net/udp'))) {
        ssh(`sudo /usr/sbin/iptables -I INPUT 1 -p udp --dport ${fixture.transport.obfuscated_udp_port} -m comment --comment sirin-quality-acceptance -j DROP`);
        injected=true;return;
      }
      await delay(100);
    }
  })();
  let output='';
  ping=spawn(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'shell','run-as','org.sirinvpn.client','/system/bin/ping','-n','-c','90','-i','1','-w','95',p.server_tunnel_address]);
  ping.stdout.on('data',data=>{output+=data});
  let selected;
  for(let n=0;n<48;n++) {
    await delay(2000);const s=await state();
    assert.equal(s.generation,before.generation);assert.equal(s.phase,'connected');
    if(s.status.transport_quality) rows.push(s.status.transport_quality);
    if(rollback ? s.status.transport_quality?.last_switch_reason==='rollback' : s.status.transport_quality?.selection==='selected') {selected=s;break}
  }
  assert(selected,rollback?'Failed candidate did not roll back':'No confirmed better transport was selected');
  if(rollback) {assert(injected);assert.equal(selected.status.transport,'direct_udp');}
  else {
    assert.notEqual(selected.status.transport,'direct_udp');
    assert(selected.status.transport_quality.sample.latency_micros<50000,'Confirmed traffic still follows the impaired old path');
  }
  assert.equal(adb('shell','pidof','org.sirinvpn.client:vpn'),service);
  assert.equal(adb('shell','ip','-o','link','show').split('\n').find(x=>/tun\d/.test(x))?.split(':')[0],tun);
  assert.match(adb('shell','run-as','org.sirinvpn.client','/system/bin/ping','-n','-c','4','-w','6',p.server_tunnel_address),/4 received/);
  await delay(2500);
  assert(!ssh('sudo wg show sirinvpn0 allowed-ips').includes('10.77.1.'),'Ephemeral lease remained in the kernel');
  writeFileSync(`target/android-evidence/quality${rollback?'-rollback':''}.json`,JSON.stringify({serial,fixture:'disposable local VPS',passed:true,rollback,
    sameGeneration:true,sameServiceProcess:true,sameTunInterface:true,selected:selected.status.transport,
    activeTrafficReplies:(output.match(/bytes from/g)??[]).length,leaseRemoved:true,rows},null,2));
  console.log(`Isolated quality ${rollback?'rollback':'selection'}, retained TUN, recovered traffic and lease cleanup passed.`);
} finally {
  monitoring=false;await fault;
  if(injected) ssh(`sudo /usr/sbin/iptables -D INPUT -p udp --dport ${fixture.transport.obfuscated_udp_port} -m comment --comment sirin-quality-acceptance -j DROP`);
  ping?.kill();ssh('sudo /usr/sbin/tc qdisc replace dev ens3 root fq_codel');
}
