import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {dirname} from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {adb,openApp,evaluate,delay,serial} from './bridge.mjs';
const fixture=JSON.parse(readFileSync(process.argv[2]));
const enrolled=JSON.parse(adb('exec-out','run-as','org.sirinvpn.client','cat','no_backup/acceptance-vps-result.json'));
assert.equal(fixture.fixture,enrolled.fixture);assert.equal(fixture.host,'10.0.2.2');
const ssh=command=>execFileSync('ssh',['-i',fixture.private_key_source,'-p',String(fixture.ssh_port),'-o','HostKeyAlias=android-vps',
  '-o','UserKnownHostsFile='+dirname(fixture.private_key_source)+'/known-hosts','-o','GlobalKnownHostsFile=/dev/null',
  '-o','StrictHostKeyChecking=yes','-o','BatchMode=yes','sirin@127.0.0.1',command],{encoding:'utf8'}).trim();
assert.equal(ssh('cat /etc/sirinvpn-acceptance-fixture'),fixture.fixture);
await openApp();
const call=(command,args={})=>evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',{command:${JSON.stringify(command)},args:${JSON.stringify(args)}})`);
const id=enrolled.server_id,p=(await call('list_servers')).ok.find(p=>p.id===id);
assert.equal(p.name,'Android isolated VPS');assert.equal(p.endpoint.host,'10.0.2.2');
const original=(await call('get_connection_preferences',{serverId:id})).ok;
const preferences={...original,transport:'direct_udp',manual_mtu:null,routing:{mode:'full_tunnel',included_routes:[],allow_lan:false},android_applications:null};
const rows=[];
function passed(name,extra={}) {rows.push({name,passed:true,...extra});writeFileSync('target/android-evidence/dns-mtu.json',JSON.stringify({serial,rows},null,2));console.log(name+': passed')}
function query() {
  const query=Buffer.concat([Buffer.from([0x51,0x72,1,0,0,1,0,0,0,0,0,0]),...['acceptance','sirin','test'].map(s=>Buffer.concat([Buffer.from([s.length]),Buffer.from(s)])),Buffer.from([0,0,1,0,1])]);
  const result=spawnSync(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'shell','run-as','org.sirinvpn.client','/system/bin/toybox','nc','-u','-w','3','10.77.0.1','53'],{input:query,timeout:5000});
  const b=result.stdout??Buffer.alloc(0);
  return b.length>=12&&b.readUInt16BE(0)===0x5172&&(b[2]&128)!==0&&b.readUInt16BE(6)>0&&b.subarray(-4).equals(Buffer.from([198,18,0,10]));
}
let rule=false,dnsRule=false;
try {
  assert(!(await call('connect_server_with_policy',{serverId:id,preferences})).error);
  ssh(`printf '%s\n' 'server:' '  local-zone: "acceptance.sirin.test." static' '  local-data: "acceptance.sirin.test. 60 IN A 198.18.0.10"' | sudo tee /etc/unbound/unbound.conf.d/zz-sirin-acceptance.conf >/dev/null`);
  ssh('sudo /usr/sbin/unbound-checkconf >/dev/null && sudo systemctl restart unbound && sudo systemctl start sirinvpn-server');
  assert(query(),'Private DNS response did not cross the VPN');
  const resolved=spawnSync(`${process.env.ANDROID_HOME??process.env.HOME+'/Android/Sdk'}/platform-tools/adb`,['-s',serial,'shell','run-as','org.sirinvpn.client','/system/bin/ping','-n','-c','1','-w','2','acceptance.sirin.test'],{encoding:'utf8',timeout:5000});
  assert.match(resolved.stdout,/acceptance.sirin.test \(198\.18\.0\.10\)/);
  passed('Ordinary app UID resolves the controlled private DNS record through Android system resolution');
  ssh('sudo /usr/sbin/iptables -I INPUT 1 -i sirinvpn0 -p udp --dport 53 -m comment --comment sirin-dns-acceptance -j DROP');dnsRule=true;assert(!query(),'Blocked DNS returned an answer');
  assert((await call('server_status',{serverId:id})).ok);passed('DNS failure remains separate from pinned management reachability');
  ssh('sudo /usr/sbin/iptables -D INPUT -i sirinvpn0 -p udp --dport 53 -m comment --comment sirin-dns-acceptance -j DROP');dnsRule=false;
  ssh('sudo /usr/sbin/iptables -I INPUT 1 -i sirinvpn0 -p icmp --icmp-type echo-request -m length --length 1201:65535 -m comment --comment sirin-mtu-acceptance -j DROP');rule=true;
  assert(!(await call('connect_server_with_policy',{serverId:id,preferences})).error);
  let snapshot;
  for(let n=0;n<45;n++) {
    await delay(1000);snapshot=(await call('android_snapshot')).ok;
    if(snapshot.status.mtu?.configured===1200&&snapshot.phase==='connected') break;
  }
  assert.equal(snapshot.status.mtu?.configured,1200);
  assert.match(adb('shell','ip','-o','link','show'),/tun\d+:.*mtu 1200/);
  assert((await call('server_status',{serverId:id})).ok);
  passed('Automatic MTU reduces the actual TUN to the measured 1200-byte path and reconnects',{mtu:1200});
} finally {
  if(dnsRule) ssh('sudo /usr/sbin/iptables -D INPUT -i sirinvpn0 -p udp --dport 53 -m comment --comment sirin-dns-acceptance -j DROP');
  if(rule) ssh('sudo /usr/sbin/iptables -D INPUT -i sirinvpn0 -p icmp --icmp-type echo-request -m length --length 1201:65535 -m comment --comment sirin-mtu-acceptance -j DROP');
  ssh('sudo rm -f /etc/unbound/unbound.conf.d/zz-sirin-acceptance.conf && sudo systemctl restart unbound && sudo systemctl start sirinvpn-server');
  await call('connect_server_with_policy',{serverId:id,preferences:original});
}
