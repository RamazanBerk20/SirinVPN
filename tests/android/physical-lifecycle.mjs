// Opt-in, ordinary Member traffic on an explicitly authorized physical phone.
// Never use the destructive emulator suites against an existing installation.
import assert from 'node:assert/strict';
import {execFileSync, spawn} from 'node:child_process';
import {createHash, randomUUID} from 'node:crypto';
import {createServer} from 'node:http';
import {isIP} from 'node:net';
import {writeFileSync, existsSync, mkdirSync} from 'node:fs';
import {dirname} from 'node:path';
import {parseArgs} from 'node:util';

const {values} = parseArgs({options: {
  serial: {type: 'string'}, model: {type: 'string'}, output: {type: 'string'},
  'authorized-member-test': {type: 'boolean', default: false},
  'remove-app-task': {type: 'boolean', default: false},
  'cycle-networks': {type: 'boolean', default: false},
  'interrupt-vpn-service': {type: 'boolean', default: false},
  'samsung-os-policy': {type: 'boolean', default: false},
  'probe-host': {type: 'string'},
}});
assert(values.serial && !values.serial.startsWith('emulator-') && values.model && values.output);
assert(values['authorized-member-test'], 'Explicit authorization for this phone is required');
assert(!existsSync(values.output), 'Evidence must not be overwritten');
const pkg = 'org.sirinvpn.client';
const adbPath = `${process.env.ANDROID_HOME ?? process.env.HOME + '/Android/Sdk'}/platform-tools/adb`;
const adb = (...args) => {
  if (args[0] === 'shell') args = ['shell', args.slice(1).map(x => "'" + String(x).replaceAll("'", "'\"'\"'") + "'").join(' ')];
  return execFileSync(adbPath, ['-s', values.serial, ...args], {encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'pipe']}).trim();
};
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const result = {fixture: 'authorized-physical-android', model: adb('shell', 'getprop', 'ro.product.model'),
  sdk: Number(adb('shell', 'getprop', 'ro.build.version.sdk')), page_size: Number(adb('shell', 'getconf', 'PAGE_SIZE')),
  started: new Date().toISOString(), checks: [], passed: false,
  limitations: ['One physical phone and existing Member server; no server administration.',
    'Session identity and sampled traffic do not prove uninterrupted packet flow.',
    'No reboot, 16 KiB page-size or other OEM coverage; network transitions can interrupt traffic.',
    values['samsung-os-policy'] ? 'Lockdown observation covers one ordinary test UID and a controlled LAN endpoint.'
      : 'OS lockdown is not tested in this run.']};
assert.equal(result.model, values.model, 'Unexpected phone model');
assert.equal(adb('shell', 'settings', 'get', 'secure', 'always_on_vpn_app'), 'null', 'This check requires Always-on initially off');
assert.equal(adb('shell', 'settings', 'get', 'secure', 'always_on_vpn_lockdown'), '0');
let port;
async function evaluate(expression) {
  const pid = adb('shell', 'pidof', pkg);
  if (!port) port = adb('forward', 'tcp:0', `localabstract:webview_devtools_remote_${pid}`);
  else adb('forward', `tcp:${port}`, `localabstract:webview_devtools_remote_${pid}`);
  const pages = await (await fetch(`http://127.0.0.1:${port}/json`, {signal: AbortSignal.timeout(5000)})).json();
  const ws = new WebSocket(pages.find(p => p.type === 'page').webSocketDebuggerUrl);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {ws.close(); reject(Error('Native request timed out'));}, 180000);
    ws.onopen = () => ws.send(JSON.stringify({id: 1, method: 'Runtime.evaluate', params: {expression, awaitPromise: true, returnByValue: true}}));
    ws.onmessage = event => {
      const reply = JSON.parse(event.data);
      if (reply.id !== 1) return;
      clearTimeout(timer); ws.close();
      if (reply.error || reply.result?.exceptionDetails || !reply.result?.result) reject(Error('Native evaluation failed'));
      else resolve(reply.result.result.value);
    };
    ws.onerror = () => {clearTimeout(timer); ws.close(); reject(Error('Native observer unavailable'));};
  });
}
const call = (command, args = {}) => evaluate(`window.__TAURI_INTERNALS__.invoke('android_call',${JSON.stringify({command, args})})`);
async function open() {
  adb('shell', 'am', 'start', '-n', `${pkg}/.MainActivity`);
  for (let attempt = 0; attempt < 60; attempt++) {
    await delay(300);
    try {if ((await call('android_snapshot')).ok?.phase) return;} catch { /* Cold-start observer only. */ }
  }
  throw Error('App did not become observable');
}
const profileDigest = () => createHash('sha256').update(adb('exec-out', 'run-as', pkg, 'cat', 'no_backup/servers.json')).digest('hex');
let originalDigest, connectedByTest = false, restoreNetworks = false, restorePolicy = false, canary;
const secure = name => adb('shell', 'settings', 'get', 'secure', name);
async function samsungToggle(name, enabled) {
  const alwaysOn = name === 'always_on_vpn_app';
  const expected = enabled ? (alwaysOn ? pkg : '1') : (alwaysOn ? 'null' : '0');
  if (secure(name) === expected) return;
  // Coordinates are intentionally scoped to the inspected S25+ Settings layout.
  // Every mutation requires OS readback; other models/layouts are not qualified.
  assert.equal(values.model, 'SM-S936B');
  assert.equal(adb('shell', 'wm', 'size'), 'Physical size: 1080x2340');
  adb('shell', 'am', 'start', '-a', 'android.settings.VPN_SETTINGS', '-f', '0x10008000');
  await delay(700); adb('shell', 'input', 'tap', '950', '390'); await delay(700);
  adb('shell', 'input', 'tap', '950', alwaysOn ? '600' : '780'); await delay(1000);
  if (!alwaysOn && enabled && secure(name) === '0') {
    // Samsung's inspected Turkish confirmation: “VPN bağlantısı gerekli mi?” / “Aç”.
    adb('shell', 'input', 'tap', '765', '2170'); await delay(700);
  }
  assert.equal(secure(name), expected, 'OS policy control needs layout/confirmation review');
}
let probe;
try {
  await open();
  const before = (await call('android_snapshot')).ok;
  assert(['disconnected', 'paused'].includes(before.phase) && before.status.state === 'disconnected'
    && !before.operation_in_progress, 'Start with the phone disconnected');
  const profiles = (await call('list_servers')).ok;
  assert.equal(profiles.length, 1, 'This bounded check requires exactly one existing Member profile');
  const profile = profiles[0];
  assert.equal(profile.role, 'member', 'Administrative profiles are not used by this check');
  originalDigest = profileDigest();
  result.checks.push({name: 'Existing Member profile readable', passed: true});
  if (values['samsung-os-policy']) {
    assert(values['probe-host'] && isIP(values['probe-host']) === 4
      && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(values['probe-host']));
    const nonce = randomUUID();
    canary = createServer((_, response) => {response.writeHead(200, {'Connection': 'close'}); response.end(nonce);});
    await new Promise((resolve, reject) => {canary.once('error', reject); canary.listen(0, values['probe-host'], resolve);});
    const port = canary.address().port;
    probe = () => new Promise(resolve => {
      const child = spawn(adbPath, ['-s', values.serial, 'shell', 'run-as', pkg + '.test', '/system/bin/toybox',
        'nc', '-w', '3', values['probe-host'], String(port)]);
      let output = '';
      child.stdout.on('data', data => {output += data; if (output.length > 8192) child.kill();});
      child.stderr.resume(); child.stdin.on('error', () => {});
      child.stdin.end('GET / HTTP/1.0\r\nHost: acceptance\r\n\r\n');
      const timer = setTimeout(() => child.kill(), 5000);
      child.once('close', () => {clearTimeout(timer); resolve(output.includes(nonce));});
    });
    // The separate test UID has INTERNET permission but no VPN/control bridge.
    adb('shell', 'am', 'force-stop', pkg + '.test');
    adb('shell', 'am', 'start', '-n', `${pkg}.test/${pkg}.PhysicalProbeActivity`);
    await delay(500);
    assert(!adb('shell', 'dumpsys', 'activity', 'activities').split('\n')
      .some(line => line.includes('topResumedActivity=') && line.includes('PhysicalProbeActivity')), 'Probe ran without opt-in');
    adb('shell', 'am', 'start', '-n', `${pkg}.test/${pkg}.PhysicalProbeActivity`, '--ez', 'authorized_acceptance', 'true');
    await delay(700); assert(await probe(), 'Controlled LAN baseline unavailable');
    result.checks.push({name: 'Separate ordinary test UID reaches controlled LAN before lockdown', passed: true});
    await open();
  }
  connectedByTest = true; // Also clean up if the connection command partially succeeds.
  const connected = await call('connect_saved', {serverId: profile.id});
  assert(!connected.error, 'Saved Member connection failed');
  const initial = (await call('android_snapshot')).ok;
  assert.equal(initial.phase, 'connected');
  const servicePid = adb('shell', 'pidof', `${pkg}:vpn`);
  async function observe(name, sameSession = true) {
    const state = (await call('android_snapshot')).ok;
    assert.equal(state.phase, 'connected', `${name}: connection lost`);
    const sameGeneration = state.generation === initial.generation;
    const sameProcess = adb('shell', 'pidof', `${pkg}:vpn`) === servicePid;
    if (sameSession) assert(sameGeneration && sameProcess, `${name}: native session changed`);
    assert((await call('server_status', {serverId: profile.id})).ok, `${name}: authenticated management unavailable`);
    const ping = adb('shell', 'run-as', pkg, '/system/bin/ping', '-n', '-c', '3', '-w', '8', profile.server_tunnel_address);
    assert.match(ping, /3 received/, `${name}: ordinary-UID tunnel traffic failed`);
    result.checks.push({name, passed: true, same_service_process: sameProcess, same_session_generation: sameGeneration,
      authenticated_management: true, ordinary_uid_replies: 3});
    console.log(`${name}: passed`);
  }
  await observe('Connected with existing encrypted identity');
  adb('shell', 'input', 'keyevent', 'KEYCODE_HOME'); await delay(2000); await open();
  await observe('Home and reopen');
  const uiPid = adb('shell', 'pidof', pkg);
  assert.notEqual(uiPid, servicePid);
  adb('shell', 'run-as', pkg, 'kill', '-9', uiPid); await delay(2000); await open();
  await observe('UI process termination and reopen');
  if (values['remove-app-task']) {
    // Refuse a root task containing any unrelated app. Android's shell task
    // removal exercises onTaskRemoved without a destructive package force-stop.
    const roots = adb('shell', 'cmd', 'activity', 'stack', 'list').split(/(?=^RootTask )/m);
    const owned = roots.filter(root => root.includes(`${pkg}/`));
    assert.equal(owned.length, 1, 'Expected one app task');
    const tasks = [...owned[0].matchAll(/taskId=(\d+): ([^\s]+)/g)];
    assert.equal(tasks.length, 1, 'Refusing to remove a shared root task');
    assert(tasks[0][2].startsWith(`${pkg}/`));
    const id = owned[0].match(/^RootTask id=(\d+)/)?.[1];
    assert(id && id === tasks[0][1], 'Root task identity mismatch');
    adb('shell', 'cmd', 'activity', 'stack', 'remove', id);
    await delay(2000);
    assert(!adb('shell', 'cmd', 'activity', 'stack', 'list').includes(`${pkg}/`), 'Task remains');
    await open(); await observe('OS task removal and reopen');
  }
  await delay(30000);
  await observe('Thirty-second foreground hold');
  async function waitPhase(phase) {
    for (let attempt = 0; attempt < 120; attempt++) {
      if ((await call('android_snapshot')).ok?.phase === phase) return;
      await delay(500);
    }
    throw new assert.AssertionError({message: `Native controller did not reach ${phase}`});
  }
  if (values['cycle-networks']) {
    assert.equal(adb('shell', 'settings', 'get', 'global', 'wifi_on'), '1');
    assert.equal(adb('shell', 'settings', 'get', 'global', 'mobile_data'), '1');
    assert(initial.status.auto_reconnect_enabled, 'Saved reconnect policy must already be enabled');
    assert(['trusted_wifi', 'untrusted_wifi'].includes((await call('get_wifi_policy')).ok.current_network));
    restoreNetworks = true;
    adb('shell', 'svc', 'wifi', 'disable'); await delay(5000); await waitPhase('connected');
    assert.equal((await call('get_wifi_policy')).ok.current_network, 'other_network');
    await observe('Wi-Fi to mobile-data transition', false);
    adb('shell', 'svc', 'data', 'disable'); await waitPhase('waiting_for_network');
    result.checks.push({name: 'Loss of both networks reports waiting', passed: true});
    adb('shell', 'svc', 'wifi', 'enable'); await waitPhase('connected');
    assert(['trusted_wifi', 'untrusted_wifi'].includes((await call('get_wifi_policy')).ok.current_network));
    await observe('Network return reconnects over Wi-Fi', false);
    adb('shell', 'svc', 'data', 'enable'); restoreNetworks = false;
  }
  if (values['interrupt-vpn-service']) {
    assert(initial.status.auto_reconnect_enabled, 'Saved reconnect policy must already be enabled');
    const pid = adb('shell', 'pidof', `${pkg}:vpn`);
    const generation = (await call('android_snapshot')).ok.generation;
    adb('shell', 'run-as', pkg, 'kill', '-9', pid);
    await delay(5000); await open(); await waitPhase('connected');
    assert.notEqual(adb('shell', 'pidof', `${pkg}:vpn`), pid);
    assert((await call('android_snapshot')).ok.generation > generation);
    await observe('VPN process death reconstructs a new session', false);
    adb('shell', 'am', 'force-stop', pkg); await delay(3000); await open(); await delay(3000);
    assert.notEqual((await call('android_snapshot')).ok.phase, 'connected', 'Force-stop unexpectedly reconnected');
    result.checks.push({name: 'Package force-stop remains stopped after reopen', passed: true});
    assert(!(await call('connect_saved', {serverId: profile.id})).error);
    await waitPhase('connected'); await observe('Explicit connect after force-stop', false);
  }
  if (values['samsung-os-policy']) {
    restorePolicy = true;
    await samsungToggle('always_on_vpn_app', true); await open(); await waitPhase('connected');
    assert((await call('android_snapshot')).ok.always_on);
    assert((await call('disconnect_server')).error, 'Ordinary Disconnect bypassed Always-on');
    await observe('Always-on retains traffic and rejects ordinary Disconnect', false);
    await samsungToggle('always_on_vpn_lockdown', true); await open();
    assert((await call('android_snapshot')).ok.lockdown);
    adb('shell', 'am', 'start', '-n', `${pkg}.test/${pkg}.PhysicalProbeActivity`, '--ez', 'authorized_acceptance', 'true');
    await delay(500);
    assert.match(adb('shell', 'run-as', pkg + '.test', '/system/bin/ping', '-n', '-c', '3', '-w', '8', profile.server_tunnel_address), /3 received/,
      'Ordinary test UID lacked VPN traffic before interruption');
    adb('shell', 'am', 'force-stop', pkg); await delay(1000);
    assert.equal(secure('always_on_vpn_app'), pkg); assert.equal(secure('always_on_vpn_lockdown'), '1');
    for (let attempt = 0; attempt < 3; attempt++) assert(!await probe(), 'Test UID escaped OS lockdown');
    result.checks.push({name: 'OS lockdown blocks ordinary UID while VPN package is force-stopped', passed: true, blocked_probes: 3});
  }
  result.passed = true;
} catch (error) {
  result.failure = error instanceof assert.AssertionError ? error.message : error.name;
  process.exitCode = 1;
} finally {
  try {
    if (restorePolicy) {
      await samsungToggle('always_on_vpn_lockdown', false); await samsungToggle('always_on_vpn_app', false);
    }
    if (restoreNetworks) {
      adb('shell', 'svc', 'wifi', 'enable'); adb('shell', 'svc', 'data', 'enable');
    }
    if (connectedByTest) {
      await open();
      assert(!(await call('disconnect_server')).error, 'Cleanup disconnect failed');
      // Explicit Stop pauses a saved reconnect policy; it is still disconnected.
      let stopped;
      for (let attempt = 0; attempt < 50; attempt++) {
        stopped = (await call('android_snapshot')).ok;
        if (!stopped.operation_in_progress && stopped.status.state === 'disconnected') break;
        await delay(100);
      }
      assert(['disconnected', 'paused'].includes(stopped.phase) && stopped.status.state === 'disconnected'
        && !stopped.operation_in_progress, 'Cleanup did not finish');
    }
    if (originalDigest) assert.equal(profileDigest(), originalDigest, 'Saved profile changed');
    if (restorePolicy) {
      adb('shell', 'am', 'start', '-n', `${pkg}.test/${pkg}.PhysicalProbeActivity`, '--ez', 'authorized_acceptance', 'true');
      await delay(500); assert(await probe(), 'Ordinary networking did not return after restoring OS policy');
      result.checks.push({name: 'Restoring OS policy re-enables ordinary UID LAN traffic', passed: true});
      adb('shell', 'am', 'force-stop', pkg + '.test'); await open();
    }
    result.cleanup_complete = true;
    result.profile_preserved = Boolean(originalDigest);
  } catch (error) {
    result.cleanup_failure = error instanceof assert.AssertionError ? error.message : error.name;
    result.cleanup_complete = false; result.passed = false; process.exitCode = 1;
  }
  if (port) adb('forward', '--remove', `tcp:${port}`);
  if (canary) {canary.closeAllConnections(); await new Promise(resolve => canary.close(resolve));}
  result.ended = new Date().toISOString();
  mkdirSync(dirname(values.output), {recursive: true});
  writeFileSync(values.output, JSON.stringify(result, null, 2), {flag: 'wx', mode: 0o600});
  console.log(`Physical lifecycle: ${result.passed ? 'passed' : 'failed'}; cleanup: ${result.cleanup_complete}`);
}
