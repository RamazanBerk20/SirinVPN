"""Bounded DNS attribution and negative control, only in the disposable VM lab."""
import json
import os
from contextlib import contextmanager
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import time
import uuid


def observe(path):
    assert Path('/etc/sirinvpn-acceptance-fixture').is_file()
    assert path.startswith('/run/sirin-dns-') and path.endswith('.jsonl')
    with open(path, 'x', encoding='utf-8') as output, selectors.DefaultSelector() as selector:
        os.chmod(path, 0o600)
        size = 0
        def emit(kind, **fields):
            nonlocal size
            line = json.dumps(dict(kind=kind, mono_ns=time.monotonic_ns(),
                                   unix_ns=time.time_ns(), **fields)) + '\n'
            size += len(line)
            assert size < 4 * 1024**2, 'DNS timeline exceeded its bound'
            output.write(line)
            output.flush()
        monitors = []
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        capture.setsockopt(socket.SOL_SOCKET, 35, 1)  # Linux x86_64 SO_TIMESTAMPNS.
        capture.setblocking(False)
        selector.register(capture, selectors.EVENT_READ, 'packet')
        buffers = {}
        try:
            for kind, args in [('rules', []), ('trace', ['trace'])]:
                monitor = subprocess.Popen(['nft', '-nn', 'monitor', *args], stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
                monitors.append(monitor)
                selector.register(monitor.stdout, selectors.EVENT_READ, kind)
                buffers[kind] = b''
            # Both nft monitors must subscribe before the first synthetic packet.
            time.sleep(.3)
            assert all(p.poll() is None for p in monitors), 'nft monitor did not start'
            emit('ready', observer_pid=os.getpid())
            previous = None
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                for key, _ in selector.select(.1):
                    if key.data != 'packet':
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        assert chunk, 'nft monitor ended early'
                        buffers[key.data] += chunk
                        lines = buffers[key.data].split(b'\n')
                        buffers[key.data] = lines.pop()
                        for line in lines:
                            emit(key.data, text=line.decode(errors='replace'))
                        continue
                    packet, ancillary, _, address = capture.recvmsg(65535, 128)
                    if address[2] != 4 or address[0] in ('lo', 'sirinvpn0') or len(packet) < 42:
                        continue
                    if packet[12:14] != b'\x08\x00':
                        continue
                    ip = packet[14:]
                    offset = (ip[0] & 15) * 4
                    ip_length = int.from_bytes(ip[2:4], 'big')
                    if ip[9] not in (6, 17) or len(ip) < offset + 8:
                        continue
                    sport, dport = struct.unpack('!HH', ip[offset:offset+4])
                    if dport != 53:
                        continue
                    timestamp = next((struct.unpack('ll', data[:16]) for level, kind, data in ancillary
                                      if level == socket.SOL_SOCKET and kind == 35), None)
                    owners = subprocess.check_output(['ss', '-H', '-n', '-t', '-u', '-a', '-p'], text=True)
                    owners = [line[:1000] for line in owners.splitlines() if f':{sport} ' in line]
                    header = (ip[offset+12] >> 4) * 4 if ip[9] == 6 else 8
                    emit('physical_dns', interface=address[0], source=socket.inet_ntoa(ip[12:16]),
                         destination=socket.inet_ntoa(ip[16:20]), protocol=ip[9], source_port=sport,
                         tcp_flags=ip[offset+13] if ip[9] == 6 else None,
                         payload_bytes=max(0, ip_length-offset-header), socket_owners=owners,
                         kernel_unix_ns=timestamp[0]*10**9+timestamp[1] if timestamp else None)
                try:
                    state = json.loads(Path('/run/sirinvpn/client-state.json').read_text())
                    state = {k: state.get(k) for k in ('transport', 'reconnecting', 'has_connected',
                             'waiting_for_user', 'enforcement', 'initial_attempts',
                             'observed_at_boot_seconds', 'applied_at_unix', 'persistent_protection')}
                    state['transport'] = state['transport'] or 'direct_udp'
                except FileNotFoundError:
                    state = None
                if state != previous:
                    emit('state', state=state)
                    previous = state
            emit('timeout')
        finally:
            capture.close()
            for monitor in monitors:
                monitor.terminate()
                monitor.wait(timeout=5)


def probe(path):
    assert Path('/etc/sirinvpn-acceptance-fixture').is_file()
    interface = json.loads(subprocess.check_output(['ip', '-j', 'route', 'show', 'default']))[0]['dev']
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, open(path, 'x') as output:
        os.chmod(path, 0o600)
        # Force the underlay so tunnel routing cannot hide a missing firewall.
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode()+b'\0')
        client.bind(('0.0.0.0', 0))
        port = client.getsockname()[1]
        for sequence in range(480):
            payload = struct.pack('!6H', sequence, 0x100, 1, 0, 0, 0)
            label = b'sirin-acceptance'
            payload += bytes([len(label)]) + label + b'\x07invalid\x00\x00\x01\x00\x01'
            try:
                client.sendto(payload, ('10.0.2.3', 53))
                result = 'sent'
            except OSError as error:
                result = error.errno
            output.write(json.dumps(dict(mono_ns=time.monotonic_ns(), pid=os.getpid(),
                                         source_port=port, sequence=sequence, result=result))+'\n')
            output.flush()
            time.sleep(.25)


@contextmanager
def capture(test, observation):
    """Retain one bounded timeline, including when the protected test fails."""
    guest = test.client
    script = '/opt/sirin-dns-attribution.py'
    guest.put(Path(__file__), '/home/sirin/dns-attribution.py')
    guest.run(['install', '-m', '0755', '/home/sirin/dns-attribution.py', script])
    name = 'sirin-dns-' + str(uuid.uuid4())
    timeline = '/run/'+name+'.jsonl'
    guest.run(['nft', '-f', '-'], data=b'''table inet sirin_dns_attribution {
 chain output {
  type filter hook output priority -301; policy accept;
  meta l4proto { tcp, udp } th dport 53 meta nftrace set 1
 }
}
''')
    guest.run(['systemd-run', '--unit='+name, '--collect', '--property=RuntimeMaxSec=180',
               '--property=LimitFSIZE=4194304', 'python3', script, 'observe', timeline])
    try:
        guest.run(['sh', '-ec', 'until test -s "$1"; do sleep 0.1; done', 'sh', timeline], timeout=10)
        yield name, script
    finally:
        active = guest.run(['systemctl', 'is-active', name], check=False).returncode == 0
        guest.run(['systemctl', 'stop', name], check=False)
        data = guest.run(['cat', timeline], check=False).stdout
        assert len(data) < 4*1024**2, 'DNS evidence limit reached'
        observation['events'] = [json.loads(line) for line in data.splitlines()]
        guest.run(['nft', 'delete', 'table', 'inet', 'sirin_dns_attribution'])
        test.save()
        assert active and observation['events'][0]['kind'] == 'ready', 'DNS recorder ended unexpectedly'
        assert not any(e['kind'] == 'timeout' for e in observation['events']), 'DNS recorder timed out'


def mark(test, observation, phase):
    clock = json.loads(test.client.run(['python3', '-c',
        'import time,json; print(json.dumps(dict(mono_ns=time.monotonic_ns(),unix_ns=time.time_ns())))']).stdout)
    observation.setdefault('phases', []).append({'phase': phase, **clock})
    return clock


def run(test):
    """Test counter boundaries; historical counter-only failures remain unattributed."""
    guest = test.client
    observation = {'scope': 'synthetic DNS only; no packet payloads',
                   'historical_failures_attributed': False}
    test.report['dns_attribution'] = observation
    with capture(test, observation) as (name, script):
        probes = '/run/'+name+'-probes.jsonl'
        try:
            _controls(test, observation, name, script, probes)
        finally:
            rules = guest.run(['nft', '-j', '-a', 'list', 'chain', 'inet', 'sirinvpn_guard', 'output'], check=False)
            if rules.returncode == 0:
                for row in json.loads(rules.stdout)['nftables']:
                    rule = row.get('rule', {})
                    if rule.get('comment') == 'sirin_dns_detector_control':
                        guest.run(['nft', 'delete', 'rule', 'inet', 'sirinvpn_guard', 'output', 'handle', str(rule['handle'])])
            test.block_server(None)
            guest.run(['systemctl', 'stop', name+'-probes'], check=False)
            data = guest.run(['cat', probes], check=False).stdout
            assert len(data) < 4*1024**2, 'DNS probe evidence limit reached'
            observation['probes'] = [json.loads(line) for line in data.splitlines()]
    events = observation['events']
    guards = [e for e in events if e['kind'] == 'rules' and 'add table inet sirinvpn_guard' in e['text']]
    assert guards, 'Protection installation was not observed'
    armed = guards[0]
    observation['guard_observed_mono_ns'] = armed['mono_ns']
    observation['timing_limit'] = ('Rules/trace timestamps are userspace receive times. '
                                   'Kernel packet timestamps are retained separately; '
                                   'the rules event is not the exact kernel commit time.')
    physical = [e for e in events if e['kind'] == 'physical_dns']
    assert physical, 'Negative-control packet metadata missing'
    assert all(e['kernel_unix_ns'] is not None for e in physical), 'Missing kernel packet timestamps'
    control = next(p for p in observation['phases'] if p['phase'] == 'deliberate_detector_control')
    late = [e for e in physical if armed['unix_ns'] <= e['kernel_unix_ns'] < control['unix_ns']]
    observation['physical_after_guard_observed'] = late
    assert not late, 'Physical DNS observed after protection; inspect the retained timeline'
    escaped_control = [e for e in physical if e['kernel_unix_ns'] >= control['unix_ns']
                       and e['source_port'] == observation['probes'][0]['source_port']]
    assert escaped_control, 'Detector failed to catch the deliberately permitted protected probe'
    observation['deliberate_protected_escape_detected'] = len(escaped_control)
    dropped = [e for e in events if e['kind'] == 'trace' and 'sirinvpn_guard output' in e['text']
               and ('policy drop' in e['text'] or 'verdict drop' in e['text'])]
    assert dropped, 'No protected DNS packet reached the guard'
    assert not any(e['kind'] == 'timeout' for e in events), 'Observer timed out'
    observation['guard_drop_events'] = len(dropped)
    observation['pre_protection_counter_false_positive_reproduced'] = True
    return {k: v for k, v in observation.items() if k not in ('events', 'probes')}


def _controls(test, observation, name, script, probes):
    guest = test.client
    test.counter(reset=True)
    observation['before_probes'] = test.counter()
    assert observation['before_probes'] == {'dns': 0, 'ipv6': 0}
    mark(test, observation, 'disconnected_negative_control')
    guest.run(['systemd-run', '--unit='+name+'-probes', '--collect', '--property=RuntimeMaxSec=120',
               'python3', script, 'probe', probes])
    time.sleep(1)
    observation['negative_control'] = test.counter()
    assert observation['negative_control']['dns'] > 0, 'The physical DNS detector did not work'
    # The old assertion spans these pre-arm packets despite a zero baseline.
    test.block_server('udp')
    mark(test, observation, 'connect_requested')
    test.cli('connect', test.server_id, '--transport', 'automatic', '--persistent',
             '--network-profile', 'normal', timeout=240)
    local = test.wait_connected(timeout=100)
    assert local['transport'] in ('tls_like', 'tcp_fallback')
    mark(test, observation, 'fallback_connected')
    time.sleep(2)
    # Prove that the same detector catches a real protected-interval escape.
    # This exception is confined to the synthetic probe's port in this VM.
    probe_port = json.loads(guest.run(['head', '-n', '1', probes]).stdout)['source_port']
    mark(test, observation, 'deliberate_detector_control')
    guest.run(['nft', 'insert', 'rule', 'inet', 'sirinvpn_guard', 'output',
               'ip', 'daddr', '10.0.2.3', 'udp', 'sport', str(probe_port), 'udp', 'dport', '53',
               'accept', 'comment', '"sirin_dns_detector_control"'])
    time.sleep(1)
    guest.run(['systemctl', 'stop', name+'-probes'])
    mark(test, observation, 'probes_stopped')
    observation['after_fallback'] = test.counter()


if __name__ == '__main__':
    {'observe': observe, 'probe': probe}[sys.argv[1]](sys.argv[2])
