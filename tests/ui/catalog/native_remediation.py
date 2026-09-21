"""Audit acceptance in the isolated Linux Tauri renderer.

UI transactions use fictional catalog fixtures. OS dialogs, document import,
application discovery and settings round trips call the actual native bridge.
"""
import argparse, hashlib, json, os, re, subprocess, sys, time
from pathlib import Path
from urllib.request import urlopen
import capture
from scenarios import scenarios, click, fill, settings

class Native(capture.Engine):

    def __init__(self, platform, bundle):
        super().__init__('desktop')

    def begin(self, command, args=None):
        self.evaluate('(()=>{window.__auditResult=null;window.__TAURI_INTERNALS__.invoke(' + json.dumps(command) + ',' + json.dumps(args or {}) + ').then(value=>window.__auditResult={value},error=>window.__auditResult={error:String(error)});return true})()')

    def result(self, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = self.evaluate('window.__auditResult')
            if value is not None:
                return value
            time.sleep(0.1)
        raise RuntimeError('Native operation did not finish')

    def invoke(self, command, args=None):
        self.begin(command, args)
        result = self.result()
        if 'error' in result:
            raise RuntimeError(result['error'])
        return result.get('value')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('platform', choices=['desktop'])
    parser.add_argument('--output', type=Path, default=capture.ROOT / 'target/frontend-audit-remediation/native')
    parser.add_argument('--bundle', type=Path, default=capture.ROOT / 'target/frontend-audit-remediation/native-bundle')
    parser.add_argument('--filter', default='')
    args = parser.parse_args()
    capture.OUT = args.output.resolve()
    capture.OUT.mkdir(parents=True, exist_ok=True)
    e = Native('desktop', args.bundle.resolve())
    results = []

    def record(name, work):
        if not re.search(args.filter, name):
            return
        try:
            details = work() or {}
            results.append({'id': name, 'platform': 'desktop', 'success': True, **details})
        except Exception as error:
            results.append({'id': name, 'platform': 'desktop', 'success': False, 'error': str(error)})
        print(json.dumps(results[-1]), flush=True)
        (capture.OUT / ('desktop' + '-checks.json')).write_text(json.dumps(results, indent=2))

    def shot(name):
        return e.shot(capture.OUT / 'desktop' / (name + '.png'))

    def native_platform():
        assert e.invoke('client_platform') == 'desktop'
        return {'evidence': 'Actual native command at the trusted application origin'}
    record('native-platform', native_platform)
    cases = {case['id']: case for case in scenarios('desktop')}

    def scene(name):
        case = cases[name]
        e.call('mount', {**case.get('state', {}), 'platform': 'desktop'})
        e.call('actions', case.get('actions', []))
        assert not e.evaluate('window.__catalog.state.fixtureErrors?.length')
        return {'files': [shot(name)], 'evidence': 'Production UI in native renderer; fictional API responses'}
    for name in ['error-clientplatform', 'connected-home', 'no-recent-handshake-home', 'disconnect-operation-in-progress', 'server-actions-menu', 'member-policy-editor', 'reserved-public-port', 'recovery-key-registered']:
        record(name, lambda name=name: scene(name))

    def qr(kind):
        scene('invitation-created-qr-and-code' if kind == 'invitation' else 'create-offline-recovery-key-completed')
        if kind == 'recovery':
            e.call('act', {'details': 'open'})
        e.call('act', click('Enlarge ' + kind + ' QR code'))
        e.call('assertVisible', {'selector': '.invitation-qr-dialog img', 'complete': True})
        e.call('assertVisible', {'selector': '[aria-label="Close enlarged QR code"]', 'complete': True})
        e.call('assertVisible', {'text': 'Copy ' + kind + ' code', 'complete': True})
        return {'files': [shot(kind + '-qr-enlarged')], 'evidence': 'Native renderer QR and complete copy/close controls'}
    for kind in ['invitation', 'recovery']:
        record(kind + '-qr-enlarged', lambda kind=kind: qr(kind))

    def confirmation():
        e.call('mount', {'platform': 'desktop', 'connected': False})
        e.begin('plugin:dialog|message', {'title': 'Remove from this device', 'message': 'Fixture only: remove a local identity? No profile will be removed by this check.', 'kind': 'warning', 'buttons': {'OkCancelCustom': ['Remove from this device', 'Cancel']}})
        time.sleep(0.6)
        early = e.evaluate('window.__auditResult')
        assert early is None, early
        file = shot('action-labelled-native-confirmation')
        subprocess.run(['xdotool', 'key', 'Escape'], env={**os.environ, 'DISPLAY': ':87'}, check=True)
        value = e.result()
        assert value.get('value') == 'Cancel', value
        return {'files': [file], 'cancel_result': value['value'], 'evidence': 'Actual OS dialog and native cancellation result'}
    record('action-labelled-native-confirmation', confirmation)

    def ownership_confirmation():
        scene('transfer-ownership-confirmation')
        message = e.evaluate('window.__catalog.prompts.find(prompt=>prompt.message.startsWith("Transfer ownership"))?.message')
        assert 'SHA256:' + 'A' * 43 in message, 'The full destination fingerprint is missing'
        e.begin('plugin:dialog|message', {'title': 'Transfer ownership', 'message': message, 'kind': 'warning', 'buttons': {'OkCancelCustom': ['Transfer ownership', 'Cancel']}})
        time.sleep(0.5)
        file = shot('ownership-identity-confirmation')
        subprocess.run(['xdotool', 'key', 'Escape'], env={**os.environ, 'DISPLAY': ':87'}, check=True)
        assert e.result().get('value') == 'Cancel'
        return {'files': [file], 'evidence': 'Production ownership message with complete fixture fingerprint rendered in an actual OS dialog; transaction itself uses fixtures'}
    record('ownership-identity-confirmation', ownership_confirmation)
    e.close()
    return int(any((not result['success'] for result in results)))
if __name__ == '__main__':
    raise SystemExit(main())
