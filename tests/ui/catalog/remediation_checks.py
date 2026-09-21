"""Behavior and short-viewport acceptance for the audit; fictional data only.

Requires the catalog Vite server. Writes separate evidence, never baseline images.
"""
import argparse, hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture
from scenarios import scenarios, click, fill

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=capture.ROOT / 'target/frontend-audit-remediation/responsive')
    args = parser.parse_args()
    capture.OUT = args.output.resolve()
    capture.OUT.mkdir(parents=True, exist_ok=True)
    results = []
    for platform in ['desktop']:
        engine = capture.Engine('desktop', browser=True)
        cases = {case['id']: case for case in scenarios('desktop')}

        def run(name, work):
            try:
                details = work() or {}
                engine.shot(capture.OUT / 'desktop' / (name + '.png'))
                results.append({'platform': 'desktop', 'name': name, 'success': True, **details})
            except Exception as error:
                results.append({'platform': 'desktop', 'name': name, 'success': False, 'error': str(error)})
            print(json.dumps(results[-1]), flush=True)

        def mount_case(name):
            case = cases[name]
            engine.call('mount', {**case.get('state', {}), 'platform': 'desktop'})
            engine.call('actions', case.get('actions', []))

        def initialization_retry():
            engine.call('mount', {'platform': 'desktop', 'errors': {'clientPlatform': 'Fixture dependency unavailable'}})
            engine.call('assertVisible', {'selector': '[role=alert]'})
            engine.call('act', {'patch': {'errors': {'clientPlatform': None}}})
            engine.call('act', click('Retry initialization'))
            assert not engine.evaluate('Boolean(document.querySelector(".platform-unavailable"))')
        run('initialization-retry', initialization_retry)

        def qr_layout():
            mount_case('invitation-created-qr-and-code')
            engine.call('act', click('Enlarge invitation QR code'))
            box = engine.call('assertVisible', {'selector': '.invitation-qr-dialog img', 'complete': True})
            engine.call('assertVisible', {'selector': '[aria-label="Close enlarged QR code"]', 'complete': True})
            engine.call('assertVisible', {'text': 'Copy invitation code', 'complete': True})
            return {'qr': box}
        for width, height in [(900, 680), (1280, 720)]:
            engine.page.set_viewport_size({'width': width, 'height': height})
            run(f'invitation-qr-{width}x{height}', qr_layout)
        engine.page.set_viewport_size({'width': 1280, 'height': 900})

        def enlarged_text():
            mount_case('invitation-created-qr-and-code')
            engine.call('act', click('Enlarge invitation QR code'))
            engine.page.evaluate('document.documentElement.style.fontSize="200%"')
            engine.call('settled')
            engine.call('assertVisible', {'selector': '.invitation-qr-dialog img', 'complete': True})
            engine.call('assertVisible', {'selector': '[aria-label="Close enlarged QR code"]', 'complete': True})
            engine.call('assertVisible', {'text': 'Copy invitation code', 'complete': True})
        run('enlarged-qr-text-200-percent', enlarged_text)
        engine.page.evaluate('document.documentElement.style.fontSize=""')
        engine.call('settled')

        def policy_navigation():
            engine.call('mount', {'platform': 'desktop'})
            engine.call('actions', [click('Devices'), click('Actions for Android phone'), click('Access policy'), click('Edit UTC text'), fill('Weekly access (UTC)', 'not a time range'), click('Save access policy')])
            engine.call('assertVisible', {'selector': '[aria-invalid=true]'})
            assert not engine.evaluate('window.__catalog.state.calls.some(call=>call.name==="updateMemberPolicy")')
        run('populated-member-policy-invalid-submit', policy_navigation)

        def weekly_schedule():
            engine.call('mount', {'platform': 'desktop'})
            engine.call('actions', [click('Devices'), click('Actions for Android phone'), click('Access policy'), click('Add interval'), fill('Day 1', 'Sun'), fill('Start 1 (UTC)', '22:00'), fill('End 1 (UTC)', '02:00')])
            engine.call('act', click('Local time preview for this week'))
            engine.call('assertVisible', {'text': 'UTC intervals stay fixed', 'complete': True})
            engine.shot(capture.OUT / 'desktop' / 'structured-overnight-schedule-editor.png')
            engine.call('act', click('Save access policy'))
            policy = engine.evaluate('window.__catalog.state.calls.find(call=>call.name==="updateMemberPolicy")?.args[2]')
            assert policy['weekly_access'] == [{'start_minute': 0, 'end_minute': 120}, {'start_minute': 9960, 'end_minute': 10080}], policy
        run('structured-overnight-schedule', weekly_schedule)

        def keyboard_menu():
            engine.call('mount', {'platform': 'desktop'})
            engine.call('actions', [click('Devices'), click('Actions for Android phone')])
            engine.page.keyboard.press('Escape')
            assert engine.evaluate('document.activeElement?.getAttribute("aria-label")') == 'Actions for Android phone'
            engine.page.keyboard.press('ArrowDown')
            engine.call('assertVisible', {'selector': '[role=menu]'})
            assert engine.evaluate('document.activeElement?.getAttribute("role")') == 'menuitem'
        run('menu-keyboard-focus', keyboard_menu)

        def recovery_qr():
            mount_case('create-offline-recovery-key-completed')
            engine.call('act', {'details': 'open'})
            engine.call('act', click('Enlarge recovery QR code'))
            engine.call('assertVisible', {'selector': '.invitation-qr-dialog img', 'complete': True})
            expected = engine.evaluate('document.querySelector("textarea.secret-code-output").value')
            return {'payload_sha256': hashlib.sha256(expected.encode()).hexdigest()}
        run('recovery-qr-enlarged', recovery_qr)

        def recovery_policy():
            mount_case('create-offline-recovery-key-completed')
            engine.call('act', click('Administrator recovery policy'))
            engine.page.locator('.access-disclosure').scroll_into_view_if_needed()
            engine.call('settled')
            engine.call('assertVisible', {'text': 'Morgan', 'complete': True})
            engine.call('assertVisible', {'text': 'Save recovery policy', 'complete': True})
        run('recovery-administrator-policy', recovery_policy)

        def recovery_completion():
            mount_case('create-offline-recovery-key-completed')
            finish = engine.page.get_by_role('button', name='Finish recovery setup')
            finish.scroll_into_view_if_needed()
            engine.call('settled')
            assert finish.is_disabled()
            engine.call('assertVisible', {'text': 'I have saved this recovery key or its encrypted package offline and can access it.', 'complete': True})
            engine.shot(capture.OUT / 'desktop' / 'recovery-retention-acknowledgement.png')
            engine.call('act', {'label': 'I have saved this recovery key', 'check': True})
            engine.call('act', click('Finish recovery setup'))
            assert not engine.evaluate('Boolean(document.querySelector("textarea.secret-code-output"))')
        run('recovery-completion-clears-material', recovery_completion)
        engine.close()
    (capture.OUT / 'results.json').write_text(json.dumps(results, indent=2))
    return int(any((not result['success'] for result in results)))
if __name__ == '__main__':
    raise SystemExit(main())
