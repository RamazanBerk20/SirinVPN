"""Exercise the UI with synthetic native responses and capture review images.

Start Vite on 127.0.0.1:1420. Requires Python Playwright + Chromium. Pass a local
axe.min.js via --axe to also check WCAG 2.2 AA; no script is fetched by the app.
These fixtures verify presentation and interaction, not a real VPN connection.
"""
import argparse
import json
from pathlib import Path
from playwright.sync_api import expect, sync_playwright
ROOT = Path(__file__).resolve().parents[2]
FIXTURE = (Path(__file__).parent / 'fixtures.js').read_text()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--axe', type=Path, help='Local axe-core JavaScript bundle')
parser.add_argument('--output', type=Path, default=ROOT / '.cache/overhaul/screenshots')
args = parser.parse_args()
OUTPUT = args.output
OUTPUT.mkdir(parents=True, exist_ok=True)
violations = []

def inspect(page, name):
    mobile_navigation = page.get_by_role('navigation', name='Mobile navigation')
    if mobile_navigation.count():
        expect(mobile_navigation).to_be_in_viewport(ratio=1)
    page.screenshot(path=str(OUTPUT / f'{name}.png'), full_page=page.get_by_role('menu').count() == 0)
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), (name, 'horizontal overflow')
    if args.axe:
        if not page.evaluate('Boolean(window.axe)'):
            page.add_script_tag(path=str(args.axe))
        result = page.evaluate("async () => await axe.run(document, {\n          runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']}\n        })")
        violations.extend(({'screen': name, 'id': item['id'], 'impact': item['impact'], 'nodes': [{'target': node['target'], 'summary': node['failureSummary']} for node in item['nodes']]} for item in result['violations']))
with sync_playwright() as pw:
    browser = pw.chromium.launch()
    for platform, scenario, width, height in [('desktop', 'connected', 1440, 1000), ('desktop', 'connected', 1220, 780), ('desktop', 'disconnected', 760, 620), ('desktop', 'onboarding', 1220, 900), ('desktop', 'onboarding', 958, 746), ('desktop', 'onboarding', 600, 800), ('desktop', 'connected', 390, 844)]:
        page = browser.new_page(viewport={'width': width, 'height': height}, reduced_motion='reduce')
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.add_init_script(f'''window.__sirinPlatform = "{'desktop'}"; window.__sirinScenario = "{scenario}";\n''' + FIXTURE)
        page.goto('http://127.0.0.1:1420', wait_until='networkidle')
        if args.axe:
            page.add_script_tag(path=str(args.axe))
        prefix = f"{'desktop'}-{scenario}-{width}"
        inspect(page, prefix + '-home')
        assert page.locator('.connection-options').count() == 0, 'Home must not contain connection controls'
        assert page.locator('.metric > span, .server-glyph, .form-heading > span').evaluate_all("elements => elements.every(el => {\n                const icon = el.querySelector('svg'); if (!icon) return true;\n                const a = el.getBoundingClientRect(), b = icon.getBoundingClientRect();\n                return Math.abs(a.x + a.width / 2 - b.x - b.width / 2) < 1 && Math.abs(a.y + a.height / 2 - b.y - b.height / 2) < 1;\n            })"), 'Boxed icons must be centered'
        if scenario == 'onboarding':
            settings = page.get_by_role('button', name='App settings', exact=True).bounding_box()
            updates = page.get_by_role('button', name='Check for app updates', exact=True).bounding_box()
            assert abs(settings['y'] - updates['y']) < 1, 'Onboarding buttons must share a baseline'
            assert settings['x'] + settings['width'] + 8 <= updates['x'], 'Onboarding buttons overlap'
            page.get_by_label('IP address or hostname', exact=True).fill('example.invalid')
            page.get_by_label('Private key path', exact=True).fill('/tmp/sirin-synthetic-key')
            page.get_by_role('button', name='Verify VPS', exact=False).click()
            page.get_by_role('button', name='Fingerprint matches — inspect network', exact=True).click()
            page.get_by_role('button', name='Install SirinVPN', exact=True).click()
            expect(page.get_by_role('heading', name='Securing your VPS')).to_be_visible()
            inspect(page, prefix + '-provisioning')
            page.evaluate('window.scrollTo(0, 0)')
            for label, original in [('App settings', settings), ('Check for app updates', updates)]:
                actual = page.get_by_role('button', name=label, exact=True).bounding_box()
                assert all((abs(actual[key] - original[key]) < 1 for key in actual)), (label, original, actual)
        if scenario != 'onboarding':
            nav = page.get_by_role('navigation', name='Main navigation' if True and width > 760 else 'Mobile navigation')
            for name in ['Devices', 'Settings', 'Servers', 'Home']:
                nav.get_by_role('button', name=name, exact=False).click()
                inspect(page, prefix + '-' + name.lower())
                if name == 'Devices' and True and (scenario == 'connected'):
                    search = page.get_by_role('searchbox', name='Search devices')
                    search.fill('no matching device')
                    expect(page.get_by_text('No devices match your search.')).to_be_visible()
                    search.fill('Android')
                    expect(page.locator('.device-row')).to_have_count(1)
                    expect(page.locator('.device-row')).to_contain_text('Android phone')
                    search.fill('')
                    expect(page.locator('.port-forward-form')).to_have_count(0)
                    expect(page.locator('.invitation-list')).to_have_count(0)
                    row = page.locator('.device-row').filter(has_text='Android phone')
                    expect(row.get_by_text('Recently active', exact=True)).to_be_visible()
                    row.locator('.device-row-summary').click()
                    expect(row.locator('.device-row-details')).to_be_visible()
                    row.get_by_role('button', name='Actions for Android phone').click()
                    expect(row.get_by_role('menuitem', name='Rename device', exact=True)).to_be_visible()
                    expect(row.get_by_role('menuitem', name='Make Admin', exact=True)).to_be_visible()
                    inspect(page, prefix + '-device-expanded')
                    page.keyboard.press('Escape')
                    expect(row.get_by_role('button', name='Actions for Android phone')).to_be_focused()
                    row.locator('.device-row-summary').press('Enter')
                    expect(row.locator('.device-row-details')).not_to_be_visible()
                    expect(page.get_by_text('No active invitations.', exact=False)).to_be_visible()
                if name == 'Settings' and True:
                    trigger = page.get_by_role('button', name='App updates', exact=True)
                    trigger.click()
                    dialog = page.get_by_role('dialog')
                    expect(dialog).to_be_visible()
                    page.keyboard.press('Tab')
                    assert dialog.evaluate('el => el.contains(document.activeElement)'), 'Dialog lost keyboard focus'
                    inspect(page, prefix + '-updates')
                    page.keyboard.press('Escape')
                    expect(dialog).not_to_be_visible()
                    expect(trigger).to_be_focused()
                if name == 'Settings':
                    for category in ['Connection', 'Network', 'Keys & recovery', 'VPS maintenance', 'General']:
                        page.get_by_role('tab', name=category, exact=True).click()
                        inspect(page, prefix + '-settings-' + category.lower())
                        if True and category == 'Network' and (scenario == 'connected'):
                            expect(page.get_by_role('button', name='Open port', exact=True)).to_be_visible()
                            page.get_by_label('Public port', exact=True).fill('48080')
                            page.get_by_label('Device port', exact=True).fill('8080')
                            expect(page.get_by_label('Mapping preview')).to_contain_text('48080')
                            inspect(page, prefix + '-port-forward-preview')
                    general = page.get_by_role('tab', name='General', exact=True)
                    general.press('End')
                    expect(page.get_by_role('tab', name='VPS maintenance', exact=True)).to_be_focused()
                    page.keyboard.press('ArrowRight')
                    expect(general).to_be_focused()
                    animation = page.get_by_role('switch', name='Interface animations')
                    animation.uncheck()
                    expect(page.locator('html')).to_have_attribute('data-motion', 'reduced')
                    notifications = page.get_by_role('switch', name='Connection notifications')
                    notifications.check()
                    page.get_by_role('button', name='Test notification').click()
                    expect(page.get_by_role('status').filter(has_text='Test notification sent')).to_be_visible()
                    page.get_by_role('switch', name='Close to tray').check()
                    page.get_by_role('switch', name='Start on system startup').check()
                    page.reload(wait_until='networkidle')
                    expect(page.locator('html')).to_have_attribute('data-motion', 'reduced')
                    nav.get_by_role('button', name='Settings', exact=False).click()
                    expect(page.get_by_role('switch', name='Connection notifications')).to_be_checked()
                    expect(page.get_by_role('switch', name='Close to tray')).to_be_checked()
                if name == 'Home' and True and (scenario == 'disconnected'):
                    expect(page.locator('.connection-options')).to_have_count(0)
                    nav.get_by_role('button', name='Settings', exact=False).click()
                    page.get_by_role('tab', name='Connection', exact=True).click()
                    page.get_by_role('switch', name='Choose transport automatically').uncheck()
                    page.get_by_role('radio', name='Direct UDP Standard WireGuard', exact=True).check()
                    page.get_by_role('button', name='Save preferences', exact=True).click()
                    expect(page.get_by_role('button', name='Save preferences', exact=True)).to_have_count(0)
                    inspect(page, prefix + '-connection-settings')
                    nav.get_by_role('button', name='Home', exact=False).click()
                    expect(page.locator('.connection-options')).to_have_count(0)
                    nav.get_by_role('button', name='Settings', exact=False).click()
                    page.get_by_role('tab', name='Connection', exact=True).click()
                    expect(page.get_by_role('radio', name='Direct UDP Standard WireGuard', exact=True)).to_be_checked()
                    nav.get_by_role('button', name='Home', exact=False).click()
                    nav.get_by_role('button', name='Servers', exact=False).click()
                    nav.get_by_role('button', name='Home', exact=False).click()
            page.go_back()
            expect(nav.get_by_role('button', name='Servers', exact=False)).to_have_attribute('aria-current', 'page')
            nav.get_by_role('button', name='Home', exact=False).click()
            if scenario == 'connected':
                page.get_by_role('button', name='Disconnect', exact=True).click()
                expect(page.get_by_role('button', name='Connect', exact=True)).to_be_enabled()
                assert page.evaluate("window.__sirinCommands.includes('disconnect_server')")
            else:
                page.get_by_role('button', name='Connect', exact=True).click()
                expect(page.get_by_role('button', name='Disconnect', exact=True)).to_be_enabled()
        assert not errors, errors
        assert not page.evaluate("window.__sirinCommands.some(name => name.includes('check_release'))"), 'Opening pages performed an automatic release check'
        print(f"PASS {'desktop'} {scenario} {width}x{height}", flush=True)
        page.close()
    browser.close()
(OUTPUT.parent / 'accessibility.json').write_text(json.dumps(violations, indent=2) + '\n')
assert not violations, f'{len(violations)} accessibility findings; see .cache/overhaul/accessibility.json'
