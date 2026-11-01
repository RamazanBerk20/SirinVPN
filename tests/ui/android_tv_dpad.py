"""Drive the Android UI with D-pad keys only, as Android TV's WebView runs it.

WebView turns on spatial navigation when the device has no touchscreen, and the TV
reports `pointer: none`; the Chromium flags below reproduce both. Build the
fictional Android catalog first (fixtures only, no VPN or network access):

    pnpm --dir apps/desktop exec vite build --config ../../tests/android/catalog.config.ts

Requires Python Playwright + Chromium. Covers connect/disconnect, server choice,
connection status and the destinations, and checks that every focused control
shows a ring that is on screen and not clipped. This is Chromium, not a TV.
"""
import argparse
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--catalog', type=Path, default=ROOT / 'target/android-catalog')
parser.add_argument('--output', type=Path, default=ROOT / 'target/android-evidence/tv-dpad')
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
page_file = args.catalog / 'tv.html'
# The Tauri stub tests/ui/catalog/vite.config.ts injects, plus plugin listener registration, which never answers here.
page_file.write_text('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                     '<script>window.__TAURI_INTERNALS__={metadata:{currentWindow:{label:"main"},currentWebview:{label:"main"}},transformCallback:()=>1,invoke:()=>new Promise(()=>{})}</script>'
                     '<link rel="stylesheet" href="catalog.css"></head><body><div id="root"></div><script src="catalog.js"></script></body></html>')
RING = """() => {
  const e = document.activeElement;
  if (!e || e === document.body) return {label: '', problem: 'nothing focused'};
  const label = (e.getAttribute('aria-label') || e.innerText || '').replace(/\\s+/g, ' ').trim();
  const s = getComputedStyle(e), w = parseFloat(s.outlineWidth), o = parseFloat(s.outlineOffset);
  if (!e.matches(':focus-visible') || s.outlineStyle === 'none' || w < 2) return {label, problem: 'no focus ring'};
  const r = e.getBoundingClientRect(), ring = {l: r.left - o - w, t: r.top - o - w, r: r.right + o + w, b: r.bottom + o + w};
  if (ring.l < 0 || ring.t < 0 || ring.r > innerWidth || ring.b > innerHeight) return {label, problem: 'ring off screen'};
  for (let a = e.parentElement; a; a = a.parentElement) {
    if (getComputedStyle(a).overflow === 'visible') continue;
    const c = a.getBoundingClientRect();
    if (ring.l < c.left - .5 || ring.t < c.top - .5 || ring.r > c.right + .5 || ring.b > c.bottom + .5) return {label, problem: 'ring clipped by ' + a.className};
  }
  return {label, problem: null};
}"""
steps = []

with sync_playwright() as pw:
    browser = pw.chromium.launch(args=['--enable-spatial-navigation',
        '--blink-settings=primaryPointerType=1,availablePointerTypes=1,primaryHoverType=1,availableHoverTypes=1'])
    page = browser.new_page(viewport={'width': 960, 'height': 540}, reduced_motion='reduce',
        user_agent='Mozilla/5.0 (Linux; Android 14; Android TV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0 Mobile Safari/537.36')
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(page_file.as_uri())
    page.wait_for_function('window.__catalog')
    assert page.evaluate("matchMedia('(pointer: none)').matches"), 'Chromium did not emulate a D-pad device'
    page.evaluate("window.__catalog.mount({platform: 'android', profileCount: 2})")

    def press(key, until):
        """Press `key` (arrows repeat, to scroll) until a control labelled `until` (or one of them) shows a visible ring."""
        for _ in range(12 if key.startswith('Arrow') else 1):
            if key:
                page.keyboard.press(key)
            for _ in range(20):  # Connect and Disconnect disable the focused button while busy.
                page.wait_for_timeout(250)
                state = page.evaluate(RING)
                if state['problem'] != 'nothing focused':
                    break
            assert state['problem'] is None, (key, until, state)
            if any(label in state['label'] for label in ([until] if isinstance(until, str) else until)):
                break
        else:
            raise AssertionError(f'D-pad did not reach {until!r}; stopped at {state["label"]!r}')
        steps.append(state['label'])
        page.screenshot(path=str(args.output / f'{len(steps):02d}.png'))

    def connected():
        return page.evaluate('window.__catalog.state.connected')

    press('', until='Disconnect')  # Home starts on its main action.
    press('Enter', until='Connect')
    assert not connected()
    press('Enter', until='Disconnect')  # Focus survives the busy, disabled state.
    assert connected()
    press('Enter', until='Connect')
    press('ArrowDown', until='Server: My private VPS')
    press('Enter', until='Choose a server')
    press('ArrowDown', until='Amsterdam VPS')
    press('Enter', until='Server: Amsterdam VPS')
    press('ArrowUp', until='Connect')
    press('ArrowDown', until='Connection details')
    press('Enter', until='Back')
    assert page.evaluate('location.hash') != '#home', 'Connection details did not open'
    assert 'Status' in page.inner_text('body') and 'Disconnected' in page.inner_text('body')
    press('Enter', until='Connect')
    assert page.evaluate('location.hash') == '#home'
    press('ArrowUp', until=('Servers', 'Devices'))
    if 'Servers' not in steps[-1]:
        press('ArrowLeft', until='Servers')
    press('Enter', until='Servers')
    assert page.evaluate('location.hash') == '#servers'
    press('ArrowDown', until='Amsterdam VPS')
    assert not errors, errors
    browser.close()
print('PASS D-pad:', ' → '.join(steps))
