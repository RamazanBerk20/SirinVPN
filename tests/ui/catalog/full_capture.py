"""Capture every catalog state on the desktop and Android layouts in both themes, and audit each one.

One reproducible run: every scenario from scenarios.py (plus coverage_states.py) is mounted with fictional
API fixtures in headless Chromium, once per form factor and theme. Each state gets screenshots of every
scroll position, an in-page UX audit (audit.js) and its visible text; the run ends with a UI-string
coverage report that names every English message no captured state showed.

  cd apps/desktop && node_modules/.bin/vite --config ../../tests/ui/catalog/vite.config.ts --port 1440 &
  PLAYWRIGHT_BROWSERS_PATH=<repo>/.cache/remediation-browsers <repo>/.cache/remediation-python/bin/python \
    tests/ui/catalog/full_capture.py --url http://127.0.0.1:1440 --output <repo>/.cache/ui-capture-YYYY-MM-DD/before
"""
from __future__ import annotations
import argparse, base64, collections, datetime, hashlib, html, json, math, os, re, sys, time
from multiprocessing import Process
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
# Another checkout's UI (for example main, for a before/after pair) served with this harness copied into it.
UI = Path(os.environ.get('SIRINVPN_UI_ROOT', ROOT)).resolve()
sys.path.insert(0, str(HERE))
FORMS = {
    'desktop': {'viewport': {'width': 1280, 'height': 860}},
    # Galaxy S25-class phone; the Android entry adds mobile-native.css and the `android` class.
    'mobile': {'viewport': {'width': 412, 'height': 915}, 'is_mobile': True, 'has_touch': True,
               'user_agent': 'Mozilla/5.0 (Linux; Android 16; SM-S937B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Mobile Safari/537.36 wv'},
}
AUDIT = (HERE / 'audit.js').read_text()
FOCUS = (HERE / 'focus.js').read_text()


def all_cases():
    from scenarios import scenarios
    from coverage_states import coverage_states
    cases = scenarios('desktop')
    coverage_states(cases)
    return cases


class Page:
    def __init__(self, playwright, url, form, theme):
        self.browser = playwright.chromium.launch(headless=True)
        self.page = self.browser.new_page(**FORMS[form], device_scale_factor=1, color_scheme=theme, reduced_motion='reduce')
        self.form, self.theme = form, theme
        self.cdp = self.page.context.new_cdp_session(self.page)
        self.page.goto(url + '/?platform=desktop')
        self.page.wait_for_function('window.__catalog?.ready', timeout=30000)
        if form == 'mobile':
            self.page.evaluate(f"import('/@fs{UI}/tests/android/catalog.ts')")
            self.page.wait_for_function("document.documentElement.classList.contains('android')", timeout=30000)
        self.platform = 'android' if form == 'mobile' else 'desktop'
        # Load every lazy page once, so no state is captured on a Suspense "Loading…" fallback.
        modules = sorted(str(p.relative_to(UI / 'apps/desktop')) for p in (UI / 'apps/desktop/src').rglob('*.tsx') if '.test.' not in p.name and p.name != 'main.tsx')
        self.page.evaluate('paths => Promise.all(paths.map(p => import("/" + p)))', modules)

    def call(self, method, *args):
        return self.page.evaluate(f'window.__catalog.{method}(' + ','.join(json.dumps(a, ensure_ascii=False) for a in args) + ')')

    def shot(self, path):
        # WebP at quality 90 is a quarter of the PNG size and still sharp enough to judge text and borders.
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(self.cdp.send('Page.captureScreenshot', {'format': 'webp', 'quality': 90})['data']))
        return path

    def capture(self, folder, stem):
        """Top of the state, then each visible scroll region stepped to its end."""
        self.call('settled')
        ports = self.call('scrollPorts')
        for port in ports:
            self.call('scroll', port['index'], 0)
        files = [self.shot(folder / f'{stem}--01-top.webp')]
        for port in ports:
            if port['height'] < 60 or port['box']['width'] < 50 or port['tag'] == 'TEXTAREA':
                continue
            maximum = port['total'] - port['height']
            count = max(1, math.ceil(maximum / max(80, port['height'] * 0.8)))
            for step in range(1, count + 1):
                self.call('scroll', port['index'], round(maximum * step / count))
                files.append(self.shot(folder / f'{stem}--{len(files) + 1:02d}-scroll.webp'))
            self.call('scroll', port['index'], 0)
        return files


def focus_pass(page, steps=40):
    """Tab through the state: every stop needs a visible focus indicator and must be on screen."""
    findings, seen = [], set()
    page.evaluate('document.activeElement?.blur()')
    for _ in range(steps):
        page.keyboard.press('Tab')
        stop = page.evaluate(FOCUS)
        if not stop or stop['target'] in seen:
            break
        seen.add(stop['target'])
        if not stop['visible']:
            findings.append({'kind': 'no-focus-ring', 'target': stop['target'], 'detail': 'focus looks the same as rest'})
        if not stop['onscreen']:
            findings.append({'kind': 'focus-offscreen', 'target': stop['target'], 'detail': 'focused control is outside the viewport'})
    return findings


def worker(url, form, theme, cases, out, log_path):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as playwright, open(log_path, 'a') as log:
        page = Page(playwright, url, form, theme)
        for number, case in enumerate(cases, 1):
            result = {'form': form, 'theme': theme, 'family': case['family'], 'id': case['id'], 'success': False, 'files': []}
            started = time.monotonic()
            try:
                page.call('mount', {**case.get('state', {}), 'platform': page.platform, 'theme': theme})
                page.call('actions', case.get('actions', []))
                required = set(case.get('required_calls', [])) | set(case.get('state', {}).get('errors', {})) | set(case.get('state', {}).get('holds', []))
                for action in case.get('actions', []):
                    required |= set(action.get('patch', {}).get('errors', {})) | set(action.get('patch', {}).get('holds', []))
                deadline = time.monotonic() + 2
                while (missing := required - set(page.page.evaluate('window.__catalog.state.calls.map(c=>c.name)'))) and time.monotonic() < deadline:
                    time.sleep(.05)
                held = case.get('state', {}).get('holds') or any(a.get('patch', {}).get('holds') for a in case.get('actions', []))
                deadline = time.monotonic() + 3
                while not held and 'Loading…' in page.page.evaluate('document.body.innerText') and time.monotonic() < deadline:
                    time.sleep(.1)
                page.call('settled')
                snapshot = page.call('inspect')
                # Native confirmations are OS dialogs: no screenshot, but their text counts as shown.
                snapshot['text'] += '\n' + '\n'.join(str(d.get('message', '')) for d in snapshot.get('dialogs', []))
                if missing:
                    raise RuntimeError('Fixture operation was not exercised: ' + ', '.join(sorted(missing)))
                if snapshot['unknown']:
                    raise RuntimeError('Missing fixtures: ' + str(snapshot['unknown']))
                for check in case.get('assertions', []) + ([{'text': case['expect']}] if case.get('expect') else []):
                    page.call('assertVisible', check)
                folder = out / f'{form}-{theme}' / case['family']
                audit = page.page.evaluate(AUDIT, form)
                if case.get('focus_pass'):
                    audit += focus_pass(page.page)
                files = page.capture(folder, case['id'])
                text = [snapshot['text']]
                if case.get('expand') and page.page.evaluate('Boolean(document.querySelector("details:not([open])"))'):
                    page.call('act', {'details': 'open'})
                    files += page.capture(folder, case['id'] + '--expanded')
                    text.append(page.call('inspect')['text'])
                    audit += page.page.evaluate(AUDIT, form)
                result.update(success=True, files=[str(f.relative_to(out)) for f in files], audit=audit, text=text, seconds=round(time.monotonic() - started, 2))
            except Exception as error:
                result['error'] = str(error)[:600]
                try:
                    result['files'] = [str(page.shot(out / f'{form}-{theme}' / '_failed' / f"{case['family']}--{case['id']}.webp").relative_to(out))]
                except Exception:
                    pass
            log.write(json.dumps(result, ensure_ascii=False) + '\n')
            log.flush()
            print(f"{form}-{theme} {number}/{len(cases)} {'OK  ' if result['success'] else 'FAIL'} {case['family']}/{case['id']}", flush=True)
        page.browser.close()


def messages():
    """Every English UI message as (key, static fragments). `native` is Android notification text, not web UI."""
    found = {}
    def walk(prefix, node):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(f'{prefix}.{key}' if prefix else key, value)
        elif isinstance(node, str):
            found[prefix] = [p.strip() for p in re.split(r'\{\{[^}]*\}\}|\{[^}]*\}|<[^>]*>', node) if len(p.strip()) >= 3]
    for path in sorted((UI / 'apps/desktop/src/locales/en').glob('*.json')):
        if path.stem not in {'native', 'format'}:
            walk(path.stem, json.loads(path.read_text()))
    return found


def report(out, results, cases):
    seen = ' '.join(re.sub(r'\s+', ' ', t) for r in results if r['success'] for t in r['text'])
    uncovered = sorted(key for key, parts in messages().items() if parts and not all(p in seen for p in parts))
    total = len(messages())
    kinds = collections.Counter(f['kind'] for r in results if r['success'] for f in r['audit'])
    per_state = collections.defaultdict(list)
    for r in results:
        if r['success']:
            for f in r['audit']:
                per_state[(f['kind'], f['target'], f['detail'])].append(f"{r['form']}-{r['theme']}/{r['family']}/{r['id']}")
    findings = sorted(({'kind': k, 'target': t, 'detail': d, 'states': len(s), 'example': s[0]} for (k, t, d), s in per_state.items()), key=lambda f: (f['kind'], -f['states']))
    images = [out / f for r in results for f in r['files']]
    summary = {
        'generated': datetime.datetime.now().isoformat(timespec='seconds'),
        'scenarios': len(cases), 'states': len(results), 'passed': sum(r['success'] for r in results),
        'failed': [f"{r['form']}-{r['theme']}/{r['family']}/{r['id']}: {r.get('error')}" for r in results if not r['success']],
        'images': len(images), 'bytes': sum(p.stat().st_size for p in images if p.exists()),
        'message_coverage': {'covered': total - len(uncovered), 'total': total, 'uncovered': uncovered},
        'audit_counts': dict(kinds), 'audit_findings': findings,
    }
    (out / 'summary.json').write_text(json.dumps(summary, indent=1, ensure_ascii=False) + '\n')
    rows = []
    for r in sorted(results, key=lambda r: (r['family'], r['id'], r['form'], r['theme'])):
        thumbs = ''.join(f'<a href="{html.escape(f)}"><img loading="lazy" src="{html.escape(f)}"></a>' for f in r['files'])
        issues = '<br>'.join(html.escape(f"{f['kind']}: {f['target']} — {f['detail']}") for f in r.get('audit', [])[:12])
        rows.append(f"<tr><td>{html.escape(r['family'])}/<b>{html.escape(r['id'])}</b><br>{r['form']} {r['theme']}{'' if r['success'] else ' <em>FAILED</em>'}<small>{issues}</small></td><td>{thumbs}</td></tr>")
    (out / 'index.html').write_text('<!doctype html><meta charset="utf-8"><title>SirinVPN UI catalog</title><style>body{font:13px system-ui;margin:16px}td{vertical-align:top;border-bottom:1px solid #ccc;padding:6px}img{height:220px;margin:2px;border:1px solid #999}small{display:block;color:#a40;max-width:360px}</style>'
                                  f"<h1>SirinVPN UI catalog</h1><p>{summary['passed']}/{summary['states']} states, {summary['images']} images, message coverage {summary['message_coverage']['covered']}/{total}</p><table>{''.join(rows)}</table>")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', default='http://127.0.0.1:1440')
    parser.add_argument('--output', type=Path, default=ROOT / '.cache' / f'ui-capture-{datetime.date.today()}' / 'run')
    parser.add_argument('--forms', default='desktop,mobile')
    parser.add_argument('--themes', default='dark,light')
    parser.add_argument('--filter', default='')
    parser.add_argument('--workers', type=int, default=2, help='browser processes per form/theme pair')
    parser.add_argument('--report-only', action='store_true', help='rebuild summary.json and index.html from results')
    parser.add_argument('--focus-only', action='store_true', help='only the first state of each family, with its keyboard pass')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    cases = [c for c in all_cases() if re.search(args.filter, c['family'] + '/' + c['id'])]
    families = set()
    for case in cases:
        # The first state of each family also gets a keyboard pass.
        case['focus_pass'] = case['family'] not in families
        families.add(case['family'])
    if args.focus_only:
        cases = [c for c in cases if c['focus_pass']]
    if not cases:
        parser.error('No scenarios matched the filter')
    if not args.report_only:
        jobs = []
        for form in args.forms.split(','):
            for theme in args.themes.split(','):
                selected = [c for c in cases if form in c.get('forms', FORMS)]
                for shard in range(args.workers):
                    jobs.append(Process(target=worker, args=(args.url, form, theme, selected[shard::args.workers], out, out / f'results-{form}-{theme}-{shard}.jsonl')))
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
    latest = {}
    for log in sorted(out.glob('results-*.jsonl')):
        for line in log.read_text().splitlines():
            item = json.loads(line)
            latest[(item['form'], item['theme'], item['family'], item['id'])] = item
    summary = report(out, list(latest.values()), cases)
    print(json.dumps({k: summary[k] for k in ('states', 'passed', 'images', 'bytes', 'audit_counts')}, indent=1))
    print('message coverage', summary['message_coverage']['covered'], '/', summary['message_coverage']['total'])
    return int(bool(summary['failed']))


if __name__ == '__main__':
    raise SystemExit(main())
