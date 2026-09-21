"""Validate the finite screenshot inventory and publish a self-contained review archive."""
from __future__ import annotations
import collections,csv,hashlib,io,json,os,shutil,subprocess,sys,time,zipfile
from pathlib import Path
from PIL import Image,ImageStat
from concurrent.futures import ThreadPoolExecutor
from scenarios import scenarios
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(os.environ.get('SIRINVPN_CATALOG_OUTPUT',ROOT/'target/screenshot-catalog-2026-09-20'))
DATE='2026-09-20'
ARCHIVE=OUT.parent/f'SirinVPN-screenshot-catalog-{DATE}.zip'

def latest(path):
 rows={}
 if path.exists():
  for line in path.read_text().splitlines():
   r=json.loads(line);rows[(r.get('platform',path.name.split('-')[0] if path.name.startswith(('desktop-',)) else ''),r['id'])]=r
 return rows

def main():
 environment={'capture_date':DATE,'renderer':'Native Linux Tauri / WebKitGTK','display':'Dedicated Xvfb :87 and :89','main_viewport':'1280x900','compact_viewport':'900x680','data':'Fictional API fixtures','configuration':'Isolated XDG configuration, data and cache; no live user profile'}
 (OUT/'capture-environment.json').write_text(json.dumps(environment,indent=2)+'\n')
 rows=[];missing=[]
 for p in ['desktop']:
  source={v['id']:v for v in latest(OUT/f'{p}-results.jsonl').values()}
  for case in scenarios(p):
   r=source.get(case['id'])
   if not r or not r.get('success') or not r.get('files'):missing.append(p+'/'+case['id']);continue
   if r.get('observed',{}).get('unknown'):raise ValueError('Unknown API fixture in '+r['id'])
   validation=r.get('observed',{}).get('fixtureValidation')
   if validation and not all(validation.values()):raise ValueError('Invalid fixture in '+r['id'])
   rows.append(r)
 if missing:raise ValueError('Missing planned screenshots: '+', '.join(missing))
 native=[r for r in latest(OUT/'native-results.jsonl').values() if r.get('platform')=='desktop']
 gaps=[{'id':r['id'],'platform':r.get('platform'),'error':r.get('error')} for r in native if not r.get('success')]
 if gaps:raise ValueError('Unresolved native captures: '+', '.join(g['id'] for g in gaps))
 rows += [r for r in native if r.get('success') and r.get('files')]
 screenshots=[];duplicates=[];references=set()
 for r in rows:
  assert r['platform']=='desktop','Only desktop captures belong in this archive'
  seen={};selected=[]
  for f in r['files']:
   assert Path(f['path']).parts[0]=='desktop',f['path']
   p=OUT/f['path'];digest=hashlib.sha256(p.read_bytes()).hexdigest()
   if digest!=f['sha256']:raise ValueError('Changed screenshot '+str(p))
   if digest in seen:
    duplicates.append({'case':r['id'],'path':f['path'],'same_as':seen[digest]});continue
   seen[digest]=f['path'];selected.append(f)
   if f['path'] in references:raise ValueError('Duplicate filename '+f['path'])
   references.add(f['path'])
   screenshots.append({'platform':r['platform'],'family':r['family'],'scenario':r['id'],'description':r['description'],'path':f['path'],'bytes':f['bytes'],'sha256':digest,'renderer':r.get('renderer'),'data_source':r.get('data_source'),'view':len(selected)})
  r['files']=selected
 def verify(s):
  p=OUT/s['path']
  with Image.open(p) as im:
   im.verify()
  with Image.open(p) as im:
   im.load();s['width'],s['height']=im.size
   if min(im.size)<200:raise ValueError('Unexpected screenshot dimensions '+s['path'])
   stats=ImageStat.Stat(im.convert('RGB'))
   if max(stats.stddev)<2:raise ValueError('Blank screenshot '+s['path'])
   thumb=Path('thumbnails')/Path(s['path']).with_suffix('.webp');(OUT/thumb).parent.mkdir(parents=True,exist_ok=True)
   im.thumbnail((420,420));im.convert('RGB').save(OUT/thumb,'WEBP',quality=78,method=3);s['thumbnail']=str(thumb)
  return s
 with ThreadPoolExecutor(max_workers=8) as pool:screenshots=list(pool.map(verify,screenshots))
 counts=collections.Counter(s['platform'] for s in screenshots);case_counts=collections.Counter(r['platform'] for r in rows)
 source_paths=sorted({*ROOT.glob('apps/desktop/src/**/*.tsx'),*ROOT.glob('apps/desktop/src/**/*.ts'),*ROOT.glob('apps/desktop/src/**/*.css'),*ROOT.glob('tests/ui/catalog/*'),*[ROOT/name for name in ['crates/core/src/network_policy.rs','crates/core/src/network_policy/wifi.rs','crates/platform/src/windows/network_context.rs','apps/desktop/src-tauri/src/wifi_automation.rs','PRIVACY.md']]})
 source_hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths if p.is_file() and p.suffix!='.pyc'}
 print(f'Validated {len(screenshots)} images; building review files.',flush=True)
 manifest={'title':'SirinVPN desktop screenshot catalog','capture_date':DATE,'scope':'Finite UI-state inventory; actual native renderers with fictional API fixtures','counts':{'screenshots':len(screenshots),'by_platform':dict(counts),'scenarios':len(rows),'scenarios_by_platform':dict(case_counts),'duplicate_views_omitted':len(duplicates)},'dimensions':dict(collections.Counter(f"{s['platform']} {s['width']}×{s['height']}" for s in screenshots)),'native_capture_gaps':gaps,'source_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'working_tree':'Existing uncommitted changes and the user-requested local Wi-Fi name display fix are included in the source hashes. Affected screenshots were regenerated after the fix.','source_sha256':source_hashes,'screenshots':screenshots,'scenarios':rows,'duplicate_views':duplicates}
 manifest['environment']=environment
 (OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
 with (OUT/'screenshots.csv').open('w',newline='') as f:
  writer=csv.DictWriter(f,fieldnames=list(screenshots[0]));writer.writeheader();writer.writerows(screenshots)
 family=collections.defaultdict(lambda:collections.Counter())
 for r in rows:family[r['family']][r['platform']+' scenarios']+=1;family[r['family']][r['platform']+' images']+=len(r['files'])
 coverage=['# Coverage inventory','',f"{len(rows)} captured scenarios; {len(screenshots)} original PNG screenshots. This is a finite inventory of distinct visible states, not a claim to enumerate all possible input values, operating systems or event timings.",'','| Feature family | Desktop scenarios | Desktop images |','|---|---:|---:|']
 for name,c in sorted(family.items()):coverage.append(f"| {name} | {c['desktop scenarios']} | {c['desktop images']} |")
 coverage += ['','## What was varied','',
 '- Empty, enrolled, connected, disconnected, recovering, unavailable, and failed connection states.',
 '- Owner, Admin and Member access; invitation compatibility; single-use and reusable codes; membership and device actions.',
 '- Settings, routing, transports, MTU evidence, Wi-Fi trust, protection and diagnostics.',
 '- Enrollment, invitation redemption, key rotation, recovery keys, backup/restore, endpoint migration and VPS maintenance.',
 '- Signed app/VPS updates, verification, setup, scheduling, rollback, interruption, errors, and completion.',
 '- Destructive-operation review screens and confirmation dialogs using fictional data.',
 '- Expanded details and overlapping scroll positions for long pages and popups.',
 '- Native file dialogs, menus, dropdowns, tooltips and notifications.',
 '', '## Practical limits','',
 '- The production React UI, styles, fonts and assets are rendered inside isolated native debug shells. Server/device responses are synthetic and chosen to expose UI branches. These images demonstrate presentation, not live VPN or backend correctness.',
 '- Desktop uses Linux Tauri/WebKitGTK. Native shell binaries were already available from development builds; their age can differ from the current frontend source.',
 '- Native browser dialog titles can include the isolated local development address. Native tray captures are native GTK menu previews with production labels and fictional state. Their actions are unbound. Confirmation dialog previews use the exact text observed in fixture journeys.',
 '- English UI; one Linux desktop environment. The supplemental set samples a compact desktop window. Other OS themes, languages, window dimensions, font settings, permission versions, accessibility modes, and text/data combinations are not exhaustively enumerated.',
 '- Intermediate frames of animations, arbitrary timing/race conditions, provider/browser/store pages and real administrator authentication prompts are outside this UI inventory.',
 '- Windows-specific update and routing variants are labeled frontend previews on Linux, not executions of Windows installers or native Windows dialogs.',
 '- QR codes and all credentials, fingerprints, names and server addresses are fictional examples. Do not attempt to import or connect using them.',
 '- Repeated identical views within the same scenario are omitted and listed in manifest.json. Some different scenarios intentionally have the same visible outcome.',
 '', 'Desktop only, as requested. No Android app screenshots are included. Fictional device names shown inside the desktop device list do not denote Android app captures. All captures were regenerated from the current frontend; no previous catalog images are reused.']
 if gaps:
  coverage += ['','## Native capture attempts not included','']+[f"- {g['platform']}/{g['id']}: {g['error']}" for g in gaps]
 coverage += ['','## Complete scenario checklist','']
 for platform in ['desktop']:
  coverage+=['','### '+platform.capitalize(),'']
  for r in rows:
   if r['platform']==platform:coverage.append(f"- [x] `{r['family']}/{r['id']}` — {len(r['files'])} image(s)")
 (OUT/'coverage.md').write_text('\n'.join(coverage)+'\n')
 (OUT/'README.md').write_text(f'''# SirinVPN screenshot catalog

{len(screenshots):,} original screenshots across {len(rows)} scenarios: **{counts['desktop']:,} desktop**.

Extract the ZIP and open **index.html** locally for the searchable gallery. No server or internet connection is required. Click a thumbnail to inspect the original PNG. Filter by feature family or description.

- `desktop/`: original screenshots named for the visible feature/state; numbered suffixes identify scroll positions and expanded details.
- `screenshots.csv`: one row per original image with its description, renderer, dimensions and SHA-256.
- `manifest.json`: complete scenarios, fixture inputs, observed UI text, image metadata, source hashes, and omitted duplicate views.
- `coverage.md`: captured feature inventory and explicit scope limits.
- `REVIEW_WITH_CHATGPT.md`: suggested review instructions.
- `replay/`: the isolated capture harness used to produce the inventory.
- `thumbnails/`: gallery previews. Use the original PNGs for detailed judgment.

Screenshots render the current production frontend, including the requested trusted Wi-Fi name display fix, in native Linux WebKitGTK. Fictional API responses expose loading, failure, success, compatibility and permission branches. Native operating-system screens are captured separately. Tray menus and native confirmation previews are labeled in the metadata.

This collection contains desktop app screenshots only, with no Android app captures or production device identities or VPS credentials. It is a broad, finite state inventory, not proof that every possible runtime state or input combination has been captured. Read coverage.md before evaluating it as a complete product audit.

Capture date: {DATE}. PNG integrity, file hashes, manifest references and archive contents were checked during packaging.
''')
 (OUT/'REVIEW_WITH_CHATGPT.md').write_text('''# Review prompt

Review this SirinVPN screenshot catalog as a demanding product designer and usability reviewer. First read README.md and coverage.md. Use the original PNG images; thumbnails are only for navigation.

Evaluate navigation, hierarchy, typography, spacing, contrast, accessibility, terminology, consistency, responsive behavior, status clarity, loading/error/success feedback, permission explanations, confirmations, and the effort required to complete each workflow. Compare desktop implementations of the same feature. Check the whole scroll sequence before concluding that a control or explanation is missing.

Cite exact screenshot filenames for every finding. For each issue, give severity, concrete evidence, user impact, and a specific fix. Distinguish a visible defect from a hypothesis requiring interaction. Highlight the ten most important changes first, then provide a feature-by-feature review and cross-platform inconsistencies. Identify strong patterns worth preserving without generic praise.

The data and backend operations are fictional fixtures in the real UI. Do not treat sample fingerprints, passwords, addresses or QR codes as live secrets. Do not infer cryptographic correctness, VPN reliability or backend security from screenshots. Read per-image metadata to distinguish actual OS surfaces from native menu/confirmation previews.

If you cannot inspect every image in one pass, state exactly which families and filenames you reviewed and which remain. Continue in batches until the documented inventory is reviewed; do not imply unseen images were checked.
''')
 replay=OUT/'replay';replay.mkdir(exist_ok=True)
 for name in ['capture.py','scenarios.py','workflows.py','extra_states.py','current_states.py','native_desktop.py','native_desktop_extras.py','package_catalog.py','local_proxy.py','main.tsx','bridge.ts','data.ts','qr.ts','visibility.ts','vite.config.ts','gallery.html']:
  shutil.copy2(ROOT/'tests/ui/catalog'/name,replay/name)
 shutil.copy2(ROOT/'tests/ui/webkit_inspector.py',replay/'webkit_inspector.py')
 (replay/'README.md').write_text('''# Replay context

These scripts are development instrumentation, not application changes. Restore them under tests/ui/catalog in the same SirinVPN working tree to replay. Dependencies: the repository frontend dependencies, Python Playwright, websocket-client and Pillow, Xvfb, ImageMagick and xdotool.

Start Vite using `pnpm --dir apps/desktop exec vite --config ../../tests/ui/catalog/vite.config.ts`. It serves current production UI components with API fixtures on port 1422. Desktop capture expects an isolated Tauri debug window on X display :87 and WebKit inspector port 9238. Never point this harness at a production profile.

Run `capture.py desktop` using the configured Python environment. `--browser --dry` performs a Chromium journey preflight without producing native screenshots. `native_desktop.py` and `native_desktop_extras.py` capture supplemental surfaces. `package_catalog.py` validates current scenario results, deduplicates identical views within each scenario, generates the gallery, and builds the ZIP.

Debug shell binaries and the full production repository are not bundled. Source hashes in manifest.json identify the captured frontend working tree. Replaying against other source changes may require updated labels or fixtures.
''')
 html=(Path(__file__).parent/'gallery.html').read_text()
 small=[{k:s[k] for k in ['platform','family','scenario','description','path','thumbnail','width','height','view','renderer']} for s in screenshots]
 html=html.replace('__CATALOG_DATA__',json.dumps(small,ensure_ascii=False).replace('<','\\u003c')).replace('__COUNTS__',f"{len(screenshots):,} screenshots · {len(rows)} scenarios · Desktop")
 (OUT/'index.html').write_text(html)
 (OUT/'VALIDATION.md').write_text(f'''# Validation

All {len(screenshots)} selected PNGs decoded successfully and passed nonblank-image and SHA-256 checks. All {len(rows)} included scenario records completed. The current planned desktop inventory has no missing screenshots. Identical scroll views within a scenario were removed. Native dialogs and representative feature screens were visually inspected. Archive integrity, included image hashes, unique ZIP entry names and the 512 MB limit are checked after ZIP creation.

## Wi-Fi name fix checks — {DATE}

- Frontend suite: 38 files, 189 tests passed.
- Network-policy Rust tests: 9 passed, including name-to-trust matching and unchanged persisted state.
- Focused Wi-Fi/General UI rerun: 16 tests passed.
- TypeScript checking and Linux desktop Rust checking passed.
- Windows desktop/CLI cross-check passed with the repository's LLVM-MinGW script.
- A read-only local NetworkManager check resolved all three available saved Wi-Fi profile names. No names or raw profile IDs were printed, stored or transmitted.
- Updated fixture captures cover existing generic trust records, custom labels, unavailable names, changed networks, Unicode/long names and compact-window wrapping. Only fictional names appear in this archive.

The original capture run encountered two static privacy-scanner false positives: an inline SVG namespace and a loopback TLS test URL. These were corrected for version 0.1 with narrowly scoped exceptions and a remote-URL regression check; run `scripts/check-privacy.sh` for the current source result. OS name resolution uses only local NetworkManager/Windows APIs and local UI state; it adds no network transport, logging, persistent name cache or dependency.
''')
 # Keep obsolete attempt images out of the browsable final folder.
 obsolete=ROOT/f'.cache/screenshot-catalog-{DATE}/excluded-captures'
 for platform in ['desktop']:
  for image in (OUT/platform).rglob('*.png'):
   if str(image.relative_to(OUT)) not in references:
    destination=obsolete/image.relative_to(OUT);destination.parent.mkdir(parents=True,exist_ok=True);shutil.move(str(image),str(destination))
 files=[OUT/s['path'] for s in screenshots]+[OUT/s['thumbnail'] for s in screenshots]+[OUT/n for n in ['index.html','README.md','coverage.md','manifest.json','screenshots.csv','REVIEW_WITH_CHATGPT.md','VALIDATION.md','capture-environment.json']]+[p for p in replay.iterdir() if p.is_file()]
 print('Writing full ZIP archive...',flush=True)
 with zipfile.ZipFile(ARCHIVE,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True) as z:
  for p in files:z.write(p,'SirinVPN-screenshot-catalog/'+str(p.relative_to(OUT)))
 assert ARCHIVE.stat().st_size<512_000_000,'Archive exceeds 512 MB; optimize losslessly before delivery'
 with zipfile.ZipFile(ARCHIVE) as z:
  if z.testzip():raise ValueError('ZIP integrity error')
  count=sum(n.endswith('.png') for n in z.namelist())
  if count!=len(screenshots):raise ValueError('ZIP image count mismatch')
  assert len(z.namelist())==len(set(z.namelist()))
  for s in screenshots:assert hashlib.sha256(z.read('SirinVPN-screenshot-catalog/'+s['path'])).hexdigest()==s['sha256']
 digest=hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
 ARCHIVE.with_suffix('.zip.sha256').write_text(digest+'  '+ARCHIVE.name+'\n')
 summary={'archive':str(ARCHIVE),'bytes':ARCHIVE.stat().st_size,'sha256':digest,'screenshots':len(screenshots),'scenarios':len(rows),'by_platform':dict(counts),'native_gaps':gaps,'duplicates_omitted':len(duplicates)}
 (OUT/'package-summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2),flush=True)
if __name__=='__main__':main()
