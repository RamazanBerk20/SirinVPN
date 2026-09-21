"""Capture the unchanged SirinVPN UI in the native desktop renderer.

Run with the catalog Vite server and isolated native shells described in README.
Every scenario uses fictional responses at the API boundary.
"""
from __future__ import annotations
import argparse, hashlib, json, math, os, re, subprocess, sys, time, traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webkit_inspector import Inspector
ROOT = Path(__file__).resolve().parents[3]
OUT = Path(os.environ.get('SIRINVPN_CATALOG_OUTPUT', ROOT / 'target/screenshot-catalog-2026-09-20'))

class Engine:
    def __init__(self, platform, browser=False):
        if platform != "desktop":
            raise ValueError("Only desktop catalog capture is supported.")
        self.platform, self.browser, self.playwright = platform, browser, None
        if platform == 'desktop' and not browser:
            self.inspector = Inspector(9238)
            self.inspector.evaluate('location.reload()')
            time.sleep(2)
            from webkit_inspector import wait_for
            wait_for(lambda:self.inspector.evaluate('Boolean(window.__catalog?.ready)'))
        else:
            from playwright.sync_api import sync_playwright
            self.playwright = sync_playwright().start()
            self.connection = self.playwright.chromium.launch(headless=True)
            self.page = self.connection.new_page(viewport={'width':1280,'height':900})
            self.page.goto(os.environ.get('SIRINVPN_CATALOG_URL','http://127.0.0.1:1422')+'/?platform=desktop')
            self.page.wait_for_function('window.__catalog?.ready')
    def evaluate(self, expression):
        if self.platform != 'desktop' or self.browser:
            return self.page.evaluate(expression)
        result = self.inspector.command('Runtime.evaluate', {'expression':'Promise.resolve().then(()=>('+expression+')).then(value=>({value}),error=>({error:String(error),stack:error.stack}))', 'returnByValue':False})
        value = self.inspector.command('Runtime.awaitPromise', {'promiseObjectId':result['objectId'], 'returnByValue':True})['value']
        if 'error' in value: raise RuntimeError(value)
        return value.get('value')
    def call(self, method, *args):
        return self.evaluate('window.__catalog.'+method+'('+','.join(json.dumps(a,ensure_ascii=False) for a in args)+')')
    def shot(self, path):
        path.parent.mkdir(parents=True,exist_ok=True)
        if self.browser: self.page.screenshot(path=str(path))
        else: subprocess.run(['import','-window','root',str(path)],env={**os.environ,'DISPLAY':':87'},check=True,timeout=20)
        return {'path':str(path.relative_to(OUT)), 'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    def capture(self, case, suffix=''):
        stem=case['id']+suffix
        folder=OUT/self.platform/case['family']
        self.call('settled')
        ports=self.call('scrollPorts')
        # Scroll each visible content region. Dialog backgrounds are kept still.
        for port in ports: self.call('scroll',port['index'],0)
        files=[self.shot(folder/(stem+'--01-top.png'))]
        for port in ports:
            if port['height'] < 60 or port['box']['width'] < 50: continue
            maximum=port['total']-port['height']
            count=1 if port['tag']=='TEXTAREA' else max(1,math.ceil(maximum/max(80,port['height']*0.72)))
            for step in range(1,count+1):
                top=round(maximum*step/count)
                self.call('scroll',port['index'],top)
                files.append(self.shot(folder/(stem+f'--{len(files)+1:02d}-scroll-{port["index"]+1}-{step}.png')))
            self.call('scroll',port['index'],0)
        return files
    def close(self):
        if self.platform=='desktop' and not self.browser: self.inspector.close()
        if self.playwright:
            if self.browser: self.connection.close()
            self.playwright.stop()

def run(engine, cases, resume=False, dry=False):
    OUT.mkdir(parents=True,exist_ok=True)
    log=OUT/(engine.platform+('-dry' if dry else '')+'-results.jsonl')
    existing={}
    if resume and log.exists():
        for line in log.read_text().splitlines():
            item=json.loads(line)
            existing[item['id']]=item
    for number,case in enumerate(cases,1):
        if existing.get(case['id'],{}).get('success'): continue
        result={**case,'platform':engine.platform,'success':False,'files':[],'data_source':'fictional API fixtures; unchanged production UI components','renderer':'Chromium preflight' if engine.browser else 'Native Tauri WebKitGTK'}
        try:
            if engine.browser: engine.page.wait_for_function('window.__catalog?.ready',timeout=10000)
            engine.call('mount',{**case.get('state',{}),'platform':engine.platform})
            snapshot=engine.call('actions',case.get('actions',[]))
            required=set(case.get('required_calls',[])) | set(case.get('state',{}).get('errors',{})) | set(case.get('state',{}).get('holds',[]))
            for action in case.get('actions',[]):
                patch=action.get('patch',{})
                required.update(patch.get('errors',{}));required.update(patch.get('holds',[]))
            exercised=set(engine.evaluate('window.__catalog.state.calls.map(call=>call.name)'))
            missing=required-exercised
            deadline=time.monotonic()+2
            while missing and time.monotonic()<deadline:
                time.sleep(.05)
                exercised=set(engine.evaluate('window.__catalog.state.calls.map(call=>call.name)'))
                missing=required-exercised
            engine.call('settled')
            snapshot=engine.call('inspect')
            if missing: raise RuntimeError('Fixture operation was not exercised: '+', '.join(sorted(missing)))
            fixture_errors=engine.evaluate('window.__catalog.state.fixtureErrors ?? []')
            if fixture_errors: raise RuntimeError('Contradictory fixture transition: '+str(fixture_errors))
            if snapshot['unknown']: raise RuntimeError('Missing fixtures: '+str(snapshot['unknown']))
            checks=case.get('assertions', []) + ([{'text':case['expect']}] if case.get('expect') else [])
            result['visible_assertions']=[engine.call('assertVisible', check) for check in checks]
            if len(snapshot['text']) < 12: raise RuntimeError('Empty app screen')
            result['observed']=snapshot
            if not dry:
                if checks:
                    result['files']=[engine.shot(OUT/engine.platform/case['family']/(case['id']+'--00-asserted.png'))]
                result['files']+=engine.capture(case)
            if case.get('expand') and engine.evaluate('Boolean(document.querySelector("details:not([open])"))'):
                engine.call('act',{'details':'open'})
                if not dry: result['files']+=engine.capture(case,'--expanded-details')
            result['success']=True
            print(f'{engine.platform} {number}/{len(cases)} OK {case["id"]} ({len(result["files"])} images)',flush=True)
        except Exception as error:
            result['error']=str(error)
            try: result['observed']=engine.call('inspect')
            except Exception: pass
            print(f'{engine.platform} {number}/{len(cases)} FAIL {case["id"]}: {error}',flush=True)
        with log.open('a') as f: f.write(json.dumps(result,ensure_ascii=False)+'\n')
    return log

def main():
    from scenarios import scenarios
    parser=argparse.ArgumentParser()
    parser.add_argument('platform',choices=['desktop'])
    parser.add_argument('--browser',action='store_true')
    parser.add_argument('--dry',action='store_true')
    parser.add_argument('--resume',action='store_true')
    parser.add_argument('--filter',default='')
    parser.add_argument('--output',type=Path,default=OUT)
    args=parser.parse_args()
    globals()["OUT"]=args.output.resolve()
    cases=[c for c in scenarios(args.platform) if re.search(args.filter,c['family']+'/'+c['id'])]
    if not cases: parser.error('No scenarios matched the filter')
    engine=Engine(args.platform,args.browser)
    try: log=run(engine,cases,args.resume,args.dry)
    finally: engine.close()
    latest={item['id']:item for line in log.read_text().splitlines() if (item:=json.loads(line))}
    return int(any(not latest.get(case['id'],{}).get('success') for case in cases))

if __name__=='__main__': raise SystemExit(main())
