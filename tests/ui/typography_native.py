"""Inspect local font faces in real WebKitGTK on an isolated virtual KWin output.

Synthetic metrics exercise UI rendering only. No connection or enforcement action
is invoked. Fractional scaling belongs to the disposable compositor, not KDE's
real output or font settings.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
from urllib.request import urlopen
from webkit_inspector import Inspector, wait_for

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--scale", default="1")
parser.add_argument("--output", type=Path, default=ROOT / ".cache/connection-policy")
parser.add_argument("--verify-scrolling", action="store_true")
args = parser.parse_args()
OUT = args.output
OUT.mkdir(parents=True, exist_ok=True)
port = 9242
with urlopen("http://127.0.0.1:1420/src/main.tsx") as response:
    source = response.read().decode()
modules = [re.search(pattern, source)[1] for pattern in [
    r'from "([^"]*/react.js[^"]*)"', r'from "([^"]*/react-dom_client.js[^"]*)"', r'import App from "([^"]*)"']]
with urlopen("http://127.0.0.1:1420" + modules[-1]) as response:
    api_module = re.search(r'from "([^"]*/api.ts[^"]*)"', response.read().decode())[1]
fixture = (Path(__file__).parent / "fixtures.js").read_text()
with tempfile.TemporaryDirectory(prefix="font-", dir=OUT) as directory, tempfile.TemporaryDirectory(prefix="sirin-wayland-") as runtime_dir:
    work = Path(directory)
    runtime = Path(runtime_dir)
    executable = work / "font-review"
    os.link(ROOT / "target/debug/sirinvpn-desktop", executable)
    env = {**os.environ, "XDG_CONFIG_HOME": str(work / "config"), "XDG_DATA_HOME": str(work / "data"),
           "XDG_CACHE_HOME": str(work / "cache"), "XDG_RUNTIME_DIR": str(runtime),
           "GDK_BACKEND": "wayland", "GIO_USE_VFS": "local", "GTK_USE_PORTAL": "0", "QT_QPA_PLATFORM": "offscreen", "KWIN_COMPOSE": "Q",
           "WEBKIT_INSPECTOR_HTTP_SERVER": f"127.0.0.1:{port}"}
    env.pop("WAYLAND_DISPLAY", None)
    env.pop("DISPLAY", None)
    launcher = work / "launch.py"
    launcher.write_text("import os,sys\nfrom pathlib import Path\nPath(sys.argv[1]).write_text(os.environ['DBUS_SESSION_BUS_ADDRESS'])\nos.execvp(sys.argv[2],sys.argv[2:])\n")
    bus_file = work / "private-bus"
    with (OUT / f"native-font-{args.scale}.log").open("w") as log:
        process = subprocess.Popen(["dbus-run-session", "--", "python3", str(launcher), str(bus_file), "kwin_wayland", "--virtual", "--width", "1600",
            "--height", "1100", "--scale", args.scale, "--socket", "sirin-font", "--no-lockscreen",
            "--no-global-shortcuts", "--no-kactivities", "--exit-with-session", str(executable)],
            env=env, stdout=log, stderr=log, start_new_session=True)
        inspector = None
        try:
            inspector = Inspector(port)
            private_env = {**env, "DBUS_SESSION_BUS_ADDRESS": bus_file.read_text()}
            assert private_env.get("DBUS_SESSION_BUS_ADDRESS") != os.environ.get("DBUS_SESSION_BUS_ADDRESS")
            private_env.update({"WAYLAND_DISPLAY":"sirin-font", "QT_QPA_PLATFORM":"wayland"})
            output = subprocess.check_output(["kscreen-doctor", "-o"], env=private_env, text=True)
            output = re.sub(r"\x1b\[[0-9;]*m", "", output)
            assert "Virtual" in output and "eDP" not in output, output
            output_name = re.search(r"Output:\s+\d+\s+(\S+)", output)[1]
            subprocess.run(["kscreen-doctor", f"output.{output_name}.scale.{args.scale}"], env=private_env, check=True, stdout=subprocess.DEVNULL)
            output = subprocess.check_output(["kscreen-doctor", "-o"], env=private_env, text=True)
            output = re.sub(r"\x1b\[[0-9;]*m", "", output)
            assert float(re.search(r"Scale:\s*([0-9.]+)", output)[1]) == float(args.scale), output
            (OUT / f"native-output-{args.scale}.txt").write_text(output)
            wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('#root > *'))"))
            inspector.evaluate('(function(){window.__sirinPlatform="desktop";window.__sirinScenario="connected";' +
                fixture.replace('window.__TAURI_INTERNALS__ =', 'window.__sirinReviewBridge =') + '})()')
            expression = """(async () => {
                const {api} = await import(location.origin + API_MODULE);
                for (const name of Object.keys(api)) api[name] = (...args) =>
                    window.__sirinReviewBridge.invoke(name.replace(/[A-Z]/g, l => '_' + l.toLowerCase()), args[0]);
                document.getElementById('root')?.remove();
                const root = document.createElement('div'); root.id = 'root'; document.body.append(root);
                const [react,renderer,app] = await Promise.all(MODULES.map(p => import(location.origin+p)));
                renderer.default.createRoot(root).render(react.default.createElement(app.default));
            })()""".replace("API_MODULE", json.dumps(api_module)).replace("MODULES", json.dumps(modules))
            promise = inspector.command("Runtime.evaluate", {"expression": expression, "returnByValue": False})
            inspector.command("Runtime.awaitPromise", {"promiseObjectId": promise["objectId"], "returnByValue": True})
            wait_for(lambda: inspector.evaluate("document.querySelectorAll('.metric').length === 8"))
            inspector.evaluate("""(() => {
              const probe = document.createElement('section'); probe.id='font-probe';
              probe.innerHTML='<h2>Türkçe · English</h2><p>İı Şş Ğğ Çç Öö Üü · Connection preferences</p>' +
                '<div class="metric"><strong class="metric-value">12.45 MB/s</strong></div>' +
                '<div class="metric"><strong class="metric-state">Waiting for measurement</strong></div>' +
                '<div class="metric"><strong class="metric-state">1 authorized</strong></div>' +
                '<div class="metric"><strong class="metric-state">Unavailable</strong></div>' +
                '<div class="metric"><strong class="metric-state">Not connected</strong></div>' +
                '<label>Device name <select><option>Ramazan’ın uzun adlı masaüstü bilgisayarı</option></select></label>' +
                '<p class="mono">2001:db8::1</p>';
              document.querySelector('.workspace').append(probe);
            })()""")
            for weight in [400, 500, 600]:
                promise = inspector.command("Runtime.evaluate", {"expression": f'document.fonts.load(\'{weight} 15px "Inter Variable"\', "İıŞşĞğÇçÖöÜü English").then(() => true)', "returnByValue": False})
                inspector.command("Runtime.awaitPromise", {"promiseObjectId": promise["objectId"], "returnByValue": True})
            result = inspector.evaluate("""(() => {
              const style = el => {const c=getComputedStyle(el);return {text:el.textContent, family:c.fontFamily,size:c.fontSize,
                weight:c.fontWeight,numeric:c.fontVariantNumeric,spacing:c.letterSpacing,zoom:c.zoom};};
              return {body:style(document.body), metrics:[...document.querySelectorAll('.metric strong')].map(style),
                select:style(document.querySelector('#font-probe select')), identifier:style(document.querySelector('#font-probe .mono')),
                faces:[...document.fonts].filter(f=>f.status==='loaded').map(f=>({family:f.family,weight:f.weight,range:f.unicodeRange})),
                dpr:devicePixelRatio, width:innerWidth, scrollWidth:document.documentElement.scrollWidth,
                titleBar:!!document.querySelector('.desktop-titlebar'), border:getComputedStyle(document.documentElement,"::after").borderWidth,
                remoteFonts:performance.getEntriesByType('resource').filter(e=>/woff/.test(e.name)&&!e.name.startsWith(location.origin)).map(e=>e.name)};
            })()""")
            assert "Inter Variable" in result["body"]["family"]
            assert result["body"]["zoom"] == "1"
            assert not result["remoteFonts"]
            for metric in result["metrics"]:
                assert "Inter Variable" in metric["family"], metric
                assert metric["size"] in ["25px", "15px"], metric
                assert metric["weight"] in ["500", "600"], metric
            assert "Inter Variable" in result["select"]["family"]
            assert "JetBrains Mono" in result["identifier"]["family"]
            assert result["scrollWidth"] <= result["width"]
            result["isolated_output_scale"] = args.scale
            (OUT / f"native-font-{args.scale}.json").write_text(json.dumps(result, indent=2))
            inspector.command("Page.enable", {})
            size = inspector.evaluate("({width:innerWidth,height:innerHeight})")
            shot = inspector.command("Page.snapshotRect", {"x":0,"y":0,**size,"coordinateSystem":"Viewport"})
            (OUT / f"native-font-{args.scale}.png").write_bytes(base64.b64decode(shot["dataURL"].split(",",1)[1]))
            inspector.evaluate("document.querySelector('#font-probe').scrollIntoView({block:'center'})")
            shot = inspector.command("Page.snapshotRect", {"x":0,"y":0,**size,"coordinateSystem":"Viewport"})
            (OUT / f"native-glyphs-{args.scale}.png").write_bytes(base64.b64decode(shot["dataURL"].split(",",1)[1]))
            inspector.evaluate("[...document.querySelectorAll('.primary-navigation button')].find(b=>b.textContent==='Settings').click()")
            wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('.settings-tabs'))"))
            inspector.evaluate("[...document.querySelectorAll('.settings-tabs button')].find(b=>b.textContent==='Connection').click()")
            wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('input[aria-label=\"Kill switch\"]'))"))
            controls = inspector.evaluate("[...document.querySelectorAll('.preference-row strong')].map(el=>({text:el.textContent,family:getComputedStyle(el).fontFamily,size:getComputedStyle(el).fontSize,weight:getComputedStyle(el).fontWeight}))")
            assert len(controls) == 4 and all('Inter Variable' in c['family'] and c['size']=='15px' for c in controls), controls
            (OUT / f"native-controls-{args.scale}.json").write_text(json.dumps(controls,indent=2))
            inspector.evaluate("window.scrollTo(0,0)")
            wait_for(lambda: inspector.evaluate("document.querySelector('.settings-tabs [aria-selected=true]')?.textContent === 'Connection'"))
            settled = inspector.command("Runtime.evaluate", {"expression": """(async () => {
                await new Promise(resolve => requestAnimationFrame(resolve));
                await Promise.allSettled(document.getAnimations().filter(a =>
                    a.effect.getTiming().iterations !== Infinity).map(a => a.finished));
                await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
                return true;
            })()""", "returnByValue": False})
            inspector.command("Runtime.awaitPromise", {"promiseObjectId": settled["objectId"], "returnByValue": True})
            shot = inspector.command("Page.snapshotRect", {"x":0,"y":0,**size,"coordinateSystem":"Viewport"})
            (OUT / f"native-settings-{args.scale}.png").write_bytes(base64.b64decode(shot["dataURL"].split(",",1)[1]))
            if args.verify_scrolling:
                inspector.evaluate("document.querySelector('#font-probe').remove(); [...document.querySelectorAll('.settings-tabs button')].find(b=>b.textContent==='Keys & recovery').click()")
                wait_for(lambda: inspector.evaluate("document.querySelector('.settings-tabs [aria-selected=true]')?.textContent==='Keys & recovery'"))
                geometry = """(() => {const r = el => {const b=el.getBoundingClientRect();return {x:b.x,y:b.y,height:b.height,width:b.width}};
                  return {sidebar:r(document.querySelector('.sidebar')),logo:r(document.querySelector('.sidebar .brand')),
                    title:r(document.querySelector('.desktop-titlebar')),height:innerHeight,outer:scrollY,
                    scroll:document.querySelector('.workspace').scrollTop}})()"""
                before = inspector.evaluate(geometry)
                inspector.evaluate("document.querySelector('.workspace').scrollTo(0,10000)")
                after = inspector.evaluate(geometry)
                assert after['scroll'] > 0, after
                assert before['sidebar'] == after['sidebar'] and before['logo'] == after['logo'] and before['title'] == after['title']
                assert after['outer'] == 0 and abs(after['sidebar']['y']+after['sidebar']['height']-after['height'])<1
                inspector.evaluate("document.querySelector('.settings-panel button:not(:disabled)').focus()")
                wait_for(lambda: inspector.evaluate("document.activeElement.getBoundingClientRect().top>=document.querySelector('.settings-tabs').getBoundingClientRect().bottom"))
                assert inspector.evaluate(geometry)['sidebar'] == before['sidebar']
                (OUT / f"native-recovery-scroll-{args.scale}.json").write_text(json.dumps({'before':before,'after':after,'focus_visible':True},indent=2))
                shot = inspector.command("Page.snapshotRect", {"x":0,"y":0,**size,"coordinateSystem":"Viewport"})
                (OUT / f"native-recovery-scroll-{args.scale}.png").write_bytes(base64.b64decode(shot["dataURL"].split(",",1)[1]))
                inspector.evaluate("[...document.querySelectorAll('.primary-navigation button')].find(b=>b.textContent==='Devices').click()")
                wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('.device-row-summary'))"))
                inspector.evaluate("document.querySelector('.device-row-summary').click(); document.querySelector('.device-row .action-menu > button').click()")
                wait_for(lambda: inspector.evaluate("document.querySelector('.device-row-details').inert"))
                assert inspector.evaluate("document.elementFromPoint(8,80).classList.contains('action-menu-backdrop')")
                inspector.evaluate("document.elementFromPoint(8,80).dispatchEvent(new PointerEvent('pointerdown',{bubbles:true}))")
                wait_for(lambda: inspector.evaluate("!document.querySelector('[role=menu]') && !document.querySelector('.device-row-details').inert"))
                (OUT / f"native-menu-{args.scale}.json").write_text(json.dumps({'backdrop_intercepts':True,'details_restored_after_dismissal':True}))
            print(json.dumps({"scale":args.scale, "device_pixel_ratio":result["dpr"], "metrics":len(result["metrics"]), "passed":True}), flush=True)
        finally:
            if inspector:
                inspector.close()
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=15)
            # Private portal services can leave dead FUSE mounts in their temporary
            # runtime directory. Unmount only this test's paths before deleting it.
            for relative in ["doc", "gvfs"]:
                subprocess.run(["fusermount3", "-uz", str(runtime / relative)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
