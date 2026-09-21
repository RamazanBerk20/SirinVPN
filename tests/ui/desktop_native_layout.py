"""Check the actual WebKitGTK renderer using synthetic VPS responses in an isolated app.

Requires a debug desktop build, Vite, websocket-client, and xdotool. The fixture
replaces the UI API methods before mounting the review UI; no real VPN or VPS is used.
The app runs on a private D-Bus session with a temporary configuration directory.
"""
import base64
import argparse
import json
import os
from pathlib import Path
import signal
import re
from urllib.request import urlopen
import subprocess
import tempfile
import time
from webkit_inspector import Inspector, wait_for

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, default=ROOT / ".cache/operational-ux")
OUTPUT = parser.parse_args().output.resolve()
(OUTPUT / "screenshots").mkdir(parents=True, exist_ok=True)
PORT = 9237
FIXTURE = (Path(__file__).parent / "fixtures.js").read_text()
checks = []
with urlopen("http://127.0.0.1:1420/src/main.tsx") as response:
    main_source = response.read().decode()
modules = [re.search(pattern, main_source)[1] for pattern in [
    r'from "([^"]*/react.js[^"]*)"', r'from "([^"]*/react-dom_client.js[^"]*)"', r'import App from "([^"]*)"']]
with urlopen("http://127.0.0.1:1420" + modules[-1]) as response:
    app_source = response.read().decode()
# HMR can attach a timestamp to imports; patch the exact API instance App uses.
api_module = re.search(r'from "([^"]*/api.ts[^"]*)"', app_source)[1]


with tempfile.TemporaryDirectory(prefix="native-layout-", dir=OUTPUT) as directory:
    work = Path(directory)
    executable = work / "SirinVPN layout review"
    os.link(ROOT / "target/debug/sirinvpn-desktop", executable)
    env = {**os.environ, "XDG_CONFIG_HOME": str(work / "config"), "GDK_BACKEND": "x11",
           "WEBKIT_INSPECTOR_HTTP_SERVER": f"127.0.0.1:{PORT}"}
    with (OUTPUT / "native-layout.log").open("w") as log:
        process = subprocess.Popen(["dbus-run-session", "--", str(executable)], env=env,
                                   stdout=log, stderr=log, start_new_session=True)
        inspector = None
        try:
            inspector = Inspector(PORT)
            wait_for(lambda: inspector.evaluate("Boolean(window.__TAURI_INTERNALS__)"))
            wait_for(lambda: inspector.evaluate("document.readyState === 'complete' && Boolean(document.querySelector('#root > *'))"))
            inspector.command("Page.enable", {})
            print("Native page: " + str(inspector.evaluate("location.href")), flush=True)
            permission = inspector.invoke("plugin:notification|is_permission_granted")
            assert permission is None or isinstance(permission, bool)
            blocked = inspector.invoke("plugin:notification|notify", {"options": {"title": "Unreachable notification"}}, error=True)
            assert "not allowed" in blocked
            checks.append("Notification initialization can read permission; unguarded plugin delivery remains blocked")
            def mount(scenario):
                # Tauri intentionally makes its native invoke function immutable.
                # Replace the UI API methods in this review process, then mount
                # the same app module with synthetic responses.
                source = 'window.__sirinPlatform="desktop"; window.__sirinScenario=' + json.dumps(scenario) + ';' + FIXTURE.replace('window.__TAURI_INTERNALS__ =', 'window.__sirinReviewBridge =')
                inspector.evaluate('(function(){' + source + '})()')
                expression = """(async () => {
                    const {api} = await import(location.origin + API_MODULE);
                    for (const name of Object.keys(api)) {
                        const command = name.replace(/[A-Z]/g, letter => '_' + letter.toLowerCase());
                        api[name] = (...args) => window.__sirinReviewBridge.invoke(command, args[0]);
                    }
                    document.getElementById('root')?.remove();
                    const root = document.createElement('div'); root.id = 'root'; document.body.append(root);
                    const [react, renderer, app] = await Promise.all(MODULES.map(path => import(location.origin + path)));
                    renderer.default.createRoot(root).render(react.default.createElement(app.default));
                    return true;
                })()"""
                expression = expression.replace("MODULES", json.dumps(modules)).replace("API_MODULE", json.dumps(api_module))
                promise = inspector.command("Runtime.evaluate", {"expression": expression, "returnByValue": False})
                inspector.command("Runtime.awaitPromise", {"promiseObjectId": promise["objectId"], "returnByValue": True})
                wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('.workspace, .onboarding-shell'))"))


            def select_page(label):
                inspector.evaluate("Array.from(document.querySelectorAll('.primary-navigation button')).find(button => button.querySelector('strong').textContent === " + json.dumps(label) + ").click()")
                wait_for(lambda: inspector.evaluate("document.querySelector('.primary-navigation button[aria-current] strong').textContent === " + json.dumps(label)))

            def screenshot(name):
                inspector.evaluate("window.scrollTo(0, 0)")
                wait_for(lambda: inspector.evaluate("document.getAnimations().every(animation => animation.playState !== 'running' || animation.effect.getTiming().iterations === Infinity)"))
                size = inspector.evaluate("({width:innerWidth,height:document.documentElement.scrollHeight})")
                result = inspector.command("Page.snapshotRect", {"x": 0, "y": 0, **size, "coordinateSystem": "Page"})
                (OUTPUT / "screenshots" / (name + ".png")).write_bytes(base64.b64decode(result["dataURL"].split(",", 1)[1]))

            def centered_icons():
                return inspector.evaluate("""Array.from(document.querySelectorAll('.metric > span, .server-glyph, .form-heading > span, .device-icon')).every(el => {
                    const icon = el.querySelector('svg'); if (!icon) return true;
                    const a = el.getBoundingClientRect(), b = icon.getBoundingClientRect();
                    return Math.abs(a.x+a.width/2-b.x-b.width/2)<1 && Math.abs(a.y+a.height/2-b.y-b.height/2)<1;
                })""")

            mount("connected")
            wait_for(lambda: inspector.evaluate("document.querySelectorAll('.metric').length === 8"))
            assert inspector.evaluate("!document.querySelector('.connection-options')")
            assert centered_icons()
            screenshot("linux-native-metrics")
            checks.append("WebKitGTK Home has centered boxed icons and no inline connection-settings panel")
            select_page("Devices")
            wait_for(lambda: inspector.evaluate("document.querySelectorAll('.device-row').length === 3"))
            assert inspector.evaluate("!document.querySelector('.port-forward-panel') && Boolean(document.querySelector('.invitation-empty'))")
            assert centered_icons()
            assert inspector.evaluate("""Array.from(document.querySelectorAll('.device-row')).every(row =>
                Math.abs(row.getBoundingClientRect().width - row.parentElement.getBoundingClientRect().width) < 1 && row.dataset.expanded === 'false')""")
            screenshot("linux-native-devices")
            inspector.evaluate("document.querySelectorAll('.device-row-summary')[1].click()")
            assert inspector.evaluate("document.querySelectorAll('.device-row')[1].dataset.expanded === 'true'")
            screenshot("linux-native-device-expanded")
            checks.append("Full-width native device rows expand; empty invitations are compact and forwarding is in Network settings")
            mount("onboarding")
            windows = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--name", "^SirinVPN$"], text=True).splitlines()
            # The private D-Bus session does not change the user's running app.
            window = next(window for window in windows if subprocess.check_output(["xdotool", "getwindowpid", window], text=True).strip() in subprocess.check_output(["pgrep", "-P", str(process.pid)], text=True).splitlines())
            subprocess.run(["xdotool", "windowsize", window, "958", "746"], check=True)
            wait_for(lambda: inspector.evaluate("innerWidth === 958"))
            assert inspector.evaluate("""(() => {
                const [a,b] = Array.from(document.querySelectorAll('.onboarding-actions > button'), el => el.getBoundingClientRect());
                return Math.abs(a.y-b.y)<1 && a.right+8<=b.left && document.documentElement.scrollWidth<=innerWidth;
            })()""")
            screenshot("linux-native-onboarding")
            checks.append("Onboarding actions share a baseline with no overlap at 958px")
            def geometry():
                return dict((key,int(value)) for key,value in (line.split("=",1) for line in subprocess.check_output(["xdotool","getwindowgeometry","--shell",window],text=True).splitlines()) if key in ["X","Y","WIDTH","HEIGHT"])
            pointer = dict(line.split("=",1) for line in subprocess.check_output(["xdotool","getmouselocation","--shell"],text=True).splitlines())
            try:
                subprocess.run(["xdotool","windowactivate","--sync",window,"windowmove",window,"80","80"],check=True)
                before = geometry()
                subprocess.run(["xdotool","mousemove","--window",window,"220","20","mousedown","1","sleep","0.2","mousemove_relative","--sync","75","45","sleep","0.2","mouseup","1"],check=True)
                wait_for(lambda: geometry()["X"] > before["X"] + 25)
                checks.append("Native pointer dragging moves the undecorated window using its title bar")
                subprocess.run(["xdotool","mousemove","--window",window,"220","20","click","--repeat","2","--delay","100","1"],check=True)
                wait_for(lambda: inspector.invoke("plugin:window|is_maximized",{"label":"main"}))
                wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('[aria-label=\"Restore window\"]'))"))
                inspector.evaluate("document.querySelector('[aria-label=\"Restore window\"]').focus()")
                subprocess.run(["xdotool","key","space"],check=True)
                wait_for(lambda: not inspector.invoke("plugin:window|is_maximized",{"label":"main"}))
                checks.append("Native double-click maximizes; the keyboard-operated Restore button restores")
                before = geometry()
                subprocess.run(["xdotool","mousemove","--window",window,str(before["WIDTH"]-2),str(before["HEIGHT"]-2),"mousedown","1","sleep","0.2","mousemove_relative","--sync","60","35","sleep","0.2","mouseup","1"],check=True)
                wait_for(lambda: geometry()["WIDTH"] > before["WIDTH"] + 25 and geometry()["HEIGHT"] > before["HEIGHT"] + 10)
                checks.append("Native pointer resize from the custom corner changes the actual window dimensions")
            finally:
                subprocess.run(["xdotool","mouseup","1","mousemove",pointer["X"],pointer["Y"]],check=True)
            print("PASS " + "; ".join(checks), flush=True)
            (OUTPUT / "native-layout.json").write_text(json.dumps(checks, indent=2) + "\n")
        except Exception:
            if inspector:
                print(inspector.evaluate("({url:location.href,ready:document.readyState,scenario:window.__sirinScenario,commands:window.__sirinCommands,mock:String(window.__TAURI_INTERNALS__?.invoke).includes('__sirinCommands'),root:document.getElementById('root')?.innerHTML.slice(0,350)})"), flush=True)
            raise
        finally:
            if inspector:
                inspector.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=20)
