"""Real KDE Wayland window controls and native preference storage; no VPN mutations.

Uses a private D-Bus session and temporary XDG config. Requires a debug app,
Vite, WebKit inspector support and the user's existing Wayland compositor.
"""
import base64
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from webkit_inspector import Inspector, wait_for

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = Path(os.environ.get("SIRINVPN_UI_OUTPUT", ROOT / ".cache/refinement"))
OUTPUT.mkdir(parents=True, exist_ok=True)
PORT = 9240
checks = []

with tempfile.TemporaryDirectory(prefix="native-window-", dir=OUTPUT) as directory:
    work = Path(directory)
    executable = work / "SirinVPN window review"
    os.link(ROOT / "target/debug/sirinvpn-desktop", executable)
    bus = subprocess.check_output(["dbus-daemon", "--session", "--fork", "--print-address", "--print-pid"], text=True).splitlines()
    env = {**os.environ, "DBUS_SESSION_BUS_ADDRESS": bus[0], "XDG_CONFIG_HOME": str(work / "config"),
           "GDK_BACKEND": "wayland", "WEBKIT_INSPECTOR_HTTP_SERVER": f"127.0.0.1:{PORT}"}
    process = None
    inspector = None
    with (OUTPUT / "native-window.log").open("w") as log:
        try:
            process = subprocess.Popen([str(executable)], env=env, stdout=log, stderr=log, start_new_session=True)
            inspector = Inspector(PORT)
            wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('.desktop-titlebar'))"))
            native = lambda command: inspector.invoke("plugin:window|" + command, {"label": "main"})
            def compositor_state():
                return json.loads(subprocess.check_output(["/usr/bin/python3", str(Path(__file__).with_name("kwin_window_state.py")), str(process.pid)], text=True, timeout=10))
            assert native("is_decorated") is False
            assert inspector.evaluate("document.querySelector('.desktop-titlebar').getBoundingClientRect().height === 38")
            assert inspector.evaluate("Array.from(document.querySelectorAll('.titlebar-controls button')).every(el => { const a=el.getBoundingClientRect(), b=el.firstElementChild.getBoundingClientRect(); return Math.abs(a.x+a.width/2-b.x-b.width/2)<1 && Math.abs(a.y+a.height/2-b.y-b.height/2)<1 && a.width >= 44; })")
            checks.append("KDE Wayland: native decoration removed; 38px title bar with centered, accessible controls")
            inspector.evaluate("document.querySelector('[aria-label=\"Maximize window\"]').click()")
            wait_for(lambda: native("is_maximized"))
            wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('[aria-label=\"Restore window\"]'))"))
            assert inspector.evaluate("document.querySelectorAll('.window-resize-edge').length === 0")
            inspector.evaluate("document.querySelector('[aria-label=\"Restore window\"]').click()")
            wait_for(lambda: not native("is_maximized"))
            wait_for(lambda: inspector.evaluate("document.querySelectorAll('.window-resize-edge').length === 8"))
            checks.append("KDE Wayland: maximize, restore and resize-edge visibility follow native state")
            inspector.evaluate("document.querySelector('[aria-label=\"Minimize window\"]').click()")
            wait_for(lambda: compositor_state()["minimized"])
            subprocess.run([str(executable)], env=env, stdout=log, stderr=log, check=True, timeout=15)
            wait_for(lambda: not compositor_state()["minimized"] and native("is_visible"))
            checks.append("KDE Wayland: minimize and single-instance reopen retain the window")
            inspector.evaluate("Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === 'App settings').click()")
            wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('[aria-label=\"Close to tray\"]'))"))
            inspector.evaluate("document.querySelector('[aria-label=\"Close to tray\"]').click()")
            wait_for(lambda: inspector.invoke("get_app_preferences")["preferences"]["close_to_tray"])
            inspector.evaluate("document.querySelector('[aria-label=\"Maximize window\"]').click()")
            wait_for(lambda: native("is_maximized"))
            assert inspector.evaluate("Boolean(document.querySelector('[role=dialog]'))")
            inspector.evaluate("document.querySelector('[aria-label=\"Restore window\"]').click()")
            wait_for(lambda: not native("is_maximized"))
            checks.append("Window controls preserve an open settings dialog")
            inspector.evaluate("document.querySelector('.titlebar-close').click()")
            wait_for(lambda: not native("is_visible"))
            assert process.poll() is None
            subprocess.run([str(executable)], env=env, stdout=log, stderr=log, check=True, timeout=15)
            wait_for(lambda: native("is_visible"))
            checks.append("Custom close reaches native close-to-tray handling; reopen restores the same dialog")
            # Create a public synthetic profile only. No identity or usable endpoint is added.
            profile_id = "123e4567-e89b-42d3-a456-426614174000"
            profiles = work / "config/sirinvpn/servers.json"
            profiles.parent.mkdir(parents=True, exist_ok=True)
            profile = dict(schema_version=1, id=profile_id, name="Preference storage test", endpoint={"host":"192.0.2.10","wireguard_port":51820},
                           client_tunnel_address="10.77.0.2", server_tunnel_address="10.77.0.1", server_wireguard_public_key="synthetic",
                           pinned_server_certificate_pem="synthetic", client_management_certificate_pem="synthetic", identity_reference="synthetic", role="owner")
            profiles.write_text(json.dumps({"schema_version":1,"servers":[profile]}))
            original = inspector.invoke("get_connection_preferences", {"serverId":profile_id})
            selected = {**original, "transport":"direct_udp", "network_profile":"restricted", "policy":{"kill_switch":True,"automatic_reconnect":False,"connect_on_startup":False},
                        "routing":{"mode":"selected_routes","included_routes":["198.51.100.0/24"],"allow_lan":True}}
            assert inspector.invoke("set_connection_preferences", {"serverId":profile_id,"preferences":selected}) == selected
            preference_path = work / f"config/org.sirinvpn.client/connection-preferences/{profile_id}.json"
            assert preference_path.stat().st_mode & 0o777 == 0o600
            rejected = inspector.invoke("set_connection_preferences", {"serverId":"../outside","preferences":selected}, error=True)
            assert "invalid" in rejected
            invalid = {**selected,"routing":{"mode":"selected_routes","included_routes":["bad route"],"allow_lan":False}}
            inspector.invoke("set_connection_preferences", {"serverId":profile_id,"preferences":invalid}, error=True)
            assert inspector.invoke("get_connection_preferences", {"serverId":profile_id}) == selected
            checks.append("Native preferences are private, validate routes and IDs, and preserve the previous save on rejection")
            # Leave the temporary test app with normal close policy, then exercise the actual close button.
            inspector.evaluate("document.querySelector('[aria-label=\"Close to tray\"]').click()")
            wait_for(lambda: not inspector.invoke("get_app_preferences")["preferences"]["close_to_tray"])
            inspector.evaluate("setTimeout(() => document.querySelector('.titlebar-close').click(), 100)")
            process.wait(timeout=15)
            inspector.close(); inspector = None
            process = subprocess.Popen([str(executable)], env=env, stdout=log, stderr=log, start_new_session=True)
            inspector = Inspector(PORT)
            assert inspector.invoke("get_connection_preferences", {"serverId":profile_id}) == selected
            checks.append("Connection preferences survive an actual app exit and restart")
            wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('.desktop-titlebar'))"))
            inspector.command("Page.enable", {})
            size = inspector.evaluate("({width:innerWidth,height:innerHeight})")
            shot = inspector.command("Page.snapshotRect", {"x":0,"y":0,**size,"coordinateSystem":"Viewport"})
            (OUTPUT / "native-wayland-window.png").write_bytes(base64.b64decode(shot["dataURL"].split(",",1)[1]))
        finally:
            if inspector: inspector.close()
            if process and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=15)
            os.kill(int(bus[1]), signal.SIGTERM)
(OUTPUT / "native-window.json").write_text(json.dumps(checks, indent=2) + "\n")
print(json.dumps(checks, indent=2), flush=True)
