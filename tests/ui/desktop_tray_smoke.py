"""Native GTK/DBus tray controls in a read-only bubblewrap mount namespace.

The real installed helper is shadowed with a deterministic fixture. No real
privilege escalation, host networking changes, or usable server identities.
Requires Vite, a debug desktop build, system Python dbus/GI and websocket-client.
"""
import base64
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
import threading
import time
import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
import gi
gi.require_version("Atspi", "2.0")
from gi.repository import GLib, Atspi
from webkit_inspector import Inspector, wait_for

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = Path(os.environ.get("SIRINVPN_TRAY_TEST_OUTPUT", str(ROOT / ".cache/tray-control")))
OUTPUT.mkdir(parents=True, exist_ok=True)
checks = []
PORT = 9246
DBusGMainLoop(set_as_default=True)

# UNIX-domain socket paths have a small fixed byte limit.
runtime_parent = ROOT / ".cache/tray-runtime"
runtime_parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="tray-", dir=runtime_parent) as directory:
    work = Path(directory)
    bus_data = subprocess.check_output(["dbus-daemon", "--session", "--fork", "--print-address", "--print-pid", "--address=unix:path=" + str(work / "bus")], text=True).splitlines()
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = bus_data[0]
    bus = dbus.bus.BusConnection(bus_data[0])
    name = dbus.service.BusName("org.kde.StatusNotifierWatcher", bus=bus)
    registered = []

    class Watcher(dbus.service.Object):
        @dbus.service.method("org.kde.StatusNotifierWatcher", in_signature="s", sender_keyword="sender")
        def RegisterStatusNotifierItem(self, service, sender=None):
            registered.append((str(sender) if service.startswith("/") else str(service), str(service) if service.startswith("/") else "/StatusNotifierItem"))

        @dbus.service.method("org.kde.StatusNotifierWatcher", in_signature="s")
        def RegisterStatusNotifierHost(self, service):
            pass

        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
        def Get(self, interface, prop):
            return {"IsStatusNotifierHostRegistered": dbus.Boolean(True), "ProtocolVersion": dbus.Int32(0), "RegisteredStatusNotifierItems": dbus.Array([], signature="s")}[prop]

        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
        def GetAll(self, interface):
            return {"IsStatusNotifierHostRegistered": dbus.Boolean(True), "ProtocolVersion": dbus.Int32(0), "RegisteredStatusNotifierItems": dbus.Array([], signature="s")}

    watcher = Watcher(name, "/StatusNotifierWatcher")
    loop = GLib.MainLoop()
    threading.Thread(target=loop.run, daemon=True).start()
    config = work / "config/sirinvpn"
    config.mkdir(parents=True)
    runtime = work / "runtime"
    runtime.mkdir(mode=0o700)
    ids = [f"123e4567-e89b-42d3-a456-4266141740{n:02}" for n in range(1, 9)]
    profiles = [dict(schema_version=1, id=id, name=f"Tray VPS {n+1}", favorite=n in [0, 1, 7],
        endpoint={"host":"192.0.2.10", "wireguard_port":51820}, client_tunnel_address="10.254.250.2", server_tunnel_address="10.254.250.1",
        server_wireguard_public_key=base64.b64encode(bytes([8])*32).decode(), pinned_server_certificate_pem="fixture",
        client_management_certificate_pem="fixture", identity_reference="tray-test", role="owner") for n, id in enumerate(ids)]
    (config / "servers.json").write_text(json.dumps({"schema_version":1,"servers":profiles}))
    (config / "secrets").mkdir(mode=0o700)
    (config / "secrets/tray-test.json").write_text(json.dumps({"wireguard_private_key":base64.b64encode(bytes([7])*32).decode(),"management_private_key_pem":"fixture"}))
    policy = dict(kill_switch=True, automatic_reconnect=True, connect_on_startup=False)
    status = dict(state="disconnected", server_id=None, interface_name="sirinvpn0", rx_bytes=0, tx_bytes=0,
        ipv6_blocked=False, ipv6_tunneled=False, kill_switch_enabled=False, auto_reconnect_enabled=False,
        transport_fallback_enabled=False, routing_mode="full_tunnel", included_routes=[], allow_lan=False,
        kill_switch_state="off", supervisor_status_known=True, connection_control_supported=True,
        independent_policy_supported=True, mtu_detection_supported=True, endpoint_updates_supported=True,
        waiting_for_user=False, startup_service_enabled=False, policy=None)
    state_file = work / "state.json"
    state_file.write_text(json.dumps({"status":status}))
    binary = work / "SirinVPN tray review"
    os.link(ROOT / "target/debug/sirinvpn-desktop", binary)
    helper = ROOT / "tests/ui/tray_helper_fixture.py"
    fake_bin = work / "bin"
    fake_bin.mkdir()
    (fake_bin / "pkexec").write_text('#!/usr/bin/python3\nimport os, sys\nassert sys.argv[1] == "/usr/lib/sirinvpn/sirinvpn-helper"\nos.execv(sys.argv[1], sys.argv[1:])\n')
    (fake_bin / "pkexec").chmod(0o755)
    env = {**os.environ, "XDG_CONFIG_HOME":str(work / "config"), "XDG_CACHE_HOME":str(work / "cache"), "XDG_DATA_HOME":str(work / "data"),
        "XDG_RUNTIME_DIR":str(runtime), "WAYLAND_DISPLAY":str(Path(os.environ["XDG_RUNTIME_DIR"]) / os.environ.get("WAYLAND_DISPLAY", "wayland-0")),
        "GDK_BACKEND":"wayland", "WEBKIT_INSPECTOR_HTTP_SERVER":f"127.0.0.1:{PORT}", "NO_AT_BRIDGE":"0",
        "SIRINVPN_TRAY_TEST_STATE":str(state_file), "SIRINVPN_HELPER_PATH":str(helper), "PATH":str(fake_bin)+":"+os.environ["PATH"]}
    a11y = dbus.Interface(bus.get_object("org.a11y.Bus", "/org/a11y/bus"), "org.a11y.Bus").GetAddress()
    os.environ["AT_SPI_BUS_ADDRESS"] = str(a11y)
    env["AT_SPI_BUS_ADDRESS"] = str(a11y)
    registry = subprocess.Popen(["/usr/lib/at-spi2-registryd"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    command = ["bwrap", "--ro-bind", "/", "/", "--bind", str(work), str(work), "--tmpfs", "/tmp", "--dev", "/dev",
        "--ro-bind", str(helper), "/usr/lib/sirinvpn/sirinvpn-helper", "--unshare-user", "--cap-drop", "ALL", "--die-with-parent", "--", str(binary)]
    process = inspector = None
    with (OUTPUT / "native-tray.log").open("w") as log:
        try:
            process = subprocess.Popen(command, env=env, stdout=log, stderr=log, start_new_session=True)
            inspector = Inspector(PORT)
            wait_for(lambda: registered)
            service, path = registered[0]
            props = dbus.Interface(bus.get_object(service, path), "org.freedesktop.DBus.Properties")
            menu_path = props.Get("org.kde.StatusNotifierItem", "Menu")
            menu = dbus.Interface(bus.get_object(service, menu_path), "com.canonical.dbusmenu")
            def rows():
                layout = menu.GetLayout(0, -1, dbus.Array([], signature="s"))[1]
                result = []
                def visit(row):
                    result.append({"id":int(row[0]), **{str(k):v for k,v in row[1].items()}})
                    for child in row[2]: visit(child)
                visit(layout)
                return result
            def find(label):
                return next((r for r in rows() if r.get("label") == label), None)
            def click(label):
                row = wait_for(lambda: (row if row and row.get("enabled", True) else None) if (row := find(label)) else None)
                assert row.get("enabled", True), row
                menu.Event(row["id"], "clicked", dbus.Int32(0), dbus.UInt32(0))
            def calls():
                file = state_file.with_suffix(".calls")
                return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []
            def set_state(**changes):
                data = json.loads(state_file.read_text())
                data["status"].update(changes)
                state_file.write_text(json.dumps(data))
            def press(label):
                def find_button(node, depth=0):
                    if depth > 12: return False
                    if node.get_name() == label and node.get_role() == Atspi.Role.PUSH_BUTTON:
                        node.get_action_iface().do_action(0)
                        return True
                    for i in range(node.get_child_count()):
                        if find_button(node.get_child_at_index(i), depth+1): return True
                    return False
                return wait_for(lambda: find_button(Atspi.get_desktop(0)))
            def save_icon(label):
                props_all = props.GetAll("org.kde.StatusNotifierItem")
                icon_name = str(props_all.get("IconName", ""))
                candidate = Path(icon_name) if icon_name.startswith("/") else Path(str(props_all.get("IconThemePath", ""))) / (icon_name + ".png")
                if candidate.is_file() and candidate.is_relative_to(work):
                    shutil.copyfile(candidate, OUTPUT / ("tray-icon-" + label + ".png"))
                (OUTPUT / ("tray-menu-" + label + ".json")).write_text(json.dumps(rows(), indent=2))
            wait_for(lambda: find("Connect to Tray VPS 1"))
            save_icon("disconnected")
            assert find("Disconnected").get("enabled", True) == True
            assert find("Kill switch: Off").get("enabled", True) == True
            click("Disconnected")
            wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('.connection-console'))"))
            assert not calls()
            checks.append("Readable status rows open Home without a connection mutation")
            assert len([r for r in rows() if str(r.get("label", "")).startswith("Tray VPS")]) <= 6
            click("Settings…")
            wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('[aria-label=\"Close to tray\"]'))"))
            prefs = inspector.invoke("get_app_preferences")["preferences"]
            inspector.invoke("set_app_preferences", {"preferences":{**prefs,"close_to_tray":True}})
            for id in ids[:2]:
                saved_policy = policy if id == ids[0] else {"kill_switch":False,"automatic_reconnect":False,"connect_on_startup":False}
                inspector.invoke("set_connection_preferences", {"serverId":id,"preferences":{"transport":"direct_udp","network_profile":"automatic","policy":saved_policy,"routing":{"mode":"full_tunnel","included_routes":[],"allow_lan":id != ids[0]}}})
            inspector.invoke("plugin:window|close", {"label":"main"})
            wait_for(lambda: not inspector.invoke("plugin:window|is_visible", {"label":"main"}))
            click("Connect to Tray VPS 1")
            wait_for(lambda: find("Connected to Tray VPS 1"))
            assert calls()[-1]["command"] == "connect"
            assert not inspector.invoke("plugin:window|is_visible", {"label":"main"})
            save_icon("connected")
            checks.append("Native menu connects using saved preferences while the window is hidden")
            inspector.invoke("desktop_selection", {"serverId":ids[1]})
            wait_for(lambda: find("Tray VPS 1").get("toggle-state") == 1)
            assert find("Tray VPS 2").get("toggle-state") == 0
            click("Reconnect")
            wait_for(lambda: calls()[-1]["command"] == "reconnect-session")
            assert calls()[-1]["server_id"] == ids[0]
            checks.append("Reconnect targets the active server, not the GUI selection; no Disconnect is sent")
            click("Tray VPS 2")
            press("Switch server")
            wait_for(lambda: find("Connected to Tray VPS 2"))
            assert calls()[-1]["command"] == "switch-session"
            assert calls()[-1]["policy"] == policy and not calls()[-1]["routing"]["allow_lan"]
            saved = inspector.invoke("get_connection_preferences", {"serverId":ids[1]})
            assert not saved["policy"]["kill_switch"] and saved["routing"]["allow_lan"]
            checks.append("Native server handoff confirms its consequences and preserves the active policy")
            set_state(state="connecting", recovery_in_progress=True, kill_switch_state="blocking")
            wait_for(lambda: find("Stop reconnecting…"))
            click("Stop reconnecting…")
            press("Stop attempts")
            wait_for(lambda: find("Resume connection"))
            assert find("Kill switch: Blocking traffic")
            save_icon("blocked")
            assert calls()[-1]["command"] == "pause-session"
            checks.append("Stopping retries retains the block and exposes Resume plus explicit Disconnect")
            click("Resume connection")
            wait_for(lambda: find("Connected to Tray VPS 2"))
            click("Diagnostics…")
            wait_for(lambda: inspector.evaluate("Boolean(document.querySelector('.diagnostics-dialog'))"))
            assert not any(c["command"] == "repair" for c in calls())
            checks.append("Diagnostics opens its local result workflow without a repair action")
            data = json.loads(state_file.read_text()); data["fail_disconnect"] = True; state_file.write_text(json.dumps(data))
            click("Disconnect and quit…")
            press("Disconnect and quit")
            wait_for(lambda: calls()[-1].get("failed"))
            assert process.poll() is None
            press("OK")
            assert inspector.invoke("plugin:window|is_visible", {"label":"main"})
            checks.append("Failed Disconnect and quit keeps the process open and displays the failure")
            data = json.loads(state_file.read_text()); data["fail_disconnect"] = False; state_file.write_text(json.dumps(data))
            wait_for(lambda: find("Disconnect and quit…").get("enabled", True))
            click("Disconnect and quit…")
            press("Disconnect and quit")
            process.wait(timeout=20)
            assert json.loads(state_file.read_text())["status"]["state"] == "disconnected"
            checks.append("Successful Disconnect and quit waits for acknowledged disconnection before exit")
            inspector.close(); inspector = None
            set_state(state="connected", server_id=ids[0], policy=policy, kill_switch_enabled=True,
                      auto_reconnect_enabled=True, kill_switch_state="armed", ipv6_blocked=True)
            registered.clear()
            process = subprocess.Popen(command, env=env, stdout=log, stderr=log, start_new_session=True)
            inspector = Inspector(PORT)
            wait_for(lambda: registered)
            service, path = registered[-1]
            props = dbus.Interface(bus.get_object(service, path), "org.freedesktop.DBus.Properties")
            menu_path = props.Get("org.kde.StatusNotifierItem", "Menu")
            menu = dbus.Interface(bus.get_object(service, menu_path), "com.canonical.dbusmenu")
            wait_for(lambda: find("Quit app (VPN keeps running)"))
            data = json.loads(state_file.read_text()); data["status_unavailable"] = True; state_file.write_text(json.dumps(data))
            wait_for(lambda: find("Connection status unavailable"))
            assert find("Kill switch: Status unknown") and find("Disconnect…") is None
            save_icon("attention")
            data["status_unavailable"] = False; state_file.write_text(json.dumps(data))
            wait_for(lambda: find("Quit app (VPN keeps running)"))
            checks.append("Helper status failure removes connection claims and uses the attention state")
            count = len(calls())
            click("Quit app (VPN keeps running)")
            process.wait(timeout=20)
            assert len(calls()) == count and json.loads(state_file.read_text())["status"]["server_id"] == ids[0]
            checks.append("Plain Quit exits the GUI without sending any connection mutation")
            (OUTPUT / "native-tray-calls.json").write_text(json.dumps(calls(), indent=2))
        finally:
            (OUTPUT / "native-tray-partial.json").write_text(json.dumps(checks, indent=2))
            if state_file.with_suffix(".calls").exists():
                (OUTPUT / "native-tray-calls.json").write_text(json.dumps(calls(), indent=2) + "\n")
            if inspector: inspector.close()
            if process and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=15)
            loop.quit()
            registry.terminate()
            registry.wait(timeout=10)
            os.kill(int(bus_data[1]), signal.SIGTERM)
(OUTPUT / "native-tray.json").write_text(json.dumps(checks, indent=2)+"\n")
print(json.dumps(checks, indent=2), flush=True)
