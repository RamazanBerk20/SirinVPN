"""Verify native Linux notification identity, local icon and acknowledged failures.

Requires Vite, a debug desktop build, Python websocket-client, and system Python
with dbus-python/PyGObject. The app uses private XDG directories and a private
session bus. One branded test notification is forwarded to the real desktop;
no user preferences, existing app instance, helper or VPN connection are changed.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote, urlparse


def bridge():
    import dbus
    import dbus.service
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib

    DBusGMainLoop(set_as_default=True)
    private_bus = dbus.bus.BusConnection(sys.argv[2])
    desktop_bus = dbus.bus.BusConnection(sys.argv[3])
    output = Path(sys.argv[4])
    remote = dbus.Interface(desktop_bus.get_object(
        "org.freedesktop.Notifications", "/org/freedesktop/Notifications"),
        "org.freedesktop.Notifications")
    name = dbus.service.BusName("org.freedesktop.Notifications", bus=private_bus)

    class Notifications(dbus.service.Object):
        @dbus.service.method("org.freedesktop.Notifications", out_signature="as")
        def GetCapabilities(self):
            return remote.GetCapabilities()

        @dbus.service.method("org.freedesktop.Notifications", out_signature="ssss")
        def GetServerInformation(self):
            return remote.GetServerInformation()

        @dbus.service.method("org.freedesktop.Notifications", in_signature="susssasa{sv}i", out_signature="u")
        def Notify(self, app, replaces, icon, title, body, actions, hints, timeout):
            if output.with_suffix(".fail").exists():
                raise dbus.exceptions.DBusException("Controlled notification failure",
                    name="org.freedesktop.Notifications.Error.Failed")
            result = remote.Notify(app, replaces, icon, title, body, actions, hints, timeout)
            output.write_text(json.dumps({"sender": str(app), "icon": str(icon),
                "title": str(title), "body": str(body),
                "desktop_entry": str(hints.get("desktop-entry", "")),
                "notification_id": int(result)}, indent=2) + "\n")
            return result

    service = Notifications(name, "/org/freedesktop/Notifications")
    output.with_suffix(".ready").touch()
    GLib.MainLoop().run()
    return service


if len(sys.argv) > 1 and sys.argv[1] == "--bridge":
    bridge()
    sys.exit(0)

from webkit_inspector import Inspector, wait_for

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".cache/notification-tests"
OUTPUT.mkdir(parents=True, exist_ok=True)
PORT = 9244
with tempfile.TemporaryDirectory(prefix="Şirin VPN ", dir=OUTPUT) as directory:
    work = Path(directory)
    bus = subprocess.check_output(["dbus-daemon", "--session", "--fork", "--print-address", "--print-pid"], text=True).splitlines()
    environment = {**os.environ, "DBUS_SESSION_BUS_ADDRESS": bus[0],
        "XDG_CONFIG_HOME": str(work / "config"), "XDG_DATA_HOME": str(work / "data"),
        "XDG_CACHE_HOME": str(work / "cache"), "GDK_BACKEND": "x11",
        "GIO_USE_VFS": "local", "GTK_USE_PORTAL": "0",
        "WEBKIT_INSPECTOR_HTTP_SERVER": f"127.0.0.1:{PORT}"}
    executable = work / "notification-test"
    os.link(ROOT / "target/debug/sirinvpn-desktop", executable)
    capture = work / "notification.json"
    process = relay = inspector = None
    with (OUTPUT / "native.log").open("w") as log:
        try:
            relay = subprocess.Popen(["/usr/bin/python3", __file__, "--bridge", bus[0],
                os.environ["DBUS_SESSION_BUS_ADDRESS"], str(capture)], stdout=log, stderr=log)
            wait_for(lambda: capture.with_suffix(".ready").exists())
            process = subprocess.Popen([str(executable)], env=environment, stdout=log, stderr=log)
            inspector = Inspector(PORT)
            before = inspector.invoke("get_app_preferences")["preferences"]
            assert not before["notifications"]
            assert "Enable notifications" in inspector.invoke("test_notification", error=True)
            assert not capture.exists()
            inspector.invoke("set_app_preferences", {"preferences": {**before, "notifications": True}})
            inspector.invoke("test_notification")
            notice = json.loads(capture.read_text())
            assert notice["sender"] == notice["title"] == "SirinVPN", notice
            assert notice["desktop_entry"] == "SirinVPN"
            icon_url = urlparse(notice["icon"])
            assert icon_url.scheme == "file" and not icon_url.netloc
            icon = Path(unquote(icon_url.path))
            assert icon.is_relative_to(work)
            assert icon.read_bytes() == (ROOT / "apps/desktop/src-tauri/icons/128x128.png").read_bytes()
            notice["bundled_icon_matches"] = True
            notice["unicode_cache_path_supported"] = True
            if "--capture" in sys.argv:
                time.sleep(0.8)  # let the desktop finish its notification reveal
                subprocess.run(["spectacle", "--background", "--nonotify", "--fullscreen",
                    "--output", str(OUTPUT / "desktop-notification.png")], check=True, timeout=20)
            capture.with_suffix(".fail").touch()
            assert "could not display" in inspector.invoke("test_notification", error=True)
            notice["delivery_failure_reported"] = True
            notice["disabled_preference_blocks_delivery"] = True
            inspector.invoke("set_app_preferences", {"preferences": before})
            (OUTPUT / "native-notification.json").write_text(json.dumps(notice, indent=2) + "\n")
            print("PASS native sender, desktop identity, bundled icon, Unicode path, preference guard and delivery failure", flush=True)
        finally:
            if inspector:
                inspector.close()
            for child in [process, relay]:
                if child and child.poll() is None:
                    child.terminate()
                    child.wait(timeout=15)
            os.kill(int(bus[1]), signal.SIGTERM)
