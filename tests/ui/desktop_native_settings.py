"""Exercise preferences, XDG startup registration and tray lifetime in the real Linux app.

Requires a debug build, running Vite, websocket-client, xdotool, gio and a
desktop session. Uses an isolated XDG config directory and never connects a VPN.
The WebKit inspector is enabled only on the test process's loopback interface.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from webkit_inspector import Inspector, wait_for

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".cache/settings"
OUTPUT.mkdir(parents=True, exist_ok=True)
PORT = 9236




with tempfile.TemporaryDirectory(prefix="desktop-native-", dir=OUTPUT) as directory:
    work = Path(directory)
    config = work / "config"
    config.mkdir()
    # Test Unicode, spaces, and literal field-code characters through the system launcher.
    executable = work / "Şirin VPN %f.AppImage"
    os.link(ROOT / "target/debug/sirinvpn-desktop", executable)
    environment = {**os.environ, "XDG_CONFIG_HOME": str(config), "GDK_BACKEND": "x11",
        "WEBKIT_INSPECTOR_HTTP_SERVER": f"127.0.0.1:{PORT}"}
    log = (OUTPUT / "desktop-native.log").open("w")
    process = None
    inspector = None
    results = []

    def launch():
        global process, inspector
        process = subprocess.Popen([str(executable)], env=environment, stdout=log, stderr=log)
        inspector = Inspector()

    def stop():
        global process, inspector
        if inspector:
            inspector.close()
            inspector = None
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=15)
        process = None

    def preference_path():
        return config / "org.sirinvpn.client/app-preferences.json"

    def visible():
        return inspector.invoke("plugin:window|is_visible", {"label": "main"})

    def save(preferences, error=False):
        return inspector.invoke("set_app_preferences", {"preferences": preferences}, error=error)

    try:
        launch()
        initial = inspector.invoke("get_app_preferences")
        assert initial["tray_available"] and initial["startup_available"], initial
        assert visible()
        original = initial["preferences"]
        assert original == dict(start_on_login=False, launch_minimized=False, close_to_tray=False, notifications=False, animations=True)
        assert not (config / "autostart").exists()
        assert "Enable notifications" in inspector.invoke("test_notification", error=True)
        results.append("Safe defaults and disabled-notification guard")
        print("PASS defaults", flush=True)

        selected = {**original, "start_on_login": True, "close_to_tray": True, "launch_minimized": True, "notifications": True, "animations": False}
        assert save(selected)["preferences"] == selected
        entry = config / "autostart/org.sirinvpn.client.desktop"
        assert entry.exists() and '" --autostart' in entry.read_text() and "%%f" in entry.read_text()
        subprocess.run(["desktop-file-validate", str(entry)], check=True)
        assert json.loads(preference_path().read_text())["preferences"] == selected
        results.append("Native preference persistence and quoted XDG startup entry")

        preference_path().parent.chmod(0o500)
        try:
            assert "could not be saved" in save({**selected, "start_on_login": False}, error=True)
        finally:
            preference_path().parent.chmod(0o700)
        assert inspector.invoke("get_app_preferences")["preferences"] == selected
        assert entry.exists()
        results.append("Startup rollback after a real filesystem write failure")

        notifications_log = work / "notifications.log"
        with notifications_log.open("w") as notification_output:
            monitor = subprocess.Popen(["dbus-monitor", "--session", "type='method_call',interface='org.freedesktop.Notifications',member='Notify',arg3='SirinVPN'"], stdout=notification_output, stderr=subprocess.DEVNULL)
            try:
                time.sleep(0.3)
                inspector.invoke("test_notification")
                wait_for(lambda: "Notifications are ready" in notifications_log.read_text())
            finally:
                monitor.terminate()
                monitor.wait(timeout=5)
        results.append("Native desktop notification delivered to the session notification service")

        window = subprocess.check_output(["xdotool", "search", "--pid", str(process.pid), "--name", "^SirinVPN$"], text=True).splitlines()[0]
        subprocess.run(["xdotool", "windowactivate", "--sync", window, "key", "alt+F4"], check=True)
        wait_for(lambda: not visible())
        assert process.poll() is None
        subprocess.run([str(executable)], env=environment, check=True, timeout=10)
        wait_for(visible)
        results.append("Close to tray keeps the process alive; a second launch restores the same window")

        stop()
        launch()
        assert not visible(), "Launch minimized with close-to-tray did not start hidden"
        assert inspector.invoke("get_app_preferences")["preferences"] == selected
        results.append("Preferences and minimized tray launch survive a process restart")

        save({**selected, "close_to_tray": False})
        stop()
        launch()
        assert inspector.invoke("plugin:window|is_minimized", {"label": "main"})
        results.append("Minimized launch without close-to-tray stays in the taskbar")

        # Exercise the exact desktop entry with the real launcher and its argument parser.
        stop()
        subprocess.run(["gio", "launch", str(entry)], env=environment, check=True, timeout=10)
        inspector = Inspector()
        save(original)
        assert not entry.exists()
        # Close the launched app normally after restoring window behavior.
        inspector.invoke("plugin:window|is_visible", {"label": "main"})
        results.append("System launcher accepts the quoted executable; disabling startup removes the entry")
    finally:
        stop()
        # Also clean up an app forked by gio, even if a later assertion fails.
        for process_directory in Path("/proc").iterdir():
            if process_directory.name.isdigit():
                try:
                    if (process_directory / "exe").resolve() == executable:
                        os.kill(int(process_directory.name), 15)
                except (OSError, ProcessLookupError):
                    pass
        log.close()
    (OUTPUT / "desktop-native-settings.json").write_text(json.dumps(results, indent=2) + "\n")
    print("PASS " + "; ".join(results))
