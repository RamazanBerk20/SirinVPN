"""Read only the audit process's window state from KWin, then unload the script.

Run with the system Python (dbus-python and PyGObject), on the real session bus.
Wayland's xdg-shell does not send a minimized-state event back to the client.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
name = f"org.sirinvpn.WindowReview.p{os.getpid()}"
loop = GLib.MainLoop()
result = []

class Receiver(dbus.service.Object):
    @dbus.service.method("org.sirinvpn.WindowReview", in_signature="s", out_signature="")
    def receive(self, value):
        result.append(json.loads(value))
        loop.quit()

receiver = Receiver(dbus.service.BusName(name, bus), "/Result")
scripting = dbus.Interface(bus.get_object("org.kde.KWin", "/Scripting"), "org.kde.kwin.Scripting")
with tempfile.TemporaryDirectory(prefix="sirin-window-state-") as directory:
    path = Path(directory) / "state.js"
    path.write_text("const w = workspace.windowList().find(w => w.pid === " + str(int(sys.argv[1])) + ");\n" +
                    "callDBus(" + json.dumps(name) + ", '/Result', 'org.sirinvpn.WindowReview', 'receive', JSON.stringify(w ? {minimized:w.minimized, width:w.frameGeometry.width, height:w.frameGeometry.height} : null));")
    script_id = scripting.loadScript(str(path), name, signature="ss")
    try:
        script = dbus.Interface(bus.get_object("org.kde.KWin", f"/Scripting/Script{script_id}"), "org.kde.kwin.Script")
        script.run(reply_handler=lambda: None, error_handler=lambda error: loop.quit())
        GLib.timeout_add(5000, lambda: (loop.quit(), False)[1])
        loop.run()
        assert result and result[0] is not None, "KWin did not find the audit process's window"
        print(json.dumps(result[0]))
    finally:
        scripting.unloadScript(name)
