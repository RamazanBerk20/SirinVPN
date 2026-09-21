#!/usr/bin/env python3
"""Synthetic guest-only fixtures for packaged Linux acceptance."""

import argparse
import errno
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def command(*arguments, data=None):
    return subprocess.run(arguments, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout


def configure_link(address, mac):
    links = json.loads(command("ip", "-j", "link"))
    link = next(row["ifname"] for row in links if row.get("address") == mac)
    command("ip", "link", "set", link, "up")
    command("ip", "address", "replace", address + "/24", "dev", link)
    suffix = address.rsplit(".", 1)[1]
    command("ip", "-6", "address", "replace", f"fd42:789::{suffix}/64", "dev", link, "nodad")


def counters(reset=False):
    if reset:
        subprocess.run(["nft", "delete", "table", "inet", "sirin_acceptance"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rules = """table inet sirin_acceptance {
 counter dns { }
 counter ipv6 { }
 chain observe {
  type filter hook output priority 300; policy accept;
  oifname != { "lo", "sirinvpn0" } meta l4proto { tcp, udp } th dport 53 counter name dns
  ip6 daddr fd42:789::1 tcp dport 18081 counter name ipv6
 }
}
"""
        command("nft", "-f", "-", data=rules.encode())
    rows = json.loads(command("nft", "-j", "list", "table", "inet", "sirin_acceptance"))
    print(json.dumps({row["counter"]["name"]: row["counter"]["packets"]
                      for row in rows["nftables"] if "counter" in row}))


def direct_dns():
    # A synthetic name only; no browsing history or packet payload is captured.
    payload = b"\x73\x76\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    payload += b"\x0fsirin-acceptance\x07invalid\x00\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        try:
            client.sendto(payload, ("10.0.2.3", 53))
        except OSError as error:
            # A fail-closed unreachable route can reject the send itself. The
            # caller still checks the physical DNS counter for actual escape.
            if error.errno not in [errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH]:
                raise
            outcome = {"send": "kernel_denied", "errno": error.errno,
                       "reason": errno.errorcode[error.errno]}
        else:
            outcome = {"send": "accepted_by_socket"}
            try:
                client.recv(4096)
            except OSError:
                pass
    print(json.dumps(outcome))


def serve_ipv6(identity):
    class Server(http.server.HTTPServer):
        address_family = socket.AF_INET6

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"exit": "physical-v6", "fixture": identity}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    Server(("fd42:789::1", 18081), Handler).serve_forever()


def gui_close_inner():
    from Xlib import X, display, protocol
    connection = display.Display()
    with tempfile.TemporaryFile() as output:
        environment = {**os.environ, "GDK_BACKEND": "x11", "GTK_USE_PORTAL": "0",
                       "WEBKIT_DISABLE_DMABUF_RENDERER": "1", "LIBGL_ALWAYS_SOFTWARE": "1"}
        app = subprocess.Popen(["/usr/bin/sirinvpn-desktop"], env=environment,
                               stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 35
            window = None
            pid_atom = connection.intern_atom("_NET_WM_PID")
            while time.monotonic() < deadline and app.poll() is None:
                for candidate in connection.screen().root.query_tree().children:
                    owner = candidate.get_full_property(pid_atom, X.AnyPropertyType)
                    if owner is not None and owner.value[0] == app.pid and candidate.get_attributes().map_state == X.IsViewable:
                        window = candidate
                        break
                if window is not None:
                    break
                time.sleep(.2)
            if window is None:
                output.seek(0)
                raise RuntimeError("The packaged GUI did not open in Xvfb: " + output.read().decode(errors="replace")[-1600:])
            time.sleep(2)
            event = protocol.event.ClientMessage(window=window,
                client_type=connection.intern_atom("WM_PROTOCOLS"),
                data=(32, [connection.intern_atom("WM_DELETE_WINDOW"), X.CurrentTime, 0, 0, 0]))
            window.send_event(event, event_mask=0)
            connection.flush()
            assert app.wait(timeout=20) == 0, "the GUI did not close cleanly"
            print(json.dumps({"real_gui_window_opened": True, "normal_window_close": True,
                              "gui_process_exited": True, "display": "isolated Xvfb in client VM"}))
        finally:
            if app.poll() is None:
                app.terminate()
                try:
                    app.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    app.kill()
                    app.wait(timeout=5)
            connection.close()


def gui_close():
    result = subprocess.run(["xvfb-run", "-a", "--server-args=-screen 0 1280x800x24 -nolisten tcp",
                             "dbus-run-session", "--", "python3", __file__, "gui-close-inner"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=75)
    if result.returncode:
        raise RuntimeError("GUI close fixture failed: " + result.stderr.decode(errors="replace")[-1800:])
    print(result.stdout.decode().strip())


def main():
    if not Path("/etc/sirinvpn-acceptance-fixture").is_file():
        raise RuntimeError("This helper is only for an owned disposable VM")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["link", "counters", "reset-counters", "dns", "ipv6", "gui-close", "gui-close-inner"])
    parser.add_argument("values", nargs="*")
    args = parser.parse_args()
    if args.action == "link":
        configure_link(*args.values)
    elif args.action in ["counters", "reset-counters"]:
        counters(args.action == "reset-counters")
    elif args.action == "dns":
        direct_dns()
    elif args.action == "ipv6":
        serve_ipv6(*args.values)
    elif args.action == "gui-close":
        gui_close()
    elif args.action == "gui-close-inner":
        gui_close_inner()


if __name__ == "__main__":
    main()
