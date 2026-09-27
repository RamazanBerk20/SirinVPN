#!/usr/bin/env python3
"""Synthetic guest-only fixtures for packaged Linux acceptance."""

import argparse
import errno
import http.server
import json
import os
from pathlib import Path
import re
import socket
import struct
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


def observe_dns(path="/run/sirin-acceptance-dns.jsonl"):
    """Bounded metadata from this synthetic VM only; never installed by the app."""
    assert re.fullmatch(r"/run/sirin-acceptance-dns(?:-[a-f0-9-]{36})?\.jsonl", path)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture:
        capture.settimeout(1)
        descriptor = os.open(path,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            deadline, count = time.monotonic() + 180, 0
            while time.monotonic() < deadline and count < 64:
                try:
                    packet, address = capture.recvfrom(65535)
                except socket.timeout:
                    continue
                if (address[2] != 4 or address[0] in ("lo", "sirinvpn0")
                        or len(packet) < 34 or packet[12:14] != b"\x08\x00"):
                    continue
                ip = packet[14:]
                offset = (ip[0] & 15) * 4
                if ip[9] not in (6, 17) or len(ip) < offset + 8:
                    continue
                if struct.unpack("!H", ip[offset+2:offset+4])[0] != 53:
                    continue
                question = None
                if ip[9] == 17:
                    payload, cursor, labels = ip[offset+8:], 12, []
                    while cursor < len(payload) and 0 < payload[cursor] < 64:
                        size = payload[cursor]
                        if cursor + size + 1 >= len(payload):
                            break
                        labels.append(payload[cursor+1:cursor+1+size].decode("ascii", "replace"))
                        cursor += size + 1
                    question = ".".join(labels)[:255]
                observed = time.time()
                tables = json.loads(command("nft", "-j", "list", "tables"))["nftables"]
                row = {"observed_unix": observed, "interface": address[0],
                       "protocol": ip[9], "destination": socket.inet_ntoa(ip[16:20]),
                       "question": question, "guard_present": any(
                           item.get("table", {}).get("name") == "sirinvpn_guard" for item in tables)}
                output.write(json.dumps(row) + "\n")
                output.flush()
                count += 1


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
    parser.add_argument("action", choices=["link", "counters", "reset-counters", "dns", "observe-dns", "ipv6", "gui-close", "gui-close-inner"])
    parser.add_argument("values", nargs="*")
    args = parser.parse_args()
    if args.action == "link":
        configure_link(*args.values)
    elif args.action in ["counters", "reset-counters"]:
        counters(args.action == "reset-counters")
    elif args.action == "dns":
        direct_dns()
    elif args.action == "observe-dns":
        observe_dns(*args.values)
    elif args.action == "ipv6":
        serve_ipv6(*args.values)
    elif args.action == "gui-close":
        gui_close()
    elif args.action == "gui-close-inner":
        gui_close_inner()


if __name__ == "__main__":
    main()
