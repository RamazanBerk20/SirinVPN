#!/usr/bin/python3
"""Fake helper bound over the installed path in the native tray test's mount namespace.

Never imported or shipped by the application. It runs no network/system commands
and records only synthetic command names, IDs, and policy (never request keys).
"""
import json
import os
from pathlib import Path
import sys

state_file = Path(os.environ["SIRINVPN_TRAY_TEST_STATE"])
command = sys.argv[1]
if command == "version":
    print(16)
    sys.exit(0)
state = json.loads(state_file.read_text())
if command == "status":
    if state.get("status_unavailable"):
        sys.exit(1)
    print(json.dumps(state["status"]))
    sys.exit(0)
request = json.load(sys.stdin)
trace = {"command": command}
if command in ["connect", "switch-session"]:
    change = request["request"] if command == "switch-session" else request
    change.setdefault("routing", {"mode":"full_tunnel", "included_routes":[], "allow_lan":False})
    trace.update(server_id=change["server_id"], policy=change["policy"], routing=change["routing"])
    if command == "switch-session" and request["expected_server_id"] != state["status"]["server_id"]:
        sys.exit(1)
    state["status"].update(server_id=change["server_id"], policy=change["policy"], transport=change["transport"] if "transport" in change else "direct_udp",
        kill_switch_enabled=change["policy"]["kill_switch"], auto_reconnect_enabled=change["policy"]["automatic_reconnect"],
        connect_on_startup=change["policy"]["connect_on_startup"], routing_mode=change["routing"]["mode"],
        included_routes=change["routing"].get("included_routes", []), allow_lan=change["routing"]["allow_lan"],
        state="connected", waiting_for_user=False, recovery_in_progress=False,
        kill_switch_state="armed" if change["policy"]["kill_switch"] else "off", ipv6_blocked=change["policy"]["kill_switch"])
elif command in ["reconnect-session", "pause-session", "disconnect-session"]:
    trace["server_id"] = request
    if request != state["status"]["server_id"]:
        sys.exit(1)
    if command == "disconnect-session" and state.get("fail_disconnect"):
        with state_file.with_suffix(".calls").open("a") as stream:
            stream.write(json.dumps({**trace, "failed": True}) + "\n")
        sys.exit(1)
    if command == "disconnect-session":
        state["status"].update(state="disconnected", server_id=None, kill_switch_state="off", policy=None,
            kill_switch_enabled=False, auto_reconnect_enabled=False, waiting_for_user=False,
            recovery_in_progress=False, connect_on_startup=False, ipv6_blocked=False)
    else:
        paused = command == "pause-session"
        state["status"].update(state="degraded" if paused else "connected", waiting_for_user=paused,
            recovery_in_progress=False, kill_switch_state=("blocking" if paused else "armed") if state["status"]["kill_switch_enabled"] else "off")
else:
    raise AssertionError("Unexpected fixture mutation: " + command)
with state_file.with_suffix(".calls").open("a") as stream:
    stream.write(json.dumps(trace) + "\n")
temporary = state_file.with_suffix(".next")
temporary.write_text(json.dumps(state))
temporary.replace(state_file)
print(json.dumps(state["status"]))
