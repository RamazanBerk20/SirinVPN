#!/usr/bin/env python3
"""Real Polkit, NetworkManager and boot-supervisor checks in a disposable VM.

Launch with the same systemd user scope/resource limits as run-linux-acceptance.sh.
No host administrator access or host network changes are used.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

HELPER = "/usr/lib/sirinvpn/sirinvpn-helper"
FIXTURE = "/opt/sirin-startup-check.py"
STATE = Path("/var/lib/sirin-startup-fixture")
CONTROL = ["connect", "connect-managed", "disconnect", "pause-for-key-rotation", "resume",
           "pause-session", "reconnect-session", "switch-session", "apply-endpoint-checkpoint",
           "publish-endpoint-checkpoint", "disconnect-session"]


def run(*args, data=None, check=True):
    return subprocess.run(args, input=data, check=check, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30)


def save(path, contents, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)
    path.chmod(mode)


def local_authorization(allowed):
    for command in CONTROL:
        result = run("pkcheck", "--action-id", "org.sirinvpn.network." + command,
                     "--process", str(os.getpid()), check=False)
        assert (result.returncode == 0) == allowed, (command, result.returncode)
    for command in ("authorize-user", "install-system", "launch-application", "supervise", "--help"):
        result = run("pkexec", "--disable-internal-agent", HELPER, command, check=False)
        assert result.returncode in (126, 127), (command, result.returncode)
    if allowed:
        result = run("pkexec", "--disable-internal-agent", HELPER, "disconnect")
        assert json.loads(result.stdout)["state"] == "disconnected"
        result = run("pkexec", "--disable-internal-agent", HELPER, "disconnect", "install-system", check=False)
        assert result.returncode == 2, result.returncode  # clap rejects extra arguments
    print(json.dumps({"control_actions": len(CONTROL), "authorized": allowed}), flush=True)


def server():
    run("ip", "netns", "add", "boot-vps")
    run("ip", "link", "add", "boot-uplink", "type", "veth", "peer", "name", "boot-peer")
    run("ip", "link", "set", "boot-peer", "netns", "boot-vps")
    run("ip", "address", "add", "198.18.0.2/24", "dev", "boot-uplink")
    run("ip", "link", "set", "boot-uplink", "up")
    # Restricted QEMU networking intentionally omits the DHCP router option.
    # The private VPS is also the lab's usable underlay gateway after reboot.
    run("ip", "route", "add", "default", "via", "198.18.0.1", "dev", "boot-uplink", "metric", "500")
    prefix = ("ip", "netns", "exec", "boot-vps")
    run(*prefix, "ip", "link", "set", "lo", "up")
    run(*prefix, "ip", "address", "add", "198.18.0.1/24", "dev", "boot-peer")
    run(*prefix, "ip", "link", "set", "boot-peer", "up")
    run(*prefix, "ip", "link", "add", "wg-test", "type", "wireguard")
    request = json.loads((STATE / "request.json").read_text())
    public = run("wg", "pubkey", data=request["private_key"].encode()).stdout.decode().strip()
    run(*prefix, "wg", "set", "wg-test", "private-key", str(STATE / "server.key"),
        "listen-port", "51820", "peer", public, "allowed-ips", "10.77.0.2/32")
    run(*prefix, "ip", "address", "add", "10.77.0.1/24", "dev", "wg-test")
    run(*prefix, "ip", "link", "set", "wg-test", "up")


def connection_time(start):
    initiated = None
    while time.monotonic() - start < 5:
        if initiated is None and Path("/sys/class/net/sirinvpn0").exists():
            initiated = time.monotonic() - start
        status = json.loads(run(HELPER, "status").stdout)
        if status["state"] == "connected":
            assert initiated is not None and initiated < 1, initiated
            run("ping", "-n", "-I", "sirinvpn0", "-c", "1", "-W", "2", "10.77.0.1")
            return {"initiation_ms": round(initiated * 1000),
                    "connected_ms": round((time.monotonic() - start) * 1000)}
        time.sleep(0.025)
    raise AssertionError("connection did not become usable within five seconds")


def guest_checks(stage):
    assert Path("/etc/sirinvpn-acceptance-fixture").is_file()
    if stage.startswith("authorization-"):
        assert os.geteuid() != 0
        return local_authorization(stage == "authorization-allowed")
    assert os.geteuid() == 0
    if stage == "server":
        return server()
    if stage == "networkmanager":
        start = str(int(time.time()))
        for _ in range(4):
            run("ip", "link", "add", "sirinprobe0", "type", "wireguard")
            run("ip", "link", "set", "sirinprobe0", "alias", "SirinVPN isolated measurement", "up")
            time.sleep(0.15)
            state = run("nmcli", "-g", "GENERAL.STATE", "device", "show", "sirinprobe0").stdout.decode()
            assert state.startswith("10 "), state
            run("ip", "link", "delete", "sirinprobe0")
        log = run("journalctl", "-u", "NetworkManager", "--since", "@" + start, "--no-pager").stdout
        assert b"starting connection 'sirinprobe0'" not in log
        assert b"device (sirinprobe0): Activation: successful" not in log
        return {"probe_cycles": 4, "unmanaged": True, "activation_events": 0}
    if stage == "connections":
        STATE.mkdir(mode=0o700, exist_ok=True)
        private = run("wg", "genkey").stdout
        save(STATE / "server.key", private.decode())
        public = run("wg", "pubkey", data=private).stdout.decode().strip()
        request = {"schema_version": 7, "server_id": str(uuid.uuid4()),
                   "endpoint_host": "198.18.0.1", "endpoint_port": 51820,
                   "transport": "direct_udp", "private_key": run("wg", "genkey").stdout.decode().strip(),
                   "server_public_key": public, "client_address": "10.77.0.2",
                   "dns_address": "10.77.0.1", "mtu": 1420, "persistent_protection": False,
                   "policy": {"kill_switch": True, "automatic_reconnect": True, "connect_on_startup": True},
                   "routing": {"mode": "full_tunnel", "allow_lan": False, "included_routes": []}}
        save(STATE / "request.json", json.dumps(request))
        save("/etc/systemd/system/sirin-boot-vps.service", "[Unit]\nAfter=network.target\nBefore=sirinvpn-reconnect.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 " + FIXTURE + " --guest server\n[Install]\nWantedBy=multi-user.target\n", 0o644)
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", "sirin-boot-vps.service")
        start = time.monotonic()
        run(HELPER, "connect", data=json.dumps(request).encode())
        results = {"manual": connection_time(start)}
        desired = Path("/var/lib/sirinvpn/desired-connection.json").read_text()
        for delayed in (False, True):
            run(HELPER, "disconnect")
            routes = {}
            if delayed:
                for family in ("-4", "-6"):
                    routes[family] = []
                    for route in json.loads(run("ip", "-j", family, "route", "show", "default").stdout):
                        # RA output contains display-only lifetime/next-hop IDs.
                        # Restore the forwarding path, not that transient text.
                        entry = ["default", "dev", route["dev"]]
                        if "gateway" in route:
                            entry += ["via", route["gateway"]]
                        if "metric" in route:
                            entry += ["metric", str(route["metric"])]
                        routes[family].append(entry)
                    if routes[family]:
                        run("ip", family, "route", "flush", "table", "main", "default")
            save("/var/lib/sirinvpn/desired-connection.json", desired)
            run(HELPER, "restore-kill-switch")
            start = time.monotonic()
            run("systemctl", "start", "sirinvpn-reconnect.service")
            if delayed:
                time.sleep(1)
                state = json.loads(Path("/run/sirinvpn/client-state.json").read_text())
                assert state["initial_attempts"] == 0
                assert not Path("/sys/class/net/sirinvpn0").exists()
                run("nft", "list", "table", "inet", "sirinvpn_guard")
                start = time.monotonic()
                for family, entries in routes.items():
                    for route in entries:
                        run("ip", family, "route", "add", *route)
            results["delayed_network" if delayed else "native_startup"] = connection_time(start)
        run("systemctl", "enable", "sirinvpn-reconnect.service", "sirinvpn-killswitch.service")
        return results
    if stage == "after-boot":
        deadline = time.monotonic() + 10
        while True:
            status = json.loads(run(HELPER, "status").stdout)
            if status["state"] == "connected" or time.monotonic() >= deadline:
                break
            time.sleep(0.1)
        assert status["state"] == "connected", status["state"]
        run("ping", "-n", "-I", "sirinvpn0", "-c", "1", "-W", "2", "10.77.0.1")
        run(HELPER, "disconnect")
        return {"connected_without_desktop": True}
    raise ValueError(stage)


def host(args):
    from lab import Lab
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}
    with Lab(args.output) as lab:
        # Keep the readiness fixture deterministic: no independent IPv6 router
        # advertisements restoring a default route during the offline phase.
        # IPv6 protection remains covered by the separate packet matrix.
        guest = lab.guest(args.base, "startup", memory=1536, ipv6=False)
        (args.output / "active-fixtures.json").write_text(json.dumps({
            "client": {"agent": str(guest.agent_path), "fixture": guest.run_id}
        }) + "\n")
        guest.start()
        guest.put(Path(__file__).resolve(), "/home/sirin/check.py")
        guest.put(args.package.resolve(), "/home/sirin/sirinvpn.deb")
        with (args.output / "setup.log").open("wb") as log:
            guest.ssh(["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "sh", "-ec",
                       "apt-get -o Acquire::Retries=2 update\napt-get install -y --no-install-recommends qemu-guest-agent network-manager /home/sirin/sirinvpn.deb\ninstall -m 0755 /home/sirin/check.py " + FIXTURE + "\nsystemctl start qemu-guest-agent NetworkManager systemd-resolved\nmodprobe wireguard\n"],
                      timeout=600, stdout=log, stderr=log)

        def stage(name):
            print(name, flush=True)
            while True:
                result = guest.run(["python3", FIXTURE, "--guest", name], timeout=60, check=False)
                if not result.returncode:
                    break
                diagnostics = [result.stderr.decode()]
                for command in (
                    [HELPER, "status"], ["ip", "-4", "route", "show", "table", "main"],
                    ["ip", "-brief", "address"], ["ip", "netns", "list"],
                    ["systemctl", "status", "sirin-boot-vps", "sirinvpn-reconnect", "sirinvpn-killswitch", "--no-pager"],
                    ["journalctl", "-b", "-u", "sirin-boot-vps", "-u", "sirinvpn-reconnect", "-u", "NetworkManager", "--no-pager", "-n", "100"],
                ):
                    detail = guest.run(command, check=False)
                    diagnostics.append(detail.stdout.decode() + detail.stderr.decode())
                (args.output / (name + "-failure.log")).write_text("\n".join(diagnostics))
                print(f"{name} failed; diagnostics saved", flush=True)
                deadline = time.monotonic() + args.keep_failed_seconds
                retry = args.output / "retry-stage"
                while time.monotonic() < deadline and not retry.exists() and not (args.output / "stop-fixtures").exists():
                    time.sleep(1)
                if not retry.exists():
                    raise RuntimeError(result.stderr.decode()[-5000:])
                retry.unlink()
            results[name] = json.loads(result.stdout)
            print(results[name], flush=True)
            (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")

        def local(allowed, user="sirin"):
            guest.run(["systemctl", "stop", "getty@tty1.service"])
            mode = "authorization-allowed" if allowed else "authorization-denied"
            command = ["systemd-run", "--wait", "--collect", "--unit", "sirin-authorization-test",
                       "-p", "User=" + user, "-p", "PAMName=login", "-p", "TTYPath=/dev/tty1",
                       "-p", "StandardInput=tty-force", "-p", "TimeoutStartSec=40",
                       "python3", FIXTURE, "--guest", mode]
            result = guest.run(command, timeout=60, check=False)
            log = guest.run(["journalctl", "-u", "sirin-authorization-test", "--no-pager"]).stdout
            (args.output / "authorization.log").open("ab").write(log)
            assert result.returncode == 0, result.stderr.decode() + log.decode()[-4000:]

        stage("networkmanager")
        local(False)
        uid = guest.run(["id", "-u", "sirin"]).stdout.decode().strip()
        guest.run(["env", "PKEXEC_UID=" + uid, HELPER, "authorize-user"])
        time.sleep(1)  # allow Polkit's filesystem watcher to reload the new rule
        local(True)
        guest.run(["runuser", "-u", "sirin", "--", "python3", FIXTURE, "--guest", "authorization-denied"])
        guest.run(["useradd", "--create-home", "otheruser"])
        local(False, "otheruser")
        results["authorization"] = {"owner_local": True, "other_user_denied": True,
                                    "nonlocal_denied": True, "administration_denied": True}
        stage("connections")
        guest.stop()
        guest.start(network=False, via_agent=True)
        stage("after-boot")
        local(True)
        results["authorization"]["survived_reboot"] = True
        guest.run(["dpkg", "--purge", "sirin-vpn"], timeout=60)
        assert guest.run(["test", "-e", f"/etc/polkit-1/rules.d/49-sirinvpn-user-{uid}.rules"], check=False).returncode != 0
        results["purge_revoked_permission"] = True
        (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        (args.output / "active-fixtures.json").unlink(missing_ok=True)
    print("PASS: NetworkManager, Polkit, delayed network and real reboot", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--guest":
        result = guest_checks(sys.argv[2])
        if result is not None:
            print(json.dumps(result), flush=True)
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--base", type=Path, required=True)
        parser.add_argument("--package", type=Path, required=True)
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--keep-failed-seconds", type=int, choices=range(0, 1801), default=0, metavar="0..1800")
        host(parser.parse_args())
