#!/usr/bin/env python3
"""Accept the packaged Linux CLI/helper against a fresh, independently installed VPS."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import time
import traceback
import uuid

from lab import Lab, ROOT, digest, free_port


FIXTURE = "/opt/sirin-acceptance.py"
HELPER = "/usr/lib/sirinvpn/sirinvpn-helper"
CLI = "/usr/bin/sirinvpn"
SERVER = "198.18.10.1"
USER_PREFIX = ["runuser", "-u", "sirin", "--", "env",
               "SSH_AUTH_SOCK=/home/sirin/acceptance-agent.sock"]


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.output = args.output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.logs = self.output / "logs"
        self.logs.mkdir(exist_ok=True)
        self.identity = str(uuid.uuid4())
        self.report = {
            "scope": "Packaged Linux CLI, Polkit helper and real WireGuard VPS in two Debian 13 VMs",
            "host_root": False, "host_privileged_networking": False,
            "limits": {"memory_bytes": 4 * 1024**3, "swap_bytes": 0,
                       "cpu_percent": 150, "server_memory_mib": 1024,
                       "client_memory_mib": 1536},
            "package_sha256": digest(args.package), "base_image_sha256": digest(args.base),
            "checks": [],
        }

    def save(self):
        (self.output / "linux-results.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def step(self, title, function):
        print(title, flush=True)
        started = time.monotonic()
        row = {"name": title, "passed": False}
        self.report["checks"].append(row)
        try:
            details = function()
            row["passed"] = True
            if details is not None:
                row["evidence"] = details
            print("PASS", flush=True)
            return details
        except Exception as error:
            row["error"] = f"{type(error).__name__}: {error}"[:2000]
            raise
        finally:
            row["seconds"] = round(time.monotonic() - started, 2)
            self.save()

    def run_guest(self, guest, arguments, *, data=None, timeout=60, check=True):
        result = guest.run(arguments, data=data, timeout=timeout, check=False)
        if check and result.returncode:
            # Commands never include credentials. Fixture SSH keys and profiles
            # stay in the disposable disks; only failure messages are retained.
            (self.logs / f"{guest.name}-last-error.log").write_bytes(result.stderr[-16000:])
            raise RuntimeError(f"{guest.name}: {arguments[0]} exited {result.returncode}: "
                               + result.stderr.decode(errors="replace")[-1800:])
        return result

    def cli(self, *arguments, timeout=180, check=True):
        result = self.run_guest(self.client, [*USER_PREFIX, CLI, "--json", *arguments],
                                timeout=timeout, check=check)
        if not check:
            return result
        return json.loads(result.stdout) if result.stdout.strip() else None

    def local(self):
        return json.loads(self.run_guest(self.client, [*USER_PREFIX, HELPER, "status"]).stdout)

    def request(self, *, host="10.0.2.100", port=18080, timeout=4):
        label = f"[{host}]" if ":" in host else host
        result = self.run_guest(self.client,
                                [*USER_PREFIX, "curl", "--noproxy", "*", "--silent",
                                 "--show-error", "--fail", "--max-time", str(timeout),
                                 f"http://{label}:{port}/"], check=False, timeout=timeout + 5)
        if result.returncode:
            return None
        value = json.loads(result.stdout)
        assert value.get("fixture") == self.identity, "unexpected canary identity"
        return value["exit"]

    def counter(self, reset=False):
        action = "reset-counters" if reset else "counters"
        return json.loads(self.run_guest(self.client, ["python3", FIXTURE, action]).stdout)

    def wait_connected(self, transport=None, timeout=70):
        deadline = time.monotonic() + timeout
        last = {}
        while time.monotonic() < deadline:
            last = self.local()
            if (last.get("state") == "connected"
                    and (transport is None or last.get("transport") == transport)):
                actual = self.request(timeout=3)
                assert actual != "direct", "VPN traffic escaped through the physical exit"
                if actual == "vps":
                    return last
            time.sleep(1)
        raise AssertionError(f"VPN did not recover: {last.get('state')}, {last.get('transport')}")

    def prepare_guest(self, guest, address, mac, client=False):
        guest.start()
        guest.put(ROOT / "tests/vm/acceptance_guest.py", "/home/sirin/acceptance-guest.py")
        if client:
            guest.put(self.args.package.resolve(), "/home/sirin/sirinvpn.deb")
        packages = "qemu-guest-agent python3 curl iproute2 nftables kmod"
        if client:
            packages += " xvfb xauth python3-xlib dbus-x11 /home/sirin/sirinvpn.deb"
        with (self.logs / f"{guest.name}-setup.log").open("wb") as log:
            guest.ssh(["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "sh", "-ec",
                       "apt-get -o Acquire::Retries=2 update\n"
                       f"apt-get install -y --no-install-recommends {packages}\n"
                       "install -m 0755 /home/sirin/acceptance-guest.py /opt/sirin-acceptance.py\n"
                       "systemctl start qemu-guest-agent\nmodprobe wireguard\nmodprobe nf_tables\n"],
                      timeout=600, stdout=log, stderr=log)
        assert guest.run(["id", "-u"]).stdout.strip() == b"0"
        unit = ("[Unit]\nDescription=Disposable acceptance private link\n"
                "After=network-pre.target\nBefore=network-online.target sirinvpn-reconnect.service\n"
                "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                f"ExecStart=/usr/bin/python3 {FIXTURE} link {address} {mac}\n"
                "[Install]\nWantedBy=multi-user.target\n")
        guest.run(["tee", "/etc/systemd/system/sirin-acceptance-link.service"], data=unit.encode())
        guest.run(["systemctl", "daemon-reload"])
        guest.run(["systemctl", "enable", "--now", "sirin-acceptance-link.service"])
        if client:
            rule = """polkit.addRule(function(action, subject) {
 // This isolated network fixture deliberately authorizes its non-local test
 // session. Account/session authorization is tested in startup_authorization.py.
 if (subject.user == "sirin" &&
     (action.id == "org.sirinvpn.network" ||
      action.id.indexOf("org.sirinvpn.network.") == 0 ||
      action.id == "org.freedesktop.policykit.exec") &&
     action.lookup("program") == "/usr/lib/sirinvpn/sirinvpn-helper") {
  return polkit.Result.YES;
 }
});
"""
            guest.run(["tee", "/etc/polkit-1/rules.d/00-sirin-acceptance.rules"], data=rule.encode())
            guest.run(["chmod", "0644", "/etc/polkit-1/rules.d/00-sirin-acceptance.rules"])
            guest.run(["systemctl", "restart", "polkit"])
            guest.run(["systemctl", "start", "systemd-resolved"])
            assert self.cli("status")["local"]["state"] == "disconnected"
            guest.run([*USER_PREFIX, "pkexec", "--disable-internal-agent", HELPER, "status"])
        return {"kernel": guest.run(["uname", "-r"]).stdout.decode().strip()}

    def provision(self):
        self.client.put(self.server.key, "/home/sirin/vps-fixture-key")
        self.client.run(["chmod", "0600", "/home/sirin/vps-fixture-key"])
        self.client.run([*USER_PREFIX, "ssh-agent", "-a", "/home/sirin/acceptance-agent.sock"])
        self.client.run([*USER_PREFIX, "ssh-add", "/home/sirin/vps-fixture-key"])
        fingerprint = subprocess.run(
            ["ssh-keygen", "-lf", str(self.server.directory / "guest-host-key.pub"), "-E", "sha256"],
            stdout=subprocess.PIPE, check=True).stdout.decode().split()[1]
        self.ssh_options = ["--username", "sirin", "--ssh-agent", "--host-key", fingerprint,
                            "--passwordless-sudo"]
        profile = self.cli("server", "add", "--name", "Acceptance", "--host", SERVER,
                           *self.ssh_options, "--server-binary", "/usr/lib/sirinvpn/sirinvpn-server",
                           "--private-dns-record", "probe.test=10.0.2.100",
                           "--private-dns-record", "dns-failure.test=10.0.2.100", timeout=600)
        self.server_id = profile["id"]
        assert not profile.get("ipv6_tunnel_enabled", False), "the fixture needs an IPv4-only profile"
        return {"profile_created": True, "server_id": self.server_id}

    def release_guard_regression(self):
        executable = "/home/sirin/installer-regression"
        self.server.put(self.args.installer_tests.resolve(), executable)
        self.server.run(["chown", "root:root", executable])
        self.server.run(["chmod", "0700", executable])
        result = self.run_guest(self.server, ["env", "SIRINVPN_POLICY_ISOLATED=1", executable,
                                "--ignored", "--exact",
                                "release_guard::tests::isolated_root_staging_rejects_policy_races_and_artifact_swaps_before_execution",
                                "--test-threads=1", "--nocapture"])
        assert b"1 passed; 0 failed" in result.stdout
        return {"test_executable_sha256": digest(self.args.installer_tests),
                "absent_empty_oversized_symlink_and_race_checks": "passed"}

    def baseline(self):
        self.server.run(["systemd-run", "--unit=sirin-acceptance-v6", "--collect",
                         "python3", FIXTURE, "ipv6", self.identity])
        assert self.request() == "direct"
        self.counter(reset=True)
        assert self.request(host="fd42:789::1", port=18081) == "physical-v6"
        self.client.run([*USER_PREFIX, "python3", FIXTURE, "dns"])
        counts = self.counter()
        assert counts["dns"] > 0 and counts["ipv6"] > 0, counts
        self.counter(reset=True)
        return {"physical_ipv4_exit": "direct", "physical_ipv6_exit": "physical-v6",
                "baseline_counters": counts}

    def connected_proof(self, transport):
        self.cli("connect", self.server_id, "--transport", transport,
                 "--kill-switch", "--automatic-reconnect")
        expected = {"direct": "direct_udp", "obfuscated": "obfuscated_udp",
                    "tls": "tls_like", "tcp": "tcp_fallback"}[transport]
        local = self.wait_connected(expected)
        assert local["kill_switch_state"] == "armed", local["kill_switch_state"]
        assert local["ipv6_blocked"] and not local["ipv6_tunneled"]
        combined = self.cli("status")
        assert combined["server"] and combined["server"]["interface_up"]
        assert self.request(host="probe.test") == "vps", "native DNS did not use the VPS record"
        self.client.run([*USER_PREFIX, "python3", FIXTURE, "dns"])
        assert self.request(host="fd42:789::1", port=18081) is None, "physical IPv6 escaped"
        assert self.counter() == {"dns": 0, "ipv6": 0}, self.counter()
        assert local["rx_bytes"] > 0 and local["tx_bytes"] > 0
        return {"transport": expected, "exit": "vps", "dns_exit": "vps",
                "kill_switch": local["kill_switch_state"], "physical_leak_counters": self.counter()}

    def public_internet(self):
        result = self.run_guest(self.client,
                                [*USER_PREFIX, "curl", "--noproxy", "*", "--silent",
                                 "--show-error", "--fail", "--max-time", "25",
                                 "--output", "/dev/null", "--write-out", "%{http_code}",
                                 "https://example.org/"], timeout=30)
        assert result.stdout == b"200", result.stdout.decode()
        return {"https_status": 200, "physical_leak_counters": self.counter()}

    def gui_close(self):
        before = self.local()
        assert before["state"] == "connected"
        result = self.run_guest(self.client, [*USER_PREFIX, "python3", FIXTURE, "gui-close"], timeout=80)
        evidence = json.loads(result.stdout)
        after = self.local()
        assert after["state"] == "connected" and after["server_id"] == before["server_id"]
        assert after["kill_switch_state"] == "armed"
        assert self.request() == "vps", "closing the real GUI changed the tunnel exit"
        return {**evidence, "vpn_remained_connected": True, "kill_switch": after["kill_switch_state"], "exit": "vps"}

    def failure_policy(self, kill_switch, reconnect):
        options = (["--kill-switch"] if kill_switch else []) + (["--automatic-reconnect"] if reconnect else [])
        self.cli("connect", self.server_id, "--transport", "direct", *options)
        self.wait_connected("direct_udp")
        self.block_server("all")
        evidence = {"kill_switch": kill_switch, "automatic_reconnect": reconnect,
                    "fault": "VPS ports blocked and the guest tunnel interface removed"}
        try:
            # Force an observable kernel interruption without waiting for a stale
            # handshake timeout. Only the disposable client's tunnel is removed.
            self.client.run(["ip", "link", "delete", "sirinvpn0"])
            deadline = time.monotonic() + 50
            while time.monotonic() < deadline:
                local = self.local()
                present = self.client.run(["ip", "link", "show", "sirinvpn0"], check=False).returncode == 0
                if reconnect and present and local["state"] != "connected" and not local.get("waiting_for_user"):
                    break
                if not reconnect and local.get("waiting_for_user") and not present:
                    break
                time.sleep(1)
            else:
                raise AssertionError("The supervisor did not apply the selected interruption policy")
            assert local["kill_switch_enabled"] == kill_switch
            assert local["auto_reconnect_enabled"] == reconnect
            assert local.get("waiting_for_user", False) == (not reconnect)
            self.counter(reset=True)
            exit_during_fault = self.request(timeout=2)
            if kill_switch:
                assert exit_during_fault is None, "the active kill switch allowed traffic during interruption"
                dns_probe = self.run_guest(self.client, [*USER_PREFIX, "python3", FIXTURE, "dns"])
                evidence["dns_probe"] = json.loads(dns_probe.stdout)
                assert self.request(host="fd42:789::1", port=18081, timeout=2) is None
                assert self.counter() == {"dns": 0, "ipv6": 0}, self.counter()
                if reconnect:
                    self.client.run(["systemctl", "restart", "sirinvpn-reconnect.service"])
                    for _ in range(3):
                        assert self.request(timeout=1) is None, "restarting the helper supervisor released protection"
                    evidence["helper_restart_preserved_block"] = True
            elif not reconnect:
                assert exit_during_fault == "direct", "disabled reconnect and kill switch retained a traffic block"
            evidence.update({"exit_during_fault": exit_during_fault,
                             "waiting_for_user": local.get("waiting_for_user", False),
                             "physical_counters": self.counter()})
        finally:
            self.block_server(None)
        if not reconnect:
            time.sleep(3)
            assert self.local().get("waiting_for_user"), "automatic recovery ran despite being disabled"
            self.cli("resume", self.server_id)
        self.wait_connected("direct_udp", timeout=100)
        evidence["recovered_after"] = "network restored" if reconnect else "explicit Resume"
        self.clean_disconnect()
        return evidence

    def dns_failure(self):
        self.server.run(["systemctl", "stop", "unbound"])
        try:
            self.client.run(["resolvectl", "flush-caches"])
            assert self.request(host="dns-failure.test", timeout=6) is None
            assert self.request() == "vps", "the numeric tunnel path failed with the resolver"
            assert self.counter() == {"dns": 0, "ipv6": 0}, self.counter()
        finally:
            self.server.run(["systemctl", "start", "unbound", "sirinvpn-server"])
        self.client.run(["resolvectl", "flush-caches"])
        assert self.request(host="dns-failure.test", timeout=8) == "vps"
        return {"numeric_path_survived": True, "resolver_recovered": True,
                "physical_leak_counters": self.counter()}

    def clean_disconnect(self):
        local = self.cli("disconnect")
        assert local["state"] == "disconnected"
        assert self.request() == "direct", "disconnect did not restore physical routing"
        assert self.request(host="fd42:789::1", port=18081) == "physical-v6"
        tables = json.loads(self.client.run(["nft", "-j", "list", "tables"]).stdout)["nftables"]
        assert not any(row.get("table", {}).get("name", "").startswith("sirinvpn") for row in tables)
        self.assert_routes_removed()
        assert b"sirinvpn0" not in self.client.run(["resolvectl", "status"]).stdout
        startup = self.client.run(["systemctl", "is-enabled", "sirinvpn-reconnect.service"], check=False)
        assert startup.returncode != 0, "manual Disconnect left startup connection enabled"
        self.counter(reset=True)
        return {"physical_routes_restored": True, "owned_firewall_removed": True,
                "owned_dns_link_removed": True, "startup_connection_disabled": True}

    def assert_routes_removed(self):
        for family in ["-4", "-6"]:
            routes = json.loads(self.client.run(["ip", family, "-j", "route", "show", "table", "all"]).stdout)
            assert not any(row.get("table") in [51820, "51820"]
                           or row.get("dev") == "sirinvpn0" for row in routes), routes
        self.client.run(["test", "!", "-e", "/var/lib/sirinvpn/desired-connection.json"])

    def relay_crash(self):
        self.counter(reset=True)
        self.client.run(["systemctl", "kill", "--kill-whom=main", "--signal=KILL",
                         "sirinvpn-transport.service"])
        for _ in range(3):
            assert self.request(timeout=1) != "direct", "transport crash leaked through the ISP"
        local = self.wait_connected("tls_like")
        assert self.counter() == {"dns": 0, "ipv6": 0}, self.counter()
        return {"transport": local["transport"], "exit": "vps"}

    def block_server(self, mode):
        self.server.run(["nft", "delete", "table", "inet", "sirin_acceptance_fault"], check=False)
        if mode is None:
            return
        protocol = "meta l4proto { tcp, udp } th dport { 443, 51820 }" if mode == "all" else \
            "udp dport { 443, 51820 }"
        rules = ("table inet sirin_acceptance_fault {\n chain input {\n"
                 "  type filter hook input priority -100; policy accept;\n"
                 f"  ip saddr 198.18.10.2 {protocol} counter drop\n"
                 " }\n}\n")
        self.server.run(["nft", "-f", "-"], data=rules.encode())

    def automatic_fallback(self):
        self.block_server("udp")
        try:
            self.cli("connect", self.server_id, "--transport", "automatic", "--persistent",
                     "--network-profile", "normal",
                     timeout=240)
            local = self.wait_connected(timeout=100)
            assert local["transport"] in ["tls_like", "tcp_fallback"], local["transport"]
            assert local["auto_reconnect_enabled"] and local["connect_on_startup"]
            assert self.request(host="probe.test") == "vps"
            assert self.counter() == {"dns": 0, "ipv6": 0}, self.counter()
            rules = json.loads(self.server.run(["nft", "-j", "list", "table", "inet",
                                               "sirin_acceptance_fault"]).stdout)["nftables"]
            drops = sum(expression["counter"]["packets"] for row in rules
                        for expression in row.get("rule", {}).get("expr", [])
                        if isinstance(expression.get("counter"), dict))
            assert drops > 0, "the test did not observe an attempted UDP transport"
            return {"udp_blocked": True, "dropped_udp_packets": drops,
                    "selected_transport": local["transport"], "exit": "vps"}
        finally:
            self.block_server(None)

    def power_loss(self):
        self.block_server("all")
        try:
            assert self.request(timeout=3) is None
            self.client.stop(crash=True)
            self.client.start(via_agent=True)
            self.counter(reset=True)
            for _ in range(3):
                assert self.request(timeout=2) is None, "blocked VPS allowed a direct exit after restart"
            local = self.local()
            assert local["kill_switch_state"] in ["armed", "blocking"], local["kill_switch_state"]
            self.client.run([*USER_PREFIX, "python3", FIXTURE, "dns"])
            assert self.request(host="fd42:789::1", port=18081) is None
            assert self.counter() == {"dns": 0, "ipv6": 0}, self.counter()
        finally:
            self.block_server(None)
        local = self.wait_connected(timeout=150)
        assert local["auto_reconnect_enabled"] and local["connect_on_startup"]
        return {"blocked_after_restart": True, "recovered_exit": "vps",
                "transport": local["transport"], "physical_leak_counters": self.counter()}

    def uninstall_server(self):
        # The ephemeral SSH agent must be restarted after the power-loss check.
        self.client.run(["rm", "-f", "/home/sirin/acceptance-agent.sock"])
        self.client.run([*USER_PREFIX, "ssh-agent", "-a", "/home/sirin/acceptance-agent.sock"])
        self.client.run([*USER_PREFIX, "ssh-add", "/home/sirin/vps-fixture-key"])
        result = self.cli("server", "uninstall", self.server_id, *self.ssh_options,
                          "--confirm-uninstall", timeout=300)
        self.server.run(["test", "!", "-e", "/etc/sirinvpn"])
        self.server.run(["test", "!", "-e", "/usr/local/lib/sirinvpn/sirinvpn-server"])
        assert b"sirinvpn" not in self.server.run(["nft", "list", "tables"]).stdout
        return {"vps_owned_files_removed": True, "vps_firewall_removed": True}

    def uninstall_active_client(self):
        self.cli("connect", self.server_id, "--transport", "direct", "--persistent")
        self.wait_connected("direct_udp")
        self.run_guest(self.client, ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get",
                                     "purge", "-y", "sirin-vpn"], timeout=180)
        assert self.request() == "direct", "removing the active client did not restore physical networking"
        assert b"sirinvpn" not in self.client.run(["nft", "list", "tables"]).stdout
        self.assert_routes_removed()
        # Reinstall the same local package so its ordinary owner workflow can
        # remove the VPS and retained user profile after this removal check.
        self.run_guest(self.client, ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get",
                                     "install", "-y", "/home/sirin/sirinvpn.deb"], timeout=180)
        assert self.local()["state"] == "disconnected"
        self.counter(reset=True)
        return {"removed_while_connected": True, "physical_network_restored": True,
                "same_package_reinstalled_for_vps_cleanup": True}

    def uninstall_client(self):
        self.run_guest(self.client, ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get",
                                      "purge", "-y", "sirin-vpn"], timeout=180)
        self.client.run(["test", "!", "-e", HELPER])
        assert self.request() == "direct"
        assert b"sirinvpn" not in self.client.run(["nft", "list", "tables"]).stdout
        return {"package_removed": True, "physical_network_available": True}

    def execute(self):
        lab = None
        try:
            with Lab(self.output) as lab:
                port = free_port()
                net = "stream,id=private,addr.type=inet,addr.host=127.0.0.1,addr.port=" + str(port)
                self.server = lab.guest(self.args.base, "sirin-vps", memory=1024,
                                        canary=("vps", self.identity), ipv6=False,
                                        extra_network=["-netdev", net + ",server=on", "-device",
                                                       "virtio-net-pci,netdev=private,mac=52:54:00:78:70:01"])
                self.client = lab.guest(self.args.base, "sirin-client", memory=1536,
                                        canary=("direct", self.identity),
                                        extra_network=["-netdev", net + ",server=off,reconnect-ms=1000", "-device",
                                                       "virtio-net-pci,netdev=private,mac=52:54:00:78:70:02"])
                control = {name: {"agent": str(guest.agent_path), "fixture": guest.run_id}
                           for name, guest in [("server", self.server), ("client", self.client)]}
                (self.output / "active-fixtures.json").write_text(json.dumps(control) + "\n")
                try:
                    self.step("Fresh disposable VPS", lambda: self.prepare_guest(
                        self.server, SERVER, "52:54:00:78:70:01"))
                    if self.args.installer_tests:
                        self.step("Release-record and artifact guards under guest root", self.release_guard_regression)
                    self.step("Install exact Debian package and guest-only Polkit authorization", lambda:
                              self.prepare_guest(self.client, "198.18.10.2", "52:54:00:78:70:02", True))
                    self.step("Provision and enroll through the packaged CLI", self.provision)
                    self.step("Verify physical IPv4, IPv6 and leak-counter baselines", self.baseline)
                    for transport in ["direct", "obfuscated", "tls", "tcp"]:
                        self.step(f"{transport}: encrypted exit, native DNS and leak prevention",
                                  lambda transport=transport: self.connected_proof(transport))
                        if transport == "direct":
                            self.step("Closing the real desktop GUI preserves the active tunnel", self.gui_close)
                            self.step("Reach public HTTPS through the tunnel", self.public_internet)
                            self.step("Resolver failure retains the tunnel and prevents DNS fallback", self.dns_failure)
                        if transport == "tls":
                            self.step("Recover from abrupt transport-process termination", self.relay_crash)
                        self.step(f"{transport}: explicit disconnect restores networking", self.clean_disconnect)
                    for kill_switch in [False, True]:
                        for reconnect in [False, True]:
                            self.step(f"Tunnel interruption: kill switch={kill_switch}, reconnect={reconnect}",
                                      lambda kill_switch=kill_switch, reconnect=reconnect:
                                      self.failure_policy(kill_switch, reconnect))
                    self.step("Automatic fallback with both UDP transports blocked", self.automatic_fallback)
                    self.step("Power loss, persistent blocking and automatic recovery", self.power_loss)
                    self.step("Disconnect clears persistent protection and restores networking", self.clean_disconnect)
                    self.step("Removing an active client restores networking", self.uninstall_active_client)
                    self.step("Uninstall VPS through pinned SSH", self.uninstall_server)
                    self.step("Remove the client package after disconnect", self.uninstall_client)
                    self.report["passed"] = True
                except Exception:
                    self.report["passed"] = False
                    self.save()
                    if self.args.keep_failed_seconds:
                        print(f"Failure: disposable fixtures retained for up to {self.args.keep_failed_seconds}s for diagnosis", flush=True)
                        traceback.print_exc()
                        deadline = time.monotonic() + self.args.keep_failed_seconds
                        while time.monotonic() < deadline and not (self.output / "stop-fixtures").exists():
                            time.sleep(1)
                    raise
                finally:
                    (self.output / "active-fixtures.json").unlink(missing_ok=True)
            self.report["guest_cleanup"] = "complete"
            return 0
        finally:
            if lab is not None and not lab.directory.exists():
                self.report["guest_cleanup"] = "complete"
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--installer-tests", type=Path,
                        help="Current installer test executable for the guest-root regression")
    parser.add_argument("--keep-failed-seconds", type=int, default=0, choices=range(0, 3601), metavar="0..3600")
    return Acceptance(parser.parse_args()).execute()


if __name__ == "__main__":
    raise SystemExit(main())
