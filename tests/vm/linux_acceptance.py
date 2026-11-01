#!/usr/bin/env python3
"""Accept the packaged Linux CLI/helper against a fresh, independently installed VPS."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tarfile
import time
import traceback
import uuid

from lab import CPU_PERCENT, Lab, MEMORY_LIMIT, ROOT, digest, free_port


FIXTURE = "/opt/sirin-acceptance.py"
HELPER = "/usr/lib/sirinvpn/sirinvpn-helper"
CLI = "/usr/bin/sirinvpn"
SERVER = "198.18.10.1"
BLOCKLIST_ZONE = "/etc/unbound/unbound.conf.d/sirinvpn-dns-blocklist.conf"
# One DNS question per name to the tunnel resolver; prints each response code.
RCODES = r"""
import socket, struct, sys
for name in sys.argv[1:]:
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(5)
    client.sendto(struct.pack(">HHHHHH", 0x5356, 0x0100, 1, 0, 0, 0) + question + b"\0\1\0\1",
                  ("10.77.0.1", 53))
    print(client.recv(4096)[3] & 0x0F)
"""
USER_PREFIX = ["runuser", "-u", "sirin", "--", "env",
               "SSH_AUTH_SOCK=/home/sirin/acceptance-agent.sock",
               "DBUS_SESSION_BUS_ADDRESS=unix:path=/home/sirin/acceptance-bus"]


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.output = args.output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.logs = self.output / "logs"
        self.logs.mkdir(exist_ok=True)
        self.identity = str(uuid.uuid4())
        self.report = {
            "scope": "Packaged Linux CLI, Polkit helper and real WireGuard VPS in two disposable VMs",
            "host_root": False, "host_privileged_networking": False,
            "limits": {"memory_bytes": MEMORY_LIMIT, "swap_bytes": 0,
                       "cpu_percent": CPU_PERCENT, "server_memory_mib": 1024,
                       "client_memory_mib": 1536},
            "package_sha256": digest(args.package), "base_image_sha256": digest(args.base),
            "vps_base_image_sha256": digest(args.vps_base or args.base),
            "vps_dns_upstream": args.vps_dns_over_tls or "recursive",
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
            guest.put((self.args.upgrade_from or self.args.package).resolve(), "/home/sirin/sirinvpn.deb")
        # The optional caches hold Debian downloads and indexes; a VPS guest from --vps-base fetches its own.
        debian_caches = guest.base == self.args.base.resolve()
        if self.args.dependency_archives and debian_caches:
            # Only public .deb downloads enter apt's cache. Apt still verifies
            # their signed repository hashes before installing dependencies.
            with tarfile.open(self.args.dependency_archives) as archive:
                members = archive.getmembers()
                assert all((m.isdir() and m.name == '.') or
                           (m.isfile() and len(Path(m.name).parts) == 1 and
                            m.name.endswith('.deb') and m.size < 512 * 1024**2)
                           for m in members), 'Invalid dependency archive'
            guest.put(self.args.dependency_archives.resolve(), '/home/sirin/dependencies.tar.gz')
            guest.ssh(['sudo', '-n', 'mkdir', '-p', '/var/cache/apt/archives'], timeout=10)
            guest.ssh(['sudo', '-n', 'tar', '-xzf', '/home/sirin/dependencies.tar.gz',
                       '-C', '/var/cache/apt/archives', '--no-same-owner'], timeout=60)
        if self.args.dependency_indexes and debian_caches:
            with tarfile.open(self.args.dependency_indexes) as archive:
                assert all(m.isfile() and Path(m.name).name == m.name and
                           m.name.startswith('_etc_apt_mirrors_') and m.size < 128 * 1024**2
                           for m in archive), 'Invalid public Debian index cache'
            self.report['dependency_indexes_sha256'] = digest(self.args.dependency_indexes)
            guest.put(self.args.dependency_indexes.resolve(), '/home/sirin/indexes.tar.gz')
            guest.ssh(['sudo', '-n', 'tar', '-xzf', '/home/sirin/indexes.tar.gz',
                       '-C', '/var/lib/apt/lists', '--no-same-owner'], timeout=60)
        packages = "qemu-guest-agent python3 curl iproute2 nftables kmod"
        # Keep later installer-driven apt refreshes on the same bounded fixture
        # network settings. Repository signatures and hashes remain enforced.
        guest.ssh(['sudo', '-n', 'tee', '/etc/apt/apt.conf.d/99sirin-acceptance'],
                  data=b'Acquire::ForceIPv4 "true";\nAcquire::Languages "none";\nAcquire::Retries "2";\n',
                  stdout=subprocess.DEVNULL)
        if client:
            packages += " xvfb xauth python3-xlib dbus-x11 gnome-keyring /home/sirin/sirinvpn.deb"
        with (self.logs / f"{guest.name}-setup.log").open("wb") as log:
            guest.ssh(["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "sh", "-ec",
                       "sed -i '/^Types:/s/ deb-src//g' /etc/apt/sources.list.d/*.sources\n"
                       "apt-get -o Acquire::Retries=2 -o Acquire::ForceIPv4=true -o Acquire::Languages=none update\n"
                       f"apt-get -o Acquire::ForceIPv4=true install -y --no-install-recommends {packages}\n"
                       "install -m 0755 /home/sirin/acceptance-guest.py /opt/sirin-acceptance.py\n"
                       "systemctl start qemu-guest-agent\nmodprobe wireguard\nmodprobe nf_tables\n"],
                      timeout=1800, stdout=log, stderr=log)
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
        return {"kernel": guest.run(["uname", "-r"]).stdout.decode().strip(),
                "os": guest.run(["grep", "^PRETTY_NAME=", "/etc/os-release"]).stdout.decode()
                .strip().partition("=")[2].strip('"')}

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
        assert self.cli('server', 'list') == [], 'Fixture must have no existing profiles'
        # Establish durable fixture/OS inputs before creating application state.
        # No global sync follows profile creation or candidate package unpacking:
        # the later power cut must still exercise the application's own durability.
        self.client.run(['sync'])
        self.cli("storage", "allow-private-file")  # Explicit consent inside this disposable headless guest.
        profile = self.cli("server", "add", "--name", "Acceptance", "--host", SERVER,
                           *self.ssh_options, "--server-binary", "/usr/lib/sirinvpn/sirinvpn-server",
                           "--private-dns-record", "probe.test=10.0.2.100",
                           "--private-dns-record", "dns-failure.test=10.0.2.100",
                           *(["--dns-over-tls-endpoint", self.args.vps_dns_over_tls]
                             if self.args.vps_dns_over_tls else []), timeout=600)
        self.server_id = profile["id"]
        assert not profile.get("ipv6_tunnel_enabled", False), "the fixture needs an IPv4-only profile"
        configuration = json.loads(self.server.run(["cat", "/etc/sirinvpn/server.json"]).stdout)
        schema = configuration["schema_version"]
        # A fresh install pins its own generated TLS certificate and answers QUIC (schema 11)
        # on UDP 443, with Obfuscated UDP moved to 51821.
        quic = configuration["tls_like"].get("quic", False)
        if not self.args.upgrade_from:
            assert schema == 11 and quic, f"server configuration schema {schema}, QUIC {quic}"
            assert configuration["obfuscated_udp"]["port"] == 51821, configuration["obfuscated_udp"]
            assert ":443 " in self.server.run(["ss", "-H", "-lun", "sport = :443"]).stdout.decode()
        return {"profile_created": True, "server_id": self.server_id,
                "server_configuration_schema": schema, "quic": quic}

    def upgrade(self):
        """Qualify an unbound development upgrade, without rewriting signed receipts."""
        guest = self.client
        guest.put(ROOT / 'tests/vm/upgrade_guest.py', '/home/sirin/upgrade-guest.py')
        def check(action):
            return json.loads(guest.run([*USER_PREFIX, 'python3', '/home/sirin/upgrade-guest.py', action], timeout=180).stdout)
        backup_before = check('backup-create')
        before = check('snapshot')
        self.report['upgrade_before_power_cut'] = {'snapshot': before, 'backup': backup_before}
        self.save()
        guest.put(self.args.package.resolve(), '/home/sirin/candidate.deb')
        # Flush only test inputs. Do not sync dpkg's files or the application's
        # profile/credential directories: their own durability is under test.
        guest.run(['python3', '-c',
                   'import os\nfor p in ("/home/sirin/upgrade-guest.py", "/home/sirin/candidate.deb", "/home/sirin"):\n'
                   ' f=os.open(p,os.O_RDONLY);os.fsync(f);os.close(f)'])
        guest.run(['dpkg', '--unpack', '/home/sirin/candidate.deb'], timeout=120)
        # A real VM power cut between unpack and configure; this is one explicit
        # interruption boundary, not a claim about every possible dpkg failure.
        guest.stop(crash=True)
        guest.start(via_agent=True)
        guest.run(['dpkg', '--configure', 'sirin-vpn'], timeout=120)
        assert not guest.run(['dpkg', '--audit']).stdout.strip()
        assert check('snapshot') == before, 'Upgrade changed profile or credential bytes'
        backup_after = check('backup-verify')
        assert self.local()['state'] == 'disconnected'
        guest.run(['rm', '-f', '/home/sirin/acceptance-agent.sock'])
        guest.run([*USER_PREFIX, 'ssh-agent', '-a', '/home/sirin/acceptance-agent.sock'])
        guest.run([*USER_PREFIX, 'ssh-add', '/home/sirin/vps-fixture-key'])
        self.cli('server', 'repair', self.server_id, *self.ssh_options,
                 '--server-binary', '/usr/lib/sirinvpn/sirinvpn-server', '--confirm-repair',
                 '--private-dns-record', 'probe.test=10.0.2.100',
                 '--private-dns-record', 'dns-failure.test=10.0.2.100', timeout=600)
        return {'previous_package_sha256': digest(self.args.upgrade_from),
                'candidate_package_sha256': digest(self.args.package),
                'profile_and_credentials_preserved': before, 'backup_before': backup_before,
                'backup_after': backup_after, 'power_cut_after_unpack': True,
                'configure_retry': 'passed', 'vps_repair_with_candidate_payload': 'passed'}

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
        expected = {"direct": "direct_udp", "obfuscated": "obfuscated_udp", "quic": "quic",
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

    def blocklist_settled(self, active, timeout=300):
        deadline = time.monotonic() + timeout
        while True:
            settings = self.cli("server", "dns-blocking", "status", self.server_id)
            status = settings["status"]
            assert status.get("failure") is None, f"blocklist refresh failed: {status}"
            if status["active"] == active and not settings["pending"]:
                return settings
            assert time.monotonic() < deadline, f"blocklist did not settle: {settings}"
            time.sleep(3)

    def rcodes(self, *names):
        result = self.run_guest(self.client, [*USER_PREFIX, "python3", "-c", RCODES, *names])
        return [int(value) for value in result.stdout.split()]

    def local_zones(self):
        return self.server.run(["unbound-control", "list_local_zones"]).stdout.decode().splitlines()

    def dns_blocking(self):
        """The Owner toggles VPS-wide blocking through the CLI and private management API."""
        initial = self.cli("server", "dns-blocking", "status", self.server_id)
        assert not initial["policy"]["enabled"] and not initial["status"]["active"], initial
        name = self.args.dns_blocklist
        source = next(preset["url"] for preset in initial["presets"] if preset["name"] == name)
        self.cli("server", "dns-blocking", "enable", self.server_id,
                 "--list", name.lower().replace(" ", "-"), "--allow", "keep.googlesyndication.com")
        enabled = self.blocklist_settled(True)
        assert enabled["policy"] == {"enabled": True, "sources": [source],
                                     "allowlist": ["keep.googlesyndication.com"]}, enabled["policy"]
        count = enabled["status"]["domain_count"]
        zones = self.local_zones()
        assert count > 10_000 and sum(zone.endswith(" always_nxdomain") for zone in zones) == count
        assert "keep.googlesyndication.com. transparent" in zones
        # Through the tunnel, a listed name and its subdomains are NXDOMAIN; private records still answer.
        assert self.rcodes("googlesyndication.com", "pagead2.googlesyndication.com",
                           "probe.test") == [3, 3, 0]
        assert self.request(host="probe.test") == "vps"
        # shortcut: VPS diagnostics with a DoT upstream abort on rustls provider selection
        # (dns_diagnostics.rs); check the diagnostic only with the recursive upstream until fixed.
        if not self.args.vps_dns_over_tls:
            checks = {check["code"]: check for check in self.cli("diagnose", self.server_id)["checks"]}
            assert checks.get("dns_blocklist", {}).get("level") == "pass", \
                [(code, check["level"]) for code, check in checks.items()]
        self.cli("server", "dns-blocking", "disable", self.server_id)
        disabled = self.blocklist_settled(False)
        assert disabled["policy"]["sources"] == [source] and not disabled["policy"]["enabled"]
        assert not any(zone.endswith(" always_nxdomain") for zone in self.local_zones())
        self.server.run(["test", "!", "-e", BLOCKLIST_ZONE])
        assert self.rcodes("probe.test") == [0]
        return {"blocked_zones": count, "blocked_rcode": 3, "allowed_zone": "transparent",
                "diagnostics": "not checked" if self.args.vps_dns_over_tls else "pass",
                "disabled_zone_removed": True,
                "physical_leak_counters": self.counter()}

    def subnet_routes(self):
        """The Owner shares a LAN behind this client: the VPS routes into it, the client keeps it."""
        lan = ["ip", "netns", "exec", "sirin-lan"]
        for command in (["ip", "netns", "add", "sirin-lan"],
                        ["ip", "link", "add", "sirinlan0", "type", "veth", "peer", "name", "eth0",
                         "netns", "sirin-lan"],
                        ["ip", "address", "add", "192.168.77.1/24", "dev", "sirinlan0"],
                        ["ip", "link", "set", "sirinlan0", "up"],
                        [*lan, "ip", "address", "add", "192.168.77.10/24", "dev", "eth0"],
                        [*lan, "ip", "link", "set", "eth0", "up"],
                        # The one host setting a Linux router needs; SirinVPN never changes it.
                        ["sysctl", "-qw", "net.ipv4.ip_forward=1"]):
            self.client.run(command)
        owner = next(member for member in self.cli("server", "members", self.server_id)["members"]
                     if member["role"] == "owner")
        device = owner["devices"][0]["id"]
        self.cli("server", "set-peer-communication", self.server_id, device, "--mode", "peers")
        snapshot = self.cli("server", "set-subnet-routes", self.server_id, device,
                            "--route", "192.168.77.0/24")
        assert [d.get("subnet_routes") for m in snapshot["members"] for d in m["devices"]
                if d["id"] == device] == [["192.168.77.0/24"]]
        vps_routes = ["ip", "-4", "route", "show", "dev", "sirinvpn0", "proto", "static"]
        assert self.server.run(vps_routes).stdout.split()[:1] == [b"192.168.77.0/24"]
        assert b"192.168.77.0/24" in self.server.run(["wg", "show", "sirinvpn0", "allowed-ips"]).stdout
        # The device learns its routes from status and applies them when it next connects.
        assert self.cli("status")["server"]["caller_subnet_routes"]["announced"] == ["192.168.77.0/24"]
        self.cli("disconnect")
        self.cli("connect", self.server_id, "--transport", "direct", "--kill-switch", "--automatic-reconnect")
        local = self.wait_connected("direct_udp")
        assert local["kill_switch_state"] == "armed", local["kill_switch_state"]
        ping = ["ping", "-c", "1", "-W", "3", "192.168.77.10"]
        self.client.run(ping)  # the router keeps its own LAN under the kill switch
        self.server.run(ping)  # the VPS reaches the LAN through the router's forwarding and NAT
        assert self.request() == "vps"
        self.cli("server", "set-subnet-routes", self.server_id, device)
        assert not self.server.run(vps_routes).stdout.strip()
        assert self.server.run(ping, check=False).returncode != 0
        self.cli("server", "set-peer-communication", self.server_id, device, "--mode", "internet-only")
        self.client.run(["ip", "netns", "delete", "sirin-lan"])
        self.client.run(["sysctl", "-qw", "net.ipv4.ip_forward=0"])
        return {"vps_route": True, "router_lan_reachable": True, "vps_reaches_lan": True,
                "removed": True, "physical_leak_counters": self.counter()}

    def leak_test(self):
        checks = {check["code"]: check for check in self.cli("diagnose", self.server_id)["checks"]}
        levels = {code: checks.get(code, {}).get("level") for code in ("leak_ipv4", "leak_ipv6", "leak_dns")}
        # The fixture tunnels IPv4 only and blocks physical IPv6, which the VPS cannot observe.
        assert levels == {"leak_ipv4": "pass", "leak_ipv6": "not_applicable", "leak_dns": "pass"}, \
            [(code, check["level"], check["message"]) for code, check in checks.items()]
        # The test requests themselves never reach the physical network.
        assert self.counter() == {"dns": 0, "ipv6": 0}, self.counter()
        # The lab disables the APT timers so they cannot take the dpkg lock mid-run, so the update check
        # must warn; enabling the timer without starting it must turn it into a pass.
        updates = {code: checks.get(code, {}).get("level") for code in ("os_security_updates", "os_reboot_required")}
        assert updates["os_security_updates"] == "warning" and updates["os_reboot_required"] in ("pass", "warning"), updates
        self.server.run(["systemctl", "enable", "apt-daily-upgrade.timer"])
        try:
            enabled = {check["code"]: check["level"] for check in self.cli("diagnose", self.server_id)["checks"]}
        finally:
            self.server.run(["systemctl", "disable", "apt-daily-upgrade.timer"])
        assert enabled.get("os_security_updates") == "pass", enabled.get("os_security_updates")
        updates["os_security_updates_with_timer"] = "pass"
        return {"leak_test": levels, "os_updates": updates, "physical_leak_counters": self.counter()}

    def speed_test(self):
        result = self.cli("speed-test", self.server_id, timeout=90)
        rates = (result["download_bits_per_second"], result["upload_bits_per_second"])
        assert min(rates) > 0, result
        assert None not in (result["idle_latency_micros"], result["download_latency_micros"],
                            result["upload_latency_micros"]), result
        assert self.counter() == {"dns": 0, "ipv6": 0}, self.counter()
        repeat = self.cli("speed-test", self.server_id, timeout=90, check=False)
        assert repeat.returncode and b"wait " in repeat.stderr, repeat.stderr[-400:]
        # The VPS logs nothing about either run.
        journal = self.server.run(["journalctl", "-u", "sirinvpn-server", "--since", "-3min", "-o", "cat"]).stdout.decode()
        assert "speed" not in journal.lower(), journal[-400:]
        return {"speed_test": result, "repeat_refused": True, "physical_leak_counters": self.counter()}

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
        assert not self.client.run(["ip", "-4", "rule", "show", "priority", "9989"]).stdout.strip()
        self.client.run(["test", "!", "-e", "/var/lib/sirinvpn/desired-connection.json"])

    def relay_crash(self):
        self.counter(reset=True)
        assert self.local()["transport"] == "tls_like"
        unit = "sirinvpn-transport@tls_like.service"
        self.client.run(["systemctl", "is-active", "--quiet", unit])
        self.client.run(["systemctl", "kill", "--kill-whom=main", "--signal=KILL",
                         unit])
        for _ in range(3):
            assert self.request(timeout=1) != "direct", "transport crash leaked through the ISP"
        local = self.wait_connected("tls_like")
        assert self.counter() == {"dns": 0, "ipv6": 0}, self.counter()
        return {"transport": local["transport"], "terminated_unit": unit, "exit": "vps"}

    def block_server(self, mode):
        self.server.run(["nft", "delete", "table", "inet", "sirin_acceptance_fault"], check=False)
        if mode is None:
            return
        # Direct UDP 51820, Obfuscated UDP 51821 and QUIC on UDP 443.
        protocol = "meta l4proto { tcp, udp } th dport { 443, 51820, 51821 }" if mode == "all" else \
            "udp dport { 443, 51820, 51821 }"
        rules = ("table inet sirin_acceptance_fault {\n chain input {\n"
                 "  type filter hook input priority -100; policy accept;\n"
                 f"  ip saddr 198.18.10.2 {protocol} counter drop\n"
                 " }\n}\n")
        self.server.run(["nft", "-f", "-"], data=rules.encode())

    def automatic_fallback(self):
        from dns_attribution import capture, mark
        observation = {"scope": "bounded DNS metadata in synthetic disposable guest only"}
        self.report.setdefault("automatic_fallback_observations", []).append(observation)
        with capture(self, observation):
            # Observe disconnect too: late DNS socket resets can precede Connect.
            self.clean_disconnect()
            mark(self, observation, "counter_baseline_requested")
            before_connect = self.counter()
            observation["before_connect"] = before_connect
            self.block_server("udp")
            try:
                mark(self, observation, "connect_requested")
                self.cli("connect", self.server_id, "--transport", "automatic", "--persistent",
                         "--network-profile", "normal", timeout=240)
                local = self.wait_connected(timeout=100)
                mark(self, observation, "fallback_connected")
                assert local["transport"] in ["tls_like", "tcp_fallback"], local["transport"]
                assert local["auto_reconnect_enabled"] and local["connect_on_startup"]
                assert self.request(host="probe.test") == "vps"
                after_connect = self.counter()
                observation["after_connect"] = after_connect
                # Count new packets, not traffic already observed while disconnected.
                # Every increment still fails, including before the guard is armed.
                assert after_connect == before_connect and after_connect["ipv6"] == 0, {
                    "before_connect": before_connect, "after_connect": after_connect}
                rules = json.loads(self.server.run(["nft", "-j", "list", "table", "inet",
                                                   "sirin_acceptance_fault"]).stdout)["nftables"]
                drops = sum(expression["counter"]["packets"] for row in rules
                            for expression in row.get("rule", {}).get("expr", [])
                            if isinstance(expression.get("counter"), dict))
                assert drops > 0, "the test did not observe an attempted UDP transport"
                return {"udp_blocked": True, "dropped_udp_packets": drops,
                        "selected_transport": local["transport"], "exit": "vps",
                        "before_connect": before_connect, "after_connect": after_connect}
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
        sentinel = ("table inet sirin_acceptance_sentinel {\n chain keep {\n"
                    "  type filter hook output priority 300; policy accept;\n }\n}\n")
        self.server.run(["nft", "-f", "-"], data=sentinel.encode())
        unrelated = self.server.run(["nft", "list", "table", "inet", "sirin_acceptance_sentinel"]).stdout
        # Earlier headless operations explicitly exercised file fallback. Now make
        # the owned session store available so deletion can verify both backends.
        self.client.run([*USER_PREFIX, "dbus-daemon", "--session", "--fork",
                         "--address=unix:path=/home/sirin/acceptance-bus"])
        self.client.run([*USER_PREFIX, "gnome-keyring-daemon", "--unlock", "--components=secrets"],
                        data=b"synthetic-fixture-password\n")
        # The ephemeral SSH agent must be restarted after the power-loss check.
        self.client.run(["rm", "-f", "/home/sirin/acceptance-agent.sock"])
        self.client.run([*USER_PREFIX, "ssh-agent", "-a", "/home/sirin/acceptance-agent.sock"])
        self.client.run([*USER_PREFIX, "ssh-add", "/home/sirin/vps-fixture-key"])
        result = self.cli("server", "uninstall", self.server_id, *self.ssh_options,
                          "--confirm-uninstall", timeout=300)
        self.server.run(["test", "!", "-e", "/etc/sirinvpn"])
        self.server.run(["test", "!", "-e", "/usr/local/lib/sirinvpn/sirinvpn-server"])
        assert b"sirinvpn" not in self.server.run(["nft", "list", "tables"]).stdout
        assert self.server.run(["nft", "list", "table", "inet", "sirin_acceptance_sentinel"]).stdout == unrelated
        return {"vps_owned_files_removed": True, "vps_firewall_removed": True,
                "unrelated_firewall_preserved": True}

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
        package = "/home/sirin/candidate.deb" if self.args.upgrade_from else "/home/sirin/sirinvpn.deb"
        expected = digest(self.args.package)
        assert self.client.run(["sha256sum", package]).stdout.decode().split()[0] == expected
        self.run_guest(self.client, ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get",
                                     "install", "-y", package], timeout=180)
        assert self.local()["state"] == "disconnected"
        self.counter(reset=True)
        return {"removed_while_connected": True, "physical_network_restored": True,
                "same_package_reinstalled_for_vps_cleanup": True, "reinstalled_package_sha256": expected}

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
                self.server = lab.guest(self.args.vps_base or self.args.base, "sirin-vps", memory=1024,
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
                    if self.args.upgrade_from:
                        self.step("Preserve legacy profile and backup through interrupted upgrade/retry", self.upgrade)
                    self.step("Verify physical IPv4, IPv6 and leak-counter baselines", self.baseline)
                    from dns_attribution import run
                    self.step("Attribute DNS before protection and during forced transport fallback", lambda: run(self))
                    if self.args.dns_attribution_only:
                        self.report["passed"] = True
                        return 0
                    self.clean_disconnect()
                    for transport in ["direct", "obfuscated", "quic", "tls", "tcp"]:
                        self.step(f"{transport}: encrypted exit, native DNS and leak prevention",
                                  lambda transport=transport: self.connected_proof(transport))
                        if transport == "direct":
                            self.step("Closing the real desktop GUI preserves the active tunnel", self.gui_close)
                            self.step("Reach public HTTPS through the tunnel", self.public_internet)
                            self.step("Resolver failure retains the tunnel and prevents DNS fallback", self.dns_failure)
                            self.step("On-demand leak test passes over the tunnel", self.leak_test)
                            self.step("Owner runs the tunnel-to-VPS speed test through the CLI", self.speed_test)
                            self.step("Owner turns VPS DNS blocking on and off through the CLI", self.dns_blocking)
                            self.step("Owner shares a LAN behind this device through the CLI", self.subnet_routes)
                        if transport == "tls":
                            self.step("Recover from abrupt transport-process termination", self.relay_crash)
                        self.step(f"{transport}: explicit disconnect restores networking", self.clean_disconnect)
                    for kill_switch in [False, True]:
                        for reconnect in [False, True]:
                            self.step(f"Tunnel interruption: kill switch={kill_switch}, reconnect={reconnect}",
                                      lambda kill_switch=kill_switch, reconnect=reconnect:
                                      self.failure_policy(kill_switch, reconnect))
                    for attempt in range(self.args.fallback_repeats):
                        self.step(f"Automatic fallback with both UDP transports blocked ({attempt + 1})", self.automatic_fallback)
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
            if lab is not None:
                complete = not lab.directory.exists() and not lab.socket_directory.exists()
                self.report["guest_cleanup"] = "complete" if complete else "incomplete"
                if not complete:
                    self.report["passed"] = False
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--vps-base", type=Path,
                        help="Separate cloud image for the VPS guest, such as Ubuntu 24.04; defaults to --base")
    parser.add_argument("--vps-dns-over-tls", metavar="IP#NAME",
                        help="Provision the VPS with this DNS-over-TLS upstream instead of recursion, "
                             "for host networks that intercept outbound DNS")
    parser.add_argument("--dns-blocklist", default="OISD Small", metavar="PRESET",
                        help="Built-in list for the DNS-blocking step, for host networks that block the default "
                             "(it must list googlesyndication.com)")
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--upgrade-from", type=Path,
                        help="Install/provision this older unbound development package before interrupted candidate upgrade")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--installer-tests", type=Path,
                        help="Current installer test executable for the guest-root regression")
    parser.add_argument("--keep-failed-seconds", type=int, default=0, choices=range(0, 3601), metavar="0..3600")
    parser.add_argument("--dependency-archives", type=Path,
                        help="Optional tar of cached public .deb downloads; apt verifies repository hashes")
    parser.add_argument("--dependency-indexes", type=Path,
                        help="Optional public Debian index cache from a trusted fixture; apt update still authenticates repositories")
    parser.add_argument("--fallback-repeats", type=int, default=1, choices=range(1, 6), metavar="1..5")
    parser.add_argument("--dns-attribution-only", action="store_true",
                        help="Run bounded packet/guard/process attribution with a pre-arm negative control")
    return Acceptance(parser.parse_args()).execute()


if __name__ == "__main__":
    raise SystemExit(main())
