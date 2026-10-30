# DNS ad and tracker blocking

Every device that uses the server's private DNS (`10.77.0.1`) can get ad and
tracker blocking from the VPS resolver, with no setup on the device. Blocking
is off by default.

## Who controls it

The Owner or an Admin turns it on in **Settings → Network → Ad and tracker
blocking**, or with the CLI:

```sh
sirinvpn server dns-blocking status <server>
sirinvpn server dns-blocking enable <server> --list hagezi-multi-light --allow example.com
sirinvpn server dns-blocking disable <server>
```

SirinVPN has no per-admin permission flags, so every Admin can change it, the
same as port forwards and member access. Members cannot see or change it. The
API is `GET`/`PUT /v1/dns-blocklist` on the private management endpoint.

A manager picks up to eight lists. The built-in choices are:

| Name | Format | Entries on 2026-10-30 |
| --- | --- | --- |
| HaGeZi Multi Light | domains | 74,278 |
| HaGeZi Multi Normal | domains | 172,633 |
| OISD Small | domains | 59,949 |
| StevenBlack Unified Hosts | hosts | 76,736 |

Any other HTTPS list in hosts (`0.0.0.0 name`) or domain-list format can be
added. Up to 512 allowed domains are never blocked, together with their
subdomains.

## How it works

The policy is stored in the VPS authorization document, next to members and
port forwards. Saving it is an ordinary authorization commit, so it is
validated, atomic, kept by repair, and included in server-state backups.

The management daemon runs without root and cannot change Unbound. A root
task, `sirinvpn-dns-blocklist.service`, applies the policy:

- `sirinvpn-dns-blocklist.path` starts it when the authorization document
  changes. The task does nothing unless the policy, the private DNS records or
  the split DNS zones changed, or the list is more than 20 hours old.
- `sirinvpn-dns-blocklist.timer` starts it 10 minutes after the timer starts
  (after install, repair or boot) and daily after that. Each run is delayed by
  up to one more hour at random, so list hosts do not see every server at
  once.
- A failing policy is retried at most once an hour.

Each list is downloaded by the existing non-login `sirinvpn-update-fetch`
account through `runuser`. The download has a 16 MiB size limit, a two-minute
deadline, no redirects and no content encoding. The parser accepts hosts and
domain-list lines, skips invalid names, and rejects a list where invalid
lines outnumber valid names (for example an HTML page or an Adblock list). It
stops at 300,000 unique names.

The task writes
`/etc/unbound/unbound.conf.d/sirinvpn-dns-blocklist.conf`, mode `0640`,
`root:unbound`:

- Each blocked name becomes `local-zone: "name." always_nxdomain`, which also
  covers its subdomains. Listed subdomains of a blocked name are left out.
- An allowed name below a blocked name gets a more specific
  `transparent` zone. Allowed names and their subdomains are removed from the
  blocked set.
- Names that equal a private DNS record or a split DNS zone are left out, so
  those zones keep working.

The new file is staged beside the live one, checked on its own with
`unbound-checkconf` as the `unbound` user, and renamed into place. The full
configuration is checked again as `unbound`, then `unbound-control reload`
loads it. Unbound rereads its configuration without root on reload, so the
installer now makes `sirinvpn.conf` `0640 root:unbound` too. If any step
fails, the previous file is restored and stays in effect.

`/var/lib/sirinvpn-dns-blocklist/status.json` holds one current summary:
whether a list is active, how many zones it has, when it was built, and the
latest failure kind (`download`, `format`, `too_many_domains` or `resolver`)
with its time. Diagnostics show a warning while the last refresh has failed.

With all four built-in lists, the generated file has 202,572 zones and is
10.7 MB. In an Ubuntu 24.04 container, Unbound 1.19.2 used about 80 MB more
memory with it, `unbound-checkconf` took 0.44 s and the reload 93 ms. Choose
fewer lists on a VPS with little memory.

## Privacy

Unbound keeps no query log, and the blocklist adds none. SirinVPN keeps no
count of blocked queries, no per-device statistics, and no refresh history.
The list hosts see the VPS IP address, the time of each download and the list
path. See [PRIVACY.md](../PRIVACY.md).

## Install, repair, uninstall, backup and restore

- **Install and repair** write the three units and the state directory, then
  enable and start the path and timer units after the other services. The
  units are stopped before the transaction changes anything, so the task never
  reloads Unbound during an install. The generated file and status are owned
  paths: rollback restores them and a successful repair keeps them.
- **Uninstall** disables the path and timer units, stops the task, removes the
  units, the generated file and the state directory, and restarts Unbound. The
  uninstall check proves the paths are gone and the units are inactive.
- **Backup and restore** carry the policy inside the authorization document.
  After a restore, the timer rebuilds the list 10 to 70 minutes later.

## Rollback to an older release

The policy is an optional field in the authorization document, so older
servers still read the document but ignore it. An older server cannot run the
task, so the last generated file stays loaded and cannot be changed from the
apps. Turn blocking off before rolling the VPS back to a release without DNS
blocking, or afterwards remove
`/etc/unbound/unbound.conf.d/sirinvpn-dns-blocklist.conf` and run
`unbound-control reload` as root.

## Verified scope

On 2026-10-30, on the development workstation:

- Unit tests cover list parsing (hosts and domain formats, comments, invalid
  names, wrong formats, non-UTF-8), the domain cap, the allowlist, private
  and split-zone names, redundant subdomains, the staged swap and its
  `0640` mode, restoring the previous file after a failed check or reload, the
  refresh window, retry limits and failure fallback, policy validation, backup
  and restore of the policy, and rejecting an invalid stored policy. The API
  handlers are tested in process for Owner, Admin and Member callers. The UI
  card and the diagnostics sanitizer have tests too.
- The four built-in lists, downloaded that day, parsed without errors. The
  OISD Small and HaGeZi Multi Normal counts match the lists' own headers.
- In `debian:13` and `ubuntu:24.04` containers with the distribution's
  Unbound (1.26.2 and 1.19.2): `unbound-control reload` swapped a generated
  file in, `runuser -u unbound -- unbound-checkconf` rejected a `0600 root`
  file that would have stopped Unbound on reload, and the three units passed
  `systemd-analyze verify`.

### Disposable VMs

Both runs used a local QEMU/KVM guest with 2 GiB of RAM and 2 vCPUs, a scratch
copy of `tests/vm/debian13.sh` with extra steps, and the x86_64 server built in
`packaging/Dockerfile.server-payloads` from this change (SHA-256
`807ba650…7229e25a`, at most `GLIBC_2.34`). No VPS was used.

- Ubuntu 24.04.5 LTS: the cloud image from the
  [Ubuntu record](ubuntu-24-04-vps-2026-10-29.md) (`04e8f246…985b6c94`).
- Debian 13 (trixie): `debian-13-genericcloud-amd64.qcow2`
  (`85a969b7…73d2d4e3`).

On both, all of the following passed:

- The normal gate: installation, listeners, IPv4-only fallback,
  identity-preserving repair and conflicting-install rollback.
- After installation, the path and timer units are enabled and active,
  `sirinvpn.conf` is `0640 root:unbound` and the state directory exists.
- Writing an enabled policy (OISD Small, allowing
  `keep.000webhostapp.com`) into the authorization document started the task
  through the path unit. In the sandboxed service it downloaded the list as
  `sirinvpn-update-fetch`, loaded 59,949 `always_nxdomain` zones and the
  transparent allowed zone, and Unbound answered NXDOMAIN for a blocked name
  and one of its subdomains. The zone file was `0640 root:unbound`.
- A list on an unresolvable host recorded a `download` failure, left the zone
  file byte-for-byte unchanged and kept Unbound answering. Returning to the
  applied policy cleared the failure without a download.
- Disabling removed the zone file and every blocked zone from Unbound.
- With blocking on, a repair kept the zone file unchanged and all units
  active.
- Uninstall removed the zone file, the three units and the state directory,
  and Unbound kept running without the blocked zones.

The VM gate has no VPN client, so these runs wrote the policy field into
`authorization.json` directly instead of through the management API.

### Two-VM lab: CLI and management API over the tunnel

`tests/vm/run-linux-acceptance.sh` now has the step "Owner turns VPS DNS
blocking on and off through the CLI". With the Direct transport connected,
the Owner's packaged CLI runs `sirinvpn server dns-blocking enable --list
oisd-small --allow keep.googlesyndication.com`, waits through `status` until
the VPS has applied it, and then checks:

- the policy reads back as sent, and Unbound on the VPS holds as many
  `always_nxdomain` zones as the API reports, plus the transparent allowed
  zone;
- from the client, through the tunnel, `googlesyndication.com` and
  `pagead2.googlesyndication.com` get NXDOMAIN while the private record
  `probe.test` still answers;
- `disable` keeps the chosen list, removes the zone file and every blocked
  zone, and the private record still answers.

The client was Debian 13 with `SirinVPN_0.1.1_amd64.deb` (SHA-256
`e0b89fde…2313585e`), built by `scripts/package-linux-container.sh` from
commit 673198d. That package's CLI provisioned the VPS with its bundled
server. The VPS used a DNS-over-TLS upstream
(`--vps-dns-over-tls 9.9.9.9#dns.quad9.net`) because this workstation's
network intercepts outbound DNS.

- **Ubuntu 24.04.5 VPS:** all 28 checks passed in 9.5 minutes, including the
  new step (59,949 zones), with zero physical DNS or IPv6 leaks and complete
  guest cleanup.
- **Debian 13 VPS:** all 28 checks passed in 13.0 minutes, with the same
  results for the new step and complete guest cleanup.

The step skips the diagnostics check when the VPS uses DNS-over-TLS. With
that upstream, every VPS diagnostics request currently aborts
`sirinvpn-server`: `dns_diagnostics.rs` builds its TLS probe with rustls's
implicit crypto provider. That bug predates DNS blocking and is tracked
separately. The `dns_blocklist` diagnostic is covered by unit tests on the
server and in the client's sanitizer.

## Not verified

- The desktop and Android UI against a real server. The card, its API calls
  and its Tauri and Android commands are covered by tests and a mocked render,
  but no lab drives the UI.
- An Admin (not Owner) turning blocking on over the tunnel. The role rule is
  tested in process.
- A real VPS, IPv6-only list hosts, aarch64, and memory use on a small VPS
  with several large lists.
