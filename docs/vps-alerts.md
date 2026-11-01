# VPS alerts

The Owner can have the VPS send a notification when it needs attention, and
let an outside monitor notice when the VPS goes silent. Both are off by
default and stay off until the Owner adds an address.

## Who controls it

Only the Owner, in **Settings → Maintenance → VPS alerts**, or with the CLI:

```sh
sirinvpn server alerts status <server>
sirinvpn server alerts set <server> --ntfy <topic address> --heartbeat <monitor address>
sirinvpn server alerts set <server> --webhook <webhook address>
sirinvpn server alerts test <server>
sirinvpn server alerts off <server>
```

`set` replaces the whole setting; an address left out is removed. Admins and
Members can neither see nor change it: the addresses are the Owner's own
notification channels and can carry access tokens. The API is
`GET`/`PUT /v1/alerts` and `POST /v1/alerts/test` on the private management
endpoint. A server installed before this feature needs a repair first, which
installs the alert timer.

There are two addresses:

- **Alert address.** An [ntfy](https://ntfy.sh) topic (on ntfy.sh or your own
  ntfy server) or any HTTPS webhook. It receives problem, recovery and test
  notices.
- **Heartbeat address.** The VPS requests it every five minutes. Point it at
  a missed-heartbeat monitor, for example a Healthchecks check (hosted at
  healthchecks.io or self-hosted), an Uptime Kuma push monitor or a Better
  Stack heartbeat, with a five-minute period and at least ten minutes of grace.

## What the VPS checks

A sandboxed task, `sirinvpn-alerts.service`, runs every five minutes as the
unprivileged `sirinvpn` account with no capabilities. It is separate from the
SirinVPN service, so it can report that service stopping. It only reads local
state:

| Problem | Condition | Text the receiver gets |
| --- | --- | --- |
| Service stopped | `sirinvpn-server`, `sirinvpn-network`, `sirinvpn-firewall`, `unbound` or, with DoH, `sirinvpn-doh` is `failed` or `inactive` | A SirinVPN service on the VPS has stopped. |
| Restart loop | one of those units restarted itself three or more times since the previous check | A SirinVPN service on the VPS keeps restarting. |
| VPN network setup | the VPN interface is missing, IPv4 forwarding is off, or a configured listener (transport, management or private DNS port) is missing | The VPN interface, forwarding or a listening port on the VPS is missing. Use server repair. |
| Private DNS | the local resolver does not answer a root query within three seconds | The VPS DNS resolver does not answer. |
| Disk space | the root file system is at least 90% full (it clears below 85%) | The VPS disk is over 90% full. |
| Security updates | automatic security updates are off or could not be confirmed, as in diagnostics | Automatic security updates on the VPS are off or could not be confirmed. |
| Pending restart | an installed update has waited for a VPS restart for three days | An installed update has waited over three days for a VPS restart. |

A recovery line reads `Resolved: <name>.`, where the name is one of: SirinVPN
service, SirinVPN service restarts, VPN network setup, Private DNS, Disk
space, Security updates, Pending restart.

## How notices are sent

- **Confirmation.** A problem is sent only when the next check still sees it,
  so anything shorter than one check interval is never reported. A pending
  restart waits three days instead.
- **Deduplication.** Each problem is sent once when it starts and once when
  it clears. Nothing is repeated while it lasts.
- **Rate limit.** Notices are at least 15 minutes apart and at most 12 in any
  24 hours. A change held back by the limit goes out with the next notice
  that may be sent, which carries only the net change: a problem that started
  and cleared in between is never sent.
- **Failure.** A notice that could not be delivered is offered again at the
  next check. Settings shows the latest failure kind.
- **Test.** The test button and `sirinvpn server alerts test` send one fixed
  test notice from the VPS to the saved alert address and report whether it
  arrived, with the HTTP status if the receiver refused it. One test may be
  sent every ten seconds.
- **New address.** Changing the setting forgets which problems were sent, so
  a new address hears about current problems too. The rate limit carries
  over.

With the **ntfy** format the VPS sends `POST <topic address>` with the text
as the body and `Title`, `Tags` and, for problems, `Priority: high` headers.
With the **webhook** format it sends `POST <webhook address>` with
`Content-Type: application/json`:

```json
{
  "event": "alert",
  "title": "SirinVPN: your VPS needs attention",
  "message": "The VPS disk is over 90% full.\nResolved: Private DNS.",
  "text": "SirinVPN: your VPS needs attention\nThe VPS disk is over 90% full.\nResolved: Private DNS.",
  "problems": ["disk_nearly_full"],
  "resolved": ["dns_failing"]
}
```

`event` is `alert` or `test`. `text` repeats the title and message for chat
webhooks that read that field. The problem codes are `service_down`,
`service_restarting`, `network_setup`, `dns_failing`, `disk_nearly_full`,
`security_updates_off` and `restart_pending`. The heartbeat is a plain `GET`
with no body. Any 2xx answer counts as delivered.

Titles are `SirinVPN: your VPS needs attention`, `SirinVPN: VPS problem
resolved` and `SirinVPN test alert`. A notice does not name the server, so
give each VPS its own topic or webhook.

## Finding out that the VPS is down

A VPS cannot report its own power loss, freeze or lost network. Each
mechanism catches something different:

| Mechanism | Catches | Misses |
| --- | --- | --- |
| Alert address | the problems above, while the VPS runs and reaches the internet | the VPS being off, frozen or offline; the alert task itself failing |
| Heartbeat address | the VPS being off, frozen, offline or without outbound HTTPS; the alert timer stopping or failing | problems while heartbeats still arrive, such as a stopped SirinVPN service (the alert address covers those); inbound blocking that leaves outbound traffic working, such as a provider firewall change |
| SirinVPN apps | while a device is connected, its app and, on Android, its VPN notification show that it is reconnecting | everything while no device is connected |

For most Owners the useful combination is an ntfy topic for problems plus a
heartbeat monitor that notifies the same phone. SirinVPN does not watch the
VPS from your devices while they are disconnected; a desktop or phone that is
asleep or offline would make that unreliable, and the heartbeat already covers
it from outside.

## Addresses

Both addresses must be absolute HTTPS addresses without a user name, password
or fragment. A query string is allowed, for example ntfy's `?auth=` token or
an Uptime Kuma push token. The host must be a DNS name or an IP literal.

Private, loopback, link-local, shared (`100.64.0.0/10`), unique-local,
documentation and VPN addresses are refused unless the Owner turns on **Allow
private, loopback and VPN addresses**, for example for an ntfy server inside
the VPN. Names are checked twice: when saved, and again just before each
request, after the VPS resolves them. If any resolved address is not allowed,
nothing is sent. The connection is pinned to the checked addresses, so a
changed DNS answer cannot redirect it. The VPS follows no redirects, uses no
proxy and gives each request six seconds.

## Privacy

What leaves the VPS, and only after the Owner adds an address:

- To the alert address: the fixed title and lines above, the problem codes in
  the webhook format, the ntfy headers, the user agent `SirinVPN-alerts/1`,
  the VPS IP address and the time of the request.
- To the heartbeat address: a `GET` with the same user agent from the VPS IP
  address every five minutes.

No server name, member or device name, IP address, port, count, usage figure
or traffic data is sent. The receiver's operator (for example ntfy.sh) sees
everything above and keeps whatever its service keeps. Anyone who knows a
public ntfy.sh topic name can read it, so use a long random topic name, an
access token or your own ntfy server.

On the VPS, the setting is stored in the authorization document, so repair
keeps it and server-state backups include it. The alert task keeps one file,
`/var/lib/sirinvpn-alerts/state.json` (mode 0600, `sirinvpn`): the kinds of
the current problems and when each was first seen, which ones the receiver was
told about, the send times of the last 24 hours, the services' restart
counters, and the latest check, delivery and heartbeat times with the latest
failure kind. There is no history. Turning alerts off deletes the file.

## Install, repair, uninstall and backup

The SSH installer writes `sirinvpn-alerts.service` and
`sirinvpn-alerts.timer`. The timer stops while an install, repair or uninstall
transaction runs, so planned restarts are not reported, and starts again at the
end. Rollback restores the earlier units and state. Uninstall removes both units
and the state directory.

## Rollback to an older release

An older server reads the authorization document without the `alerts` field and
does not know `sirinvpn-server alerts check`, so its timer task fails without
sending anything. Its next authorization change drops the setting. After
updating again, set the alerts again.

## Limits

- A problem reaches the receiver five to ten minutes after it starts.
- The VPS cannot see a provider firewall, routing or DNS problem outside
  itself.
- The HTTPS transport certificate is generated for ten years, and the service
  refuses to start with an invalid one, which is reported as a stopped
  service. There is no separate certificate check. A DoT or DoH upstream with a
  bad certificate shows as private DNS not answering.
- A public address change is handled by endpoint observation and signed
  endpoint updates, not by an alert.

## Verified scope

Unit tests cover URL validation, the private-address check after resolution,
confirmation, deduplication, the rate limit and net change, the three-day
restart wait, restart-loop parsing, the exact notice text, and the ntfy,
webhook and heartbeat requests against a local HTTPS receiver. Handler tests
prove the settings are Owner-only and validated before any change. The
Settings card has component tests. The installer tests check the units,
their position in the transaction and their removal.
