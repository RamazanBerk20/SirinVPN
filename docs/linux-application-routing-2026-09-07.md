# Linux application routing

Settings → Network now offers Selected applications when the installed Linux
helper advertises support. Save that mode, connect, and use the application
launcher below the routing choices. The CLI equivalents are:

```sh
sirinvpn connect SERVER_ID --applications
sirinvpn run SERVER_ID /usr/bin/application -- --application-argument
```

The launcher requires an absolute native executable. Arguments are separate
values, with one argument per line in the desktop; no shell parsing occurs.
Close existing instances before launching. Flatpak, Snap, desktop portals and
service launchers are unsupported. An application that delegates networking to
an existing process or a separate service needs a compatible native launch path.

Only processes created by these launches and their ordinary children share the
application network namespace. Unselected applications retain their usual routes
and system DNS. The selected application's DNS uses the private VPS resolver.
The namespace masks host resolver and session-bus sockets, while carrying the
user's selected Wayland display, supported X authority file and native audio
socket into its private runtime view. This is a routing facility, not a sandbox
for hostile software with access to the user's other files and processes.

The helper establishes interface-scoped policy routes and a separate nftables
guard. The app network cannot fall back to the ordinary internet if the tunnel
disappears, including when the optional host kill switch is off. Explicit IPv4
LAN bypass permits the existing bounded LAN ranges but keeps ordinary DNS and
DoT ports from escaping there. Host network services are blocked from the app
interface except IPv6 neighbour maintenance.

Reconnect suspends the app link and preserves the namespace until routes, NAT
and the guard are restored. Key rotation updates the namespace's tunnel source
addresses without replacing its private addresses. Explicit disconnect or a
server switch removes the link before removing the guard; existing applications
stay open in a networkless namespace and must be launched again for a new
connection. Lost runtime ownership metadata cannot authorize guard removal from
a remaining app link.

IPv6 requires a dual-stack profile and host support for interface-level
`force_forwarding`, or IPv6 forwarding already enabled by the administrator.
On an older kernel with global forwarding disabled, application IPv6 is blocked.
SirinVPN does not enable global forwarding. The interface setting is documented
in the [kernel networking controls](https://docs.kernel.org/networking/ip-sysctl.html).
An existing host firewall may also block forwarding: the launcher checks a TCP
connection to the private DNS service inside the namespace and refuses to start
an app when that path is unavailable. It does not rewrite another firewall's
policy. A ready status confirms current configuration and supervisor freshness;
it is not a measurement of every destination an application might contact.

The root launcher runs fixed, root-owned system tools from protected paths,
revalidates the calling account and namespace, and permanently drops UID, GID,
capabilities and privilege acquisition before executing user-selected code.
User-controlled arguments and environment reach only that unprivileged stage.
The parent distinguishes a completed command from a confirmed running process.
Executable choices, arguments, PIDs and activity are not persisted. The private
runtime record contains only current namespace ownership and network bindings.

Application mode uses tunnel-request schema 11, desired-state schema 6,
runtime-state schema 5, connection-preference schema 4 and key-rotation schema 4.
Earlier formats remain readable for their original modes; application mode under
an earlier schema is rejected. The release compatibility contract includes these
versions so a rollback must declare that it can read them.

Focused evidence is maintained in `tests/network/run-application-routing.sh` and
the helper and launcher regression tests. The network test uses real Linux
namespaces, nftables, routing, NAT and the production privilege-drop executable
inside a disposable container with no host network, devices or systemd. Its VPN
exit is a synthetic veth, so it does not establish an encrypted WireGuard
handshake, polkit desktop interaction or final-artifact acceptance. Those remain
part of the full platform test pass after implementation.

On 7 September, the isolated packet test passed active routing, abrupt tunnel
loss, reconnect, rotated IPv4/IPv6 source addresses, disconnect, explicit LAN
bypass and IPv4-only blocking. It also checked host IPv4/IPv6 and native DNS,
lost-metadata guard retention, altered-rule detection, namespace continuity,
unprivileged execution and display/runtime isolation. The 76 helper, 46 core,
45 release and six desktop-preference tests passed; 15 focused frontend tests,
TypeScript, Clippy with warnings denied, formatting and the privacy gate passed.
Five helper tests requiring their separate isolated fixtures stayed ignored in
the ordinary unit run; the application kernel test ran through its own script.

The subsequent Debian 13 VM acceptance run passed this packet matrix twice on
kernel 6.12.107: once with global IPv6 forwarding disabled and once enabled. The
first case requires application IPv6 to stay blocked on this older kernel; the
second requires IPv6 delivery and source-address rotation through the VPN exit.
Both cases also require the initial global forwarding setting and ordinary host
IPv4, IPv6 and DNS behavior to remain unchanged. The VM runner now supplies the
forwarding prerequisites for the server-policy fixtures explicitly. All 14
deferred kernel tests passed across 15 cases in
`tests/vm/run-kernel-acceptance.sh`; this still does not substitute for the
packaged client-to-VPS acceptance run.
