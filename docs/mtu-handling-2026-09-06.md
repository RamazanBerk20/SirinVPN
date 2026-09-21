# Current-path MTU handling

Managed desktop and CLI connections automatically test packet delivery to the
private VPS address after a WireGuard handshake. Small probes establish that ICMP
is usable before larger DF probes are considered. A candidate must answer twice
before it becomes the suggestion. The helper reduces the automatic MTU to a
verified candidate and keeps the transport preset if ICMP is unavailable. There
is no external probe service and no history of network measurements.

The probe is bounded to the current tunnel path. It determines a usable packet
size up to the configured ceiling, rather than claiming the exact physical MTU
of every Internet destination beyond the VPS. Candidates range from the current
preset down to 576 bytes for IPv4. Tunneled IPv6 never goes below 1280; when small
packets work but this minimum fails, the UI suggests TLS/TCP transport instead of
silently disabling IPv6. Current results are refreshed after reconnection or a
detected route change. Normal status polling does not repeatedly send probes.

The app's Connection settings include automatic/manual selection. Manual MTU
stays fixed even if a lower working size is measured. The CLI accepts
`sirinvpn connect SERVER --mtu 1300`; omitting the flag selects automatic probing.
Current status includes the configured value, suggestion and probe outcome.
Per-server manual preferences persist locally. Key rotation retains the active
MTU policy in its versioned recovery journal.

The helper requires request schema 8 and desired-connection schema 3 when an MTU
policy is present. Older request versions preserve their existing fixed behavior.
The supervisor has scoped raw-socket capability for ICMP; Debian packages include
`iputils-ping`. The current Linux component must be updated before using the new
managed connection controls.

Focused checks include automatic reduction, manual retention, unavailable ICMP,
IPv6 minimum enforcement and current-only probing. The isolated
`sh tests/network/run-mtu-path.sh` check passed through a real WireGuard pair with
an induced oversized-packet black hole: automatic MTU dropped from 1420 to 1280,
manual MTU stayed at 1420 while reporting the lower suggestion, routing/firewall
rules were preserved, and fully blocked ICMP produced an unavailable measurement.
This is focused implementation evidence; final package and real-network acceptance
still follow completion of the remaining product scope.
