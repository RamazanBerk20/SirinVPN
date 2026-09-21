# Transport quality and Wi-Fi policy — 6 September 2026

Linux transport comparison behavior below is superseded by [the September 19 fix](connection-stability-2026-09-19.md). Wi-Fi policy is unchanged.

Managed Linux sessions measure the private WireGuard path using eight small ICMP
echo requests every 30 seconds. The current status exposes mean latency, jitter,
and delivered probes. No public measurement service is contacted. Blocked ICMP
is reported as unavailable; it is not classified as a broken VPN. These samples
do not estimate bulk download speed.

Automatic mode compares the configured transports while the kill switch is
verified and the current tunnel has transferred at most 32 KiB since the preceding
sample. It prefers complete packet delivery, then latency plus a jitter penalty;
a latency improvement must exceed both the comparison's 20% threshold and 5 ms.
Each comparison visits at most four candidates. A failed or slower trial returns
once to the previous measured winner, even with automatic reconnect disabled.
Failed rollback follows the user's independent recovery policy. All transition
paths preserve the existing guard. Without a kill switch the current path is
measured, and voluntary comparisons remain disabled.

Comparisons can run again after ten minutes or a physical network change.
Only the current comparison, a current counter baseline, and current observations
exist in `/run`; reconnecting resets this state. Stale measurements disappear from
status. The desktop's existing single-network transport cache records the result
after a comparison finishes and retains its existing seven-day bound. Repeated
apply failures now use the supervisor's bounded exponential backoff.

Desktop Settings → General includes an optional Wi-Fi policy and an explicit list
of trusted networks. The app connects to the chosen saved server on entering an
untrusted Wi-Fi network while it is running. Existing sessions, paused sessions,
and retained protection remain authoritative. There is one attempt per network
entry; cancellation or manual disconnect suppresses more attempts in that app
session until the network or the explicit policy changes. Restarting the app
starts a new observation session. OS authorization may still be required by the
installed networking component.

Trust uses a locally salted hash of a saved [NetworkManager connection UUID](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli-examples.html).
Unidentified Wi-Fi remains untrusted. Trust does not attest to a physical access
point; users should trust only connections they control. Marking a network trusted
requires the current token to match the network the UI reviewed. The private
network-policy schema 2 stores only the explicit policy, chosen server, and trusted
labels/hashes. Discovery creates no visited-network list, timestamps, SSIDs, BSSIDs,
or location records. Removing the chosen server disables its Wi-Fi automation.

Focused verification: a real isolated WireGuard pair delivered all eight quality
probes and reported unavailable with ICMP blocked. Rust policy checks cover
packet loss over apparent speed, hysteresis, idle/protection gates, bounded
rollback with recovery disabled, schema preservation, explicit trust and its
privacy constraints. Desktop native and TypeScript checks pass. Full physical
Wi-Fi roaming and release-artifact acceptance remain part of the final platform
matrix.
