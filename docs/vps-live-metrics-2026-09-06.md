# Live VPS overview

The desktop now subscribes to `/v1/status/stream` once while connected. The VPS
sends authenticated SSE readings at a one-second sampling interval. The overview
shows a steady **Live** indicator, without an age timer or manual refresh button.
Local tunnel checks continue independently and do not restart the VPS stream.

Each subscriber retains only its previous CPU/network counters. Streams use the
existing pinned TLS 1.3 connection and client certificate. Access is rechecked
before every reading, including after host collection; revoked devices lose their
existing stream. Collection stops when its response is dropped. Host commands and
client reads have deadlines. No metrics history is stored.

The native client reconnects with bounded backoff after EOF, a stalled reading, or
a connection failure. Disconnect, server switch, unknown local status, and view
cleanup cancel the subscription; late callbacks cannot restore metrics or access.
Push readings do not provide request latency, so that field is only shown when a
snapshot request actually measured it.

Streaming requires the updated VPS server binary as well as the desktop app.
Older servers returning 404/405/501 keep automatic four-second snapshot updates,
labelled **Automatic updates**, with a note about updating the VPS. The client
checks for streaming support again after 30 seconds. Authentication and protocol
failures do not trigger this compatibility fallback.

Validation: frontend production build and 94 UI tests; 30 native desktop tests;
40 core and 43 server tests (the pre-existing disposable-network test remains
ignored); browser stream checks and existing state/layout checks. Coverage includes
fragmented SSE over TLS past the normal eight-second request deadline, protocol
and size limits, revocation, disconnect/switch/unmount races, automatic recovery,
and old-server fallback. Browser checks use synthetic native channel readings;
no deployed VPS was changed.

Tunnel duration now advances every second from a monotonic local observation
timestamp. New helper readings correct the reported duration independently of
the VPS stream. Disconnect, unknown state and a new counter epoch stop or reset
the clock. Readings older than 15 seconds become unavailable until a fresh local
observation arrives, so a suspended app or stalled helper cannot leave an
unverified duration counting indefinitely. Rates still come from local counters.

The Linux desktop remembers explicitly verified SSH fingerprints in a private,
atomic `ssh-host-keys.json` store under its configuration directory. Trust is
scoped to host and port, survives restart, and is shared across repair/update,
backup, restore and uninstall flows. A matching fresh probe skips the fingerprint
screen. New and changed keys require explicit verification; confirmation probes
again before saving, and every actual SSH operation still checks the pin before
authentication. Successful new installations remember the verified key as well.
Existing profiles require one final verification because earlier versions did
not retain this information. Only current public pins are retained, without
credentials, timestamps or operation history. Destructive uninstall confirmation
and restore replacement consent remain in their existing flows.

Delivery was checked against the files the user launches, not just a native
`cargo check`: `target/release/sirinvpn-desktop`, the Debian package and the
AppImage were rebuilt. Each desktop payload contains the exact current production
UI plus the SSH trust and stream commands. Both packages contain a byte-identical
streaming-enabled server payload. Verification hashes are recorded locally in
`.cache/status-stream/build.json`. Fully quit the desktop, including its tray
process, and reopen the rebuilt executable or AppImage. SSH trust and the duration
clock are desktop changes and do not require another VPS update.
