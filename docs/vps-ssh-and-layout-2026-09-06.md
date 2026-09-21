# VPS SSH login and layout follow-up — 2026-09-06

Initial setup and maintenance now explain how to verify a VPS host key: open the
hosting provider's browser console, run the supplied public-key fingerprint
command, and compare the displayed SHA256 value. The command is copyable and
reads only public SSH host keys. Previously verified keys continue to bypass
manual review unless the key changes.

Setup, update/repair, VPS backup, restore, and uninstall share a saved SSH login
form. Remembering is enabled by default and can be disabled for one operation.
A successful pinned SSH authentication saves the login to the OS credential
store before maintenance begins, so a later maintenance failure does not discard
it. The saved summary fills the username, port, and authentication method. Change
login and Forget login remain available. Saved passwords never return to the UI;
the operation resolves them natively and refuses a different host, port, or key.
There is no plaintext persistence fallback. Existing users must enter their login
once because earlier versions did not retain it. See `PRIVACY.md` for retention.

The desktop scroll container now places its initial spacing inside the page.
Sticky settings tabs therefore meet the title bar, without a gap exposing clipped
content. Compact copy controls no longer enlarge VPN-address and fingerprint
value rows; device facts align their text baselines.

Validation completed:

- Production frontend build and all 101 UI tests.
- All 36 native desktop library tests, 19 installer tests, and 59 helper tests
  (one existing kernel-only test requires a disposable privileged namespace).
- Existing status-stream browser smoke, including live metrics and trust checks.
- New `tests/ui/vps_follow_up_smoke.py`: saved credentials, setup verification help,
  settings scrolling at two laptop sizes, and measured text alignment.
- Full Linux packaging, followed by extraction and verification of the current
  compressed frontend assets and native commands in the executable, Debian
  package, and AppImage. Packaged VPS server bytes remain identical to the built
  server. Build receipt: `.cache/vps-follow-up/build.json`.

A Direct UDP fallback defect was reproduced using the observed Wi-Fi route:
NetworkManager changed its metric from 600 to 20600 without changing its gateway,
interface, or source address. The previous route fingerprint treated this as a
new network and required a new WireGuard handshake within 30 seconds, which
could cycle an otherwise healthy tunnel. All three new regression tests failed
on the old code, including the actual supervisor cycling Direct UDP.

The supervisor now fingerprints the preferred route's path, excluding metric,
route provenance, and lease countdown metadata. Metrics still determine which
route is preferred, so a change that selects another gateway/interface remains
a real transition. Existing lost-route and stale-handshake recovery tests pass.
NetworkManager documents its connectivity-related +20000 metric penalty in its
[configuration manual](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager.conf.html#connectivity-section).

The desktop also compares its packaged helper with the installed build when
starting, resuming, reconnecting, or switching a session. This delivers behavior
fixes even when the wire protocol remains compatible. Compatible helpers are
not updated merely to read status or disconnect. The normal OS authorization
flow applies to installation.

A read-only ten-minute administrator capture observed five healthy handshakes
on Obfuscated UDP and the increased route metric before the update.

After the user restarted the updated app and reconnected, live status confirmed
Direct UDP with 1,013 seconds of tunnel uptime, no recovery in progress, and an
armed kill switch. The installed helper matched the rebuilt binary byte for
byte. NetworkManager still reported limited connectivity and route metric 20600,
while the supervisor remained on its first connection attempt. The user also
reported uninterrupted internet access after the limited-connectivity notice.
This confirms the updated helper holds Direct UDP under the previously observed
route condition. No deployed VPS was changed by these tools.
