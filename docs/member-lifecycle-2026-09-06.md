# Member suspension and bulk revocation — 6 September 2026

Implemented the first feature slice from the [prompt gap audit](feature-gap-audit-2026-09-06.md): pause/reactivate a member and revoke every device of a member in one management operation. Device limits, schedules, reusable/scoped invitations and recovery-key authorization remain separate work.

## Behavior

The desktop's Devices page offers **Suspend member**, **Reactivate member**, and **Revoke all member devices** in that member's device action menu. The confirmation identifies the member and describes the effect on all devices. The same operations are available through the CLI:

```sh
sirinvpn server members SERVER_ID
sirinvpn server suspend-member SERVER_ID MEMBER_ID
sirinvpn server reactivate-member SERVER_ID MEMBER_ID
sirinvpn server revoke-member-devices SERVER_ID MEMBER_ID --confirm-revoke-all
```

Suspension removes all of the member's WireGuard and authenticated-relay authorizations, excludes their certificates from new management TLS connections, rejects requests from existing connections, closes their status streams, and removes their active peer-access and port-forward rules. Device identities, permanent tunnel addresses, peer flags and saved port mappings remain in current state. Suspended addresses stay reserved, preventing another member from receiving them. The interface labels these devices Suspended and their saved port mappings Paused.

Reactivation restores access for those same identities and saved settings. An already-running client may wait for its next WireGuard handshake or reconnect; this operation does not remotely restart the client. New device enrollment and ownership transfer to a suspended member are rejected.

Suspension cancels that member's pending additional-device invitations, enrollment retry receipts and prepared key rotations. Reactivation does not resurrect them. Other members' pending access remains unchanged.

Bulk revocation permanently removes the member, every one of their device authorizations, their port mappings and pending access. A returning person needs a new invitation. The Owner cannot be suspended or bulk revoked; transfer ownership first. An Owner can manage Admins and ordinary Members, while an Admin can manage only ordinary Members. Suspended Admins cannot reactivate themselves through an existing management connection.

Repeated suspension/reactivation to the current state is harmless. Repeating a successful bulk revocation after losing its response is also harmless. Read-only endpoint handoff sources reject all these operations.

## Implementation and compatibility

- `PATCH /v1/members/{member_id}/suspension` accepts the strict JSON body `{"suspended":true}` or `false`.
- `DELETE /v1/members/{member_id}/devices` requires the strict body `{"confirmed":true}`.
- Both return the authoritative current membership snapshot through the existing pinned management client. Authorization and role checks occur under the state write lock, including other management mutations that previously cached permission before waiting on that lock.
- The existing authorization transaction updates WireGuard, peer isolation and port rules before publishing the saved state and relay authorization set. A failed save attempts to restore the previous runtime projections. The isolated kernel test injects a real filesystem failure and verifies this restoration. This is not a claim of atomicity across every kernel or storage hardware failure.
- `member_lifecycle_enabled` advertises support in current configuration. Older servers omit it and both desktop native commands and CLI require a VPS update before performing these operations. No client profile migration is needed.
- Authorization stays at schema 1 while every member is active; schema 2 is required while any member is suspended. Old daemons reject schema 2 rather than silently restoring paused access. Schema 1 with a suspended member is rejected by current validation. Reactivating or removing the last suspended member returns the current state to schema 1. Do not manually lower the version to downgrade a server.
- Repair/uninstall identity checks and encrypted VPS backup/restore support the new schema. The release compatibility manifest advertises authorization schemas 1–2. Backup restoration preserves the suspension and device identities.

The only new persisted member metadata is a current `suspended` boolean, omitted when false. No action history, actor, reason or timestamp is stored. Suspended identities remain because reactivation depends on them; revoked identities are removed. Existing privacy boundaries and current-state backup rules continue to apply.

The kernel test also exposed and fixed an existing nftables parsing issue in generated port-forward rules. Matching the packet's TCP/UDP port before its connection-tracking original port supplies the protocol context needed by nftables. Both the old rejection and corrected rule were reproduced in the disposable test namespace; see the [Netfilter conntrack expression reference](https://netfilter.org/projects/nftables/manpage.html) for the underlying fields.

## Validation

- Server tests cover every member identity, retained addresses/settings, pending bootstrap and rotation cancellation, role boundaries, requests queued behind suspension, stream termination, explicit bulk confirmation, retries, handoff guards, private storage and encrypted VPS restore.
- `sh tests/network/run-member-lifecycle.sh` runs with Docker networking disabled and disposable network namespaces. Real IPv4/IPv6 WireGuard traffic stops for both suspended member devices while an unrelated member stays connected; the same device identities regain access on reactivation. It checks WireGuard peers, relay authorization, IPv4/IPv6 nftables sets, port rules, persisted state, restart projections, bulk deletion and rollback after a real write failure. Wrapped transport authorization is checked through the shared relay registry; this test does not claim separate live sessions for all three wrappers.
- Frontend tests cover current member selection, protected roles, unsupported servers, cancellation, duplicate actions, late replies after server/disconnect changes, failed requests, and old refresh results arriving after a successful mutation.
- `tests/ui/member_lifecycle_smoke.py` exercises the desktop controls and paused-forward display through synthetic IPC. Screenshots include the suspended and revoked states and the expanded menu within workspace bounds.
- Focused Rust tests, frontend tests/build, strict Clippy and the privacy scanner are part of delivery validation. The privacy scanner's existing allowlist was updated for the previous status-stream test's local TLS URL.

These checks use generated test identities. No real member was suspended or revoked, and the connected user's VPS and VPN session were not changed.

## Delivery

Final validation passed: 200 Rust tests across the affected packages and release compatibility code, 109 frontend tests, two Python checks, the explicit kernel lifecycle test, the browser smoke check, strict Clippy, workspace formatting, maintainability and privacy checks. The existing peer-activity kernel test was not rerun for this slice.

The release CLI/server and native desktop were compiled, and both Debian and AppImage packages were rebuilt. At 15:48 Istanbul time, extraction verified the current frontend JS/CSS and member-lifecycle native commands in all three desktop deliverables, and byte-identical updated server payloads in both packages. The helper executable remains the same build already used for the stable Direct UDP connection.

| Artifact | Location | SHA-256 |
| --- | --- | --- |
| Desktop | `target/release/sirinvpn-desktop` | `f72f35981992ce1dd358e47e830a0d9de0ea44081435cf6dea4cf890ca021ece` |
| VPS payload | `target/release/sirinvpn-server` | `b166bba23fd92b0e4f707453fb045388d7dd940ca690ef497d32827b5fb24314` |
| Debian package | `target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb` | `de6a6029d928ce36ff0eca3c97d91130973890f82d4177aacd6479f2334ffd8f` |
| AppImage | `target/release/bundle/appimage/SirinVPN_0.1.0_amd64.AppImage` | `538aae9e60f505b28451d61a02536ba7ab266f2bb0698cdf43f052e5893d9592` |

Fully Quit the running app, reopen the rebuilt desktop, and use **Update VPS software** once. Member actions appear after the connected VPS advertises the new capability. No VPS update was performed by the implementation tools.
