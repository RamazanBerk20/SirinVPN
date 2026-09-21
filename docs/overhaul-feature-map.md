# Desktop feature map and Android reference

The desktop columns describe the source implementation as of 8 September 2026.
The current Android port has its own [feature matrix](android/features.md) and
[verification report](android/progress.md); historical Android evidence below
does not qualify the current implementation.
The earlier September 4–5 audits retain their historical evidence; their feature
counts and platform limitations do not describe this implementation. See the
[latest feature completion and build evidence](feature-completion-2026-09-08.md).
The recorded Linux acceptance applies to its named earlier builds; GUI and native
Windows acceptance are separate from source checks and compilation.

| Capability | Linux / Windows desktop and CLI | Android | Focused evidence |
| --- | --- | --- | --- |
| Pinned SSH installation and preflight | Implemented | [Current matrix](android/features.md) | [Preflight](installer-network-preflight-2026-09-06.md), [Android](android-integration-2026-09-07.md) |
| Four transports and bounded recovery | Helper / LocalSystem service | [Current matrix](android/features.md) | [HTTPS transport](https-transport-2026-09-06.md), [Windows](windows-integration-2026-09-07.md) |
| Kill switch, reconnect, startup | Independent policies | [Current matrix](android/features.md) | [Policy](connection-policy-audit-2026-09-05.md), platform documents |
| Selected IP/subnet routing and LAN policy | Implemented on both desktops | [Current matrix](android/features.md) | Platform documents and routing tests |
| Application routing | Linux explicit native launches; Windows selected executable/account rules, gated by signed WFP driver availability | [Current matrix](android/features.md) | [Linux application routing](linux-application-routing-2026-09-07.md), [Windows routing](feature-completion-2026-09-08.md) |
| Current quality and automatic MTU | Implemented, with protected idle comparisons and rollback | [Current matrix](android/features.md) | [MTU](mtu-handling-2026-09-06.md), [Quality/Wi-Fi](transport-quality-and-wifi-2026-09-06.md), platform documents |
| Opt-in untrusted-Wi-Fi connection | Desktop automation with explicit trusted fingerprints | [Current matrix](android/features.md) | Quality/Wi-Fi and platform documents |
| DNS upstreams, records and split zones | Provisioning / Network settings / repair | [Current matrix](android/features.md) | [Split DNS](split-dns-2026-09-06.md) |
| Roles, devices, peer policy, IPv4 forwards | Implemented | [Current matrix](android/features.md) | [Member lifecycle](member-lifecycle-2026-09-06.md), Android document |
| Limits, UTC schedules, delegated access | Implemented | [Current matrix](android/features.md) | [Policies and invitations](member-policies-and-invitations-2026-09-06.md) |
| Reusable invitations and QR enrollment | Signed sharing / paste | [Current matrix](android/features.md) | Policies/invitations and Android documents |
| Device and VPS encrypted backups | Implemented | [Current matrix](android/features.md) | Shared backup tests and Android document |
| Recovery keys and owner recovery | Implemented | [Current matrix](android/features.md) | [Owner recovery](offline-owner-recovery-2026-09-06.md), Android document |
| Device key rotation and signed endpoints | Implemented | [Current matrix](android/features.md) | [Endpoints and outer IPv6](endpoints-and-outer-ipv6-2026-09-06.md), Android document |
| Signed VPS update / rollback / repair | Implemented | [Current matrix](android/features.md) | [VPS updates](signed-vps-updates-2026-09-06.md) |
| Signed app update | Debian and Windows coordination; user-owned AppImage atomic replacement and compatible signed rollback | [Current matrix](android/features.md) | [Client updates](feature-completion-2026-09-08.md), [Releases](releases.md) |
| Current diagnostics while disconnected | Desktop dialog and CLI | [Current matrix](android/features.md) | [Current diagnostics](current-diagnostics-2026-09-07.md) |
| Local notifications, tray and startup | Native desktop integrations | [Current matrix](android/features.md) | [Notifications](notification-branding-2026-09-05.md), [Tray](tray-controls-2026-09-05.md), Windows document |

Features are gated by native capabilities and current authorization. UI state is
not an authorization boundary. Changing saved connection preferences does not
silently change a running tunnel. No geolocation, activity timeline, traffic
history or fabricated health result was introduced.

Tests and package inspection are evidence for the exact behavior they exercise.
Windows driver/firewall operation and full migration/update fault acceptance
still require native qualification. Current Android coverage for platform
policy, restrictive networks and recovery is recorded in its verification report. See the [implementation checklist](remaining-implementation-2026-09-06.md).
