# Remaining product implementation

Working checklist for completing the remaining scope in the product prompt. Full
acceptance testing follows implementation; focused checks run with each change.
Existing live VPN sessions and VPS installations are not test fixtures.

- [x] Member device limits, expiration, schedules and delegated permissions
- [x] Reusable and scoped invitations; member invitation policy
- [x] Recovery key, encrypted recovery package and administrator recovery policy
- [x] DNS split zones and resolver/upstream diagnosis
- [x] MTU discovery, suggestion and manual override
- [x] Current transport quality, safe optimization and network trust policy
- [x] Transport camouflage and restrictive-network behavior
- [x] Configurable ports, alternate endpoints and endpoint catch-up
- [x] IPv6 outer endpoints
- [x] Installer NAT/address discovery and conflict report
- [x] Signed VPS updates, compatible rollback and opt-in security updates
- [x] Linux application routing where supported
- [x] Android QR, persistent transports, roaming, split routing and administration
- [x] Android opt-in Wi-Fi automation and current-network optimization
- [x] Windows service, secure storage, networking, firewall and packaging
- [x] Windows selected-executable routing, persistent account-scoped guard and kernel-driver integration
- [x] AppImage signed baseline, atomic replacement and compatible rollback
- [x] Android signed baseline, native APK verification and system installer coordination
- [x] Current-condition diagnostics across network, authentication, DNS and MTU
- [x] Rebuild deliverables and update the feature/evidence documentation

Conditional features (QUIC, bandwidth limits and domain-derived routes) require a
concrete benefit and reliable enforcement. The privacy requirement excludes
activity history. Production signing and platform acceptance require explicit
evidence and must not be inferred from compilation.

See the [8 September completion record](feature-completion-2026-09-08.md) for the
new features and fresh build evidence. Windows application routing requires
publisher kernel signing before normal Windows can enable it. Compilation and
policy tests do not establish native driver or APK installation acceptance.
