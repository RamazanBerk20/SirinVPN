# Overhaul acceptance checklist

Baseline: 2026-09-04, 66,519 lines across 101 source files; 18 source files over
1,000 lines. The complete local gate passed before modification, including 42 UI
tests. Scope: existing Linux and Android capabilities, server, libraries, CLI,
packaging, and operational tooling. The existing VPS must remain unchanged.

Each numbered item is one acceptance item. Completion requires recorded evidence;
blocked and partially completed items do not count as passed. Audit coverage is
reported independently from security confidence and release readiness.

## Audit (5 items)

1. Inventory first-party components, boundaries, and existing features.
2. Audit locked Rust, JavaScript, and Android dependencies against available advisories.
3. Review native trust, authorization, secrets, filesystem, subprocess, and networking boundaries.
4. Review frontend state, IPC, permissions, privacy, packaging, and operational scripts.
5. Record confirmed findings, fixes, regression evidence, and unresolved risks.

## Maintainability (5 items)

6. Extract UI features, shared components, state hooks, and platform adapters.
7. Divide styling by responsibility and introduce a coherent design system.
8. Decompose native monoliths while preserving exported contracts and state formats.
9. Split oversized tests by behavior and retain all existing coverage.
10. Update architecture and privacy checks; document remaining size exceptions.

## Experience and feature preservation (7 items)

11. Implement concept-aligned onboarding with pin confirmation, install, join, and recovery.
12. Implement responsive Home and server selection with real connection states and metrics.
13. Retain transport, protection, routing, LAN, DNS, and private-record configuration.
14. Implement Devices with existing invitations, roles, ownership, peer access, and forwarding.
15. Implement Settings with existing backups, migration, repair, removal, rotation, and manual releases.
16. Apply the visual system to Android enrollment, backup, native VPN, and persistence flows.
17. Validate accessibility, reduced motion, small/large layouts, safe areas, and error states.

## Verification and delivery (7 items)

18. Pass the complete local gate and targeted regression tests.
19. Build Linux packages and inspect their payloads.
20. Build the Android APK and verify its manifest and embedded server architectures.
21. Pass Android native instrumented tests on Pixel 10.
22. Exercise isolated server provisioning, transport/privacy failures, and rollback scenarios.
23. Capture and review frontend screenshots on desktop and Android.
24. Deliver the audit report, exact completion calculation, evidence, and prioritized next steps.

## Compatibility requirements

Preserve Rust exports, Tauri command payloads, CLI behavior, existing state schemas,
identity binding, native authorization, and interrupted-operation recovery. Do not
add unsupported concept settings, other platforms, telemetry, activity history,
external visual assets, or automatic release checks. Tests of destructive operations
must use disposable resources and must never target the existing VPS.

## Final acceptance record

Completed 2026-09-05 (Europe/Istanbul). **23 / 24 = 95.8%.** Item 22 remains
partial and receives no completion credit. The [audit report](audit-2026-09-04.md)
and its evidence manifest distinguish automated checks, native emulator checks,
disposable integration runs, and remaining release qualification.

| Item | Status | Evidence |
| --- | --- | --- |
| 1 | Pass | Source inventory and feature map |
| 2 | Pass | Cargo, pnpm, and resolved Maven audits; remaining Rust warnings recorded |
| 3 | Pass | Boundary review and F01–F06 in the audit |
| 4 | Pass | IPC/state review, privacy gate, manifests, Gitleaks, ShellCheck |
| 5 | Pass | Findings, corrections, tests, and unresolved-risk register |
| 6 | Pass | Focused UI components/controllers; `App.tsx` reduced to 338 lines |
| 7 | Pass | Component/theme sheets, local assets, responsive design system |
| 8 | Pass | Native module map, unchanged command registries and schemas |
| 9 | Pass | All 259 original Rust and 42 original frontend tests retained |
| 10 | Pass | Source-size gate, unused-local check, architecture and exception guidance |
| 11 | Pass | Provision/invite/recovery flows retained and restyled |
| 12 | Pass | Home/server selection, power actions, current-state metrics |
| 13 | Pass | Existing transport, routing, LAN, protection, and DNS controls retained |
| 14 | Pass | Devices, roles, invitations, ownership, peer access, forwarding |
| 15 | Pass | Maintenance/recovery dialogs and manual release checks |
| 16 | Pass | Android panels and real native enrollment preparation/recovery boundaries |
| 17 | Pass | Eight UI scenarios, keyboard/Back/overflow checks, reduced-motion CSS, automated WCAG scan |
| 18 | Pass | Final full local gate; two shell tests/twenty subcases; separate clean ShellCheck run |
| 19 | Pass | Debian/AppImage build, Debian executable ownership/identity/payload checks |
| 20 | Pass | APK build and compiled manifest/resource/both-VPS-payload checks |
| 21 | Pass | Six instrumented tests on Pixel_10 |
| 22 | Partial | Provisioning/listener/repair/rollback VM and offline package recovery passed; complete live transport/privacy fault matrix not run |
| 23 | Pass | Reviewed desktop/Android fixture screenshots and actual emulator captures |
| 24 | Pass | Audit, exact completion calculation, artifact hashes, and prioritized next steps |
