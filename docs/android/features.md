# Desktop → Android feature families

All 39 families are mapped in [scenarios.json](scenarios.json), with source/API
references, original images, roles, Android approach, captures, runtime evidence
and verification scope. The table describes implemented behavior; a passing
happy path does not verify an entire family. See [actual coverage](progress.md).

| Families | Android implementation and obtained evidence | Remaining scope |
| --- | --- | --- |
| onboarding, provisioning, join, owner-recovery | Shared onboarding; native installer/enrollment/recovery, protected entry, pinned-SSH Owner provisioning and Member/offline recovery | Every password/sudo/compatibility/interruption branch |
| home, servers | Shared server management and controller snapshots; selected/active/quick profiles separate; real lifecycle tests | Every multi-server/stale-profile branch |
| connection, measurements, protection, startup | Four carriers, quality selection/rollback, automatic MTU reduction, Android Always-on/lockdown/reboot | All restrictive-network, locked-boot and OEM cases |
| routing, dns, port-forwarding | Native routes/package selection, LAN policy, IPv6 containment; real app-UID routing, DNS/failure and port mapping | External IPv6 leaks and all DNS upstream/split-zone branches |
| devices, member-actions, member-policy, invitations | Shared authorization/UI; real rename, peer permission, invitations, enrollment and Member restrictions | Full delegation, schedules, revocation and ownership transfer |
| key-rotation, recovery-keys, device-backups | Shared transactions, Keystore, protected QR/SAF; policy-preserving rotation and encrypted round trips | Every interrupted/recovery-policy branch; camera decoding |
| endpoint | Signed migration/publication/checkpoints; invalid inputs retain the tunnel | Positive cross-address migration end to end |
| diagnostics, vps-backup, vps-restore, vps-repair, vps-updates, removal | Service-owned operations; backup/restore/repair and guarded uninstall exercised; shared release verification; [scheduled VPS backups](../scheduled-vps-backups.md) into a SAF folder while the app is open | Signed VPS update/rollback, diagnostics and interruption coverage; scheduled backups on a device |
| general, settings | Shared preferences; real draft/Back/font checks | Process-death draft restoration |
| wifi | Desktop-only: the Android app omits Wi-Fi auto-connect and requests no location permission | None |
| app-updates | Signed releases, APK package/version/signer checks, OS consent; rejection/cancellation exercised | Actual artifact download, replacement and reconstruction |
| compact-window, dialogs, tooltips | SirinVPN mobile styling, four destinations, insets/IME, touch help, Back guards; narrow/landscape/200% tests | TalkBack, split-screen, complete process-death restoration |
| native-confirmations, native-file-dialogs, native-selects | Native confirmation, SAF, package/permission controls; real protected entry/QR/share cancellation | Every confirmation/select and completed external sharing |
| native-notifications, native-tray | Service notification and real TileService; no desktop popup layer; Activity-free controls and notification-denial traffic; home-screen widget and permission-protected [automation intents](automation.md) on the same control paths | Locked authentication, blocked channels, competing VPN, every stale action; launcher-hosted widget on a physical device |

Executable arguments become package routing. Startup/tray settings become
Android VPN policy and native controls. SSH-agent login becomes a selected key
or password. AppImage/Windows installers become signed APK review and OS consent;
silent rollback/downgrade is not offered. Equivalent outcomes are claimed only
to the extent explicitly tested in each scenario row.

Android TV has no desktop counterpart. The app has a leanback launcher entry and
banner and requires no touchscreen. With a D-pad, the destinations lead the page
instead of floating over it, wide screens scroll the page, Home starts on
Connect, and sub-pages start on Back. `tests/ui/android_tv_dpad.py` checks
connect/disconnect, server choice and connection details with arrow keys and
Enter in Chromium with WebView's spatial navigation, not on a TV.
