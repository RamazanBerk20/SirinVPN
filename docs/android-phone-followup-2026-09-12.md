> Historical report: this Android implementation was removed on 13 September 2026. See [reset record](android-reset-2026-09-13.md); these results do not validate a replacement.

Android follow-up, 12 September 2026

Invitation creation and redemption now ask for only Device Name. New access groups derive their internal member name from that value, while invitations for an existing group retain its identity and permissions. Device rows show the shared device name and access role. The redundant "Access group" row is removed from device details, keeping the internal member name out of the device identity display.

The later device-name consistency correction also removes the local-only "My computer" / "My Android device" alias for an "Owner device". Both the owner and other users see the shared saved name as the row title, with no duplicate "Saved device name" detail. The "This device" marker still identifies the current device. Nine device-list tests passed, covering local and remote views on both platforms. The Android update was installed and the desktop release rebuilt and restarted; artifacts are in `target/device-name-consistency/`.

The WireGuard backend, transport carriers, foreground notification, Quick Settings tile and recovery controller now run in Android's separate `:tunnel` process. The Tauri interface talks to a private service through Android Messenger, with same-UID checks and connection cancellation. Closing the interface cannot exit the process that owns the VPN. Successfully verified ordinary connections save encrypted running-session state; Disconnect clears that state. Android Always-on and traffic-blocking enforcement remain separate optional requirements.

Quick Connect remembers the last successfully verified connection. Its encrypted bookmark is separate from the running session, so Disconnect stops recovery while leaving the shortcut usable. Changing connection preferences or deleting the associated profile invalidates the shortcut. The ongoing notification shows the server, connection state, transfer rates and a Disconnect action. Connecting asks for notification permission; declining it does not prevent VPN consent or connection.

All platform icons now derive from the existing `apps/desktop/src/assets/sirin-mark.png`, the exact image confirmed by the user (SHA-256 `8e1c1f6c6bcacb12347284f252085b6f464b2dbdaea28478382b50418dc30bc2`). Android includes adaptive and themed launcher icons plus the same mark for its notification and tile. Desktop PNG, ICO, ICNS and Windows tile exports use that source as well. Run `python3 scripts/generate-app-icons.py` to refresh them. The script preserves Android exports in checked-in inputs even when Tauri writes them into its generated project, and `build.rs` synchronizes those inputs into each Android build.

Validation artifacts are in `target/android-phone-followup/`:

- 46 frontend test files, 221 tests passed, including single-name invitation submission and connection after notification refusal.
- 12 native Kotlin unit tests passed, including transfer-rate resets and elapsed-time calculations.
- Three Android instrumentation tests passed: encrypted bookmark/session lifetimes, mismatched bookmark rejection, and the private controller running in a different process with the same app UID.
- ARM64 APK built and installed on the connected Samsung SM-S936B (Android 16), preserving its enrolled profile. APK inspection checks native libraries, payloads, privacy flags, service process isolation and tile binding permission.
- The saved server connected with real traffic. The foreground connection notification and the added SirinVPN Quick Settings tile were observed. The native recovery service restarted after the subsequent icon APK update.
- The corrected launcher artwork was extracted from the final APK and visually checked against the confirmed source.
- The desktop release built successfully with `pnpm --dir apps/desktop tauri build --no-bundle`. The running desktop interface was restarted with that binary so its native window, tray and notification artwork use the updated exports.

Extended Samsung battery-management behavior, a full phone reboot and Windows runtime behavior were not exercised in this follow-up. Android's explicit Force stop is distinct from closing the app and is not overridden.
