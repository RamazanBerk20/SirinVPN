# Build and reproduce Android evidence

The tracked Android sources are in `apps/desktop/android`. The generated Tauri
project in `apps/desktop/src-tauri/gen/android` is an output, not the source of
truth. `scripts/prepare-android.py` reapplies the reviewed overlay.

## Toolchain used

Linux x86_64; Node 26.9, pnpm 11.3.0; Rust 1.97.1; Tauri 2.11.5 / JS API
2.11.1; React 19.2.8; Go 1.27.1; JDK 17; Gradle 8.14.3; AGP 8.11; Kotlin
compiler 1.9.25 (resolved runtime stdlib 2.0.21); Android SDK 36; NDK
30.0.16248370. Minimum API 29, target API 36. The universal APK contains
`arm64-v8a` and `x86_64`; acceptance suites execute on x86_64 emulators.

Install the matching SDK/NDK with Android's SDK manager, Rust targets
`aarch64-linux-android` and `x86_64-linux-android`, and project dependencies
with `pnpm --dir apps/desktop install --frozen-lockfile`. Set `GO_BIN` if Go is
not installed at `.cache/android-tools/go/bin/go`.

Build the two bundled VPS binaries before preparing the Android project:

```sh
docker build -f packaging/Dockerfile.server-payloads -t sirinvpn-server-payload-builder .
docker run --rm --cpus=2 --memory=4g --user "$(id -u):$(id -g)" \
  -v "$PWD:/workspace" -w /workspace \
  -e CARGO_HOME=/workspace/.cache/server-payload-cargo \
  -e CARGO_TARGET_DIR=/workspace/target/server-payloads \
  sirinvpn-server-payload-builder \
  cargo build --locked --release -p sirinvpn-server \
    --target x86_64-unknown-linux-gnu --target aarch64-unknown-linux-gnu

export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
export ANDROID_HOME="$HOME/Android/Sdk"
sh scripts/build-android.sh all debug
python3 scripts/check-android-package.py \
  apps/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

The build uses Gradle's existing development signing identity. It does not
generate or replace production signing credentials. `all release` selects a
release build; supplying and authorizing release signing remains a separate
distribution step. The delivered development APK is debuggable.

The package check verifies the actual native libraries, both ABIs, ELF LOAD
alignment of at least 16 KB, ZIP alignment, APK signature and exclusion of
named acceptance inputs. These checks do not substitute for running on a
physical ARM64/16 KB device.

## Emulator preparation

Create isolated API 29 and API 36 x86_64 AVDs. The exercised devices are
`emulator-5562` and `emulator-5560`, respectively. The test scripts reject
non-emulator serial numbers. Use a current Android System WebView: the pinned
frontend browser baseline is Chrome 111. The API 29 factory image shipped
WebView 74; tests installed the signed WebView/Trichrome 133 packages from the
API 36 image. A native explanation handles an older provider.

```sh
adb -s emulator-5562 install -r \
  apps/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
adb -s emulator-5562 shell wm size 320x640
adb -s emulator-5562 shell wm density 160
sh scripts/build-android-catalog.sh
adb -s emulator-5562 install -r \
  apps/desktop/src-tauri/gen/android/app/build/outputs/apk/androidTest/universal/debug/app-universal-debug-androidTest.apk
```

The catalog and instrumentation classes are in the separate test APK. They
are never packaged in the production application's assets or components.
The catalog disables WebView network loading and supplies fictional API data.
Accept Android VPN consent through its system dialog before native provisioning.
Native controls tests also require adding the SirinVPN Quick Settings tile.

## Isolated infrastructure

Administrative tests must use the disposable, loopback-only VM, never a real
user VPS. The fixture's private key and guest marker bind tests to that VM.
Its output directory must be new. The launcher enforces CPU/RAM limits and
removes the VM and temporary credentials after its bounded lifetime.

```sh
systemd-run --user --scope --quiet \
  -p MemoryHigh=3G -p MemoryMax=4G -p MemorySwapMax=0 \
  -p CPUQuota=150% -p TasksMax=256 \
  python3 tests/android/vps_lab.py \
    --output .cache/android-vps-new --duration 5400

# In another terminal, after fixture.json appears:
ANDROID_SERIAL=emulator-5562 python3 tests/android/provision.py \
  .cache/android-vps-new/fixture.json
```

The base VM is `.cache/debian-13-genericcloud-amd64.qcow2`; see `tests/vm/README.md`
for its acquisition and isolation rules. The native provisioning test verifies
the SSH fingerprint, installs through the real service and saves only sanitized
fixture identity/result metadata. It removes its private input after reading it.

`ANDROID_SERIAL` selects a test device. Native tests on the **same device** must
run sequentially. Catalog capture owns the visible screen; do not open another
Activity or install the test APK while it is capturing.

```sh
node tests/android/transports.mjs
node tests/android/lifecycle.mjs
node tests/android/controls.mjs
node tests/android/owner.mjs .cache/android-vps-new/fixture.json
node tests/android/quality.mjs .cache/android-vps-new/fixture.json
node tests/android/quality.mjs .cache/android-vps-new/fixture.json --rollback
node tests/android/dns-mtu.mjs .cache/android-vps-new/fixture.json
node tests/android/routing.mjs .cache/android-vps-new/fixture.json
node tests/android/resilience.mjs
ANDROID_SERIAL=emulator-5562 node tests/android/policy.mjs
ANDROID_SERIAL=emulator-5562 node tests/android/consent.mjs
ANDROID_SERIAL=emulator-5562 node tests/android/ui.mjs
ANDROID_SERIAL=emulator-5562 node tests/android/power.mjs
ANDROID_SERIAL=emulator-5562 node tests/android/reboot.mjs
ANDROID_SERIAL=emulator-5562 node tests/android/transitions.mjs
ANDROID_SERIAL=emulator-5562 node tests/android/native-flows.mjs
ANDROID_SERIAL=emulator-5562 node tests/android/camera-ui.mjs
ANDROID_SERIAL=emulator-5562 node tests/android/resources.mjs
# Only after all other VPS tests; this destroys the guarded disposable installation:
ANDROID_SERIAL=emulator-5562 node tests/android/uninstall.mjs .cache/android-vps-new/fixture.json

# API 29 compatibility test temporarily reverts only WebView, then restores 133:
ANDROID_SERIAL=emulator-5562 node tests/android/webview.mjs
adb -s emulator-5562 shell am instrument -w \
  -e class org.sirinvpn.client.VaultAcceptanceTest \
  org.sirinvpn.client.test/androidx.test.runner.AndroidJUnitRunner

# Requires an already-authorized Member profile; no server administration:
node tests/android/notification-denial.mjs
# Select that profile for Quick Settings first. Keep this evidence separate:
SIRIN_TRANSPORT_EVIDENCE=target/android-evidence/authorized-transports.json \
  node tests/android/transports.mjs --without-obfuscated-udp
```

Some suites deliberately require exactly one disposable profile, a connected
fixture, saved pinned SSH credentials or an existing fixture result. Read the
guard at the top of the named test. Policy/consent tests revoke authorization;
restore consent before subsequent connection tests. The maintenance
instrumentation action requires the same private fixture input as provisioning;
it exercises encrypted document round trips, repair and explicit replacement
restore through Binder. APK acceptance additionally needs signed higher-version
and unsigned dummy packages in `target/android-update-fixtures`; it **cancels**
the OS installation and never replaces the application with the dummy package.

Root in selected emulator tests observes kernel routes/TUN state or injects
faults; production VPN operation and traffic tests run under ordinary app UIDs.
A root-owned UI Automator dump must be removed after reboot before a shell-UID
dump can replace it. Reboot tests wait for a changed boot ID as well as completed
startup, avoiding a read of the previous boot's completion property.

## Presentation and regression

The current mobile redesign check captures 20 states at three display/text
configurations. It exercises enrollment choices, Home/details, settings pages,
server selection/actions/rename and Owner/Member device screens. It checks
horizontal overflow, fixture calls and history navigation, and saves a gallery
under `target/android-evidence/mobile-redesign`. Its profiles are fictional.
The older 552-scenario gallery predates this redesign.

```sh
sh scripts/build-android-catalog.sh
# Install its test APK on emulator-5560, then:
node tests/android/mobile-redesign.mjs
adb -s emulator-5560 shell am instrument -w \
  -e class org.sirinvpn.client.QrScannerTest \
  org.sirinvpn.client.test/androidx.test.runner.AndroidJUnitRunner
# Use a blank/default virtual-camera scene. Checks real permission denial,
# then camera open, Home/release, return/resume and Back/cancellation:
ANDROID_SERIAL=emulator-5560 node tests/android/camera-ui.mjs
# Disconnected isolated API 33+ emulator, automation off. Resets only emulator
# runtime permissions and the notification prompt marker; never a real endpoint.
ANDROID_SERIAL=emulator-5560 node tests/android/permissions.mjs
# Disconnected isolated API 33+ emulator with VPN consent and no existing PIN. Tests
# SystemUI actions with an idle foreground service; contacts no endpoint.
# Temporarily sets and removes an emulator-only PIN to check the lock guard.
ANDROID_SERIAL=emulator-5560 node tests/android/notification-shade.mjs
# Native notification formatting and fresh one-second samples. The emulator must
# be disconnected with notifications allowed. Uses synthetic counters, no endpoint.
adb -s emulator-5560 shell am instrument -w \
  -e class org.sirinvpn.client.NotificationTrafficTest \
  org.sirinvpn.client.test/androidx.test.runner.AndroidJUnitRunner
# Rebuild/install the catalog test APK first. Uses synthetic counter readings in
# the actual mobile UI to check duplicate events, idle, reconnect and recovery.
ANDROID_SERIAL=emulator-5560 node tests/android/traffic-sampling.mjs
# Isolated emulator with notifications allowed. Migrates an existing notification
# and checks all SirinVPN channels suppress launcher badges; contacts no endpoint.
adb -s emulator-5560 shell am instrument -w \
  -e class org.sirinvpn.client.NotificationBadgeTest \
  org.sirinvpn.client.test/androidx.test.runner.AndroidJUnitRunner

# Full historical scenario catalog (separate from the focused mobile capture):
node tests/android/capture.mjs
python3 scripts/android-parity.py \
  --capture-evidence target/android-catalog-evidence/results.jsonl
python3 scripts/android-parity.py --check

pnpm --dir apps/desktop test
pnpm --dir apps/desktop build
cargo fmt --all -- --check
CARGO_BUILD_JOBS=2 cargo clippy --workspace --all-targets -- -D warnings
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo test --workspace
python3 scripts/check-maintainability.py
python3 -m unittest discover -s tests/unit
sh scripts/check-privacy.sh

cd apps/desktop/src-tauri/gen/android
ANDROID_HOME="$HOME/Android/Sdk" JAVA_HOME=/usr/lib/jvm/java-17-openjdk \
  ./gradlew :app:lintUniversalDebug -x rustBuildUniversalDebug --max-workers=2
```

See `progress.md` for observed results and failures. In particular, presentation
captures do not prove server operations, traffic protection, native permission
flows, signature checks or physical-device behavior.

`QrScannerTest` uses deterministic synthetic QR data and the production camera
view/decoder configuration. It checks full-preview framing, supported HD size
selection and a 2,407-character code at the preview edge in both polarities.
It does not access the physical camera or a real invitation.

Capture import checks all image hashes, merges only presentation evidence and
generates a browsable HTML index. It never changes a scenario's runtime status.
`node tests/android/capture.mjs . --resume` skips a successful row only when its
bundle hash matches. Keep evidence in `target/`, not `/tmp`, across host reboots.
