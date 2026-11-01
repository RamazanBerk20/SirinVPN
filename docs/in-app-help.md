# In-app help: the “Can’t connect?” guide and the demo

Both parts run in the shared React interface, so desktop and Android behave the
same.

## “Can’t connect?” guide

### Where to find it

- **Home:** after a connection attempt fails, or while the selected server's
  tunnel is up without a working connection, **Can’t connect? Find out why**
  appears under the connect button.
- **Settings → VPS maintenance** (**Diagnostics** on Android): **Troubleshoot**,
  next to **Run diagnostics**.

### What it checks

Opening the guide runs the existing diagnostics once (`run_diagnostics`, the
same report as **Run diagnostics**). The guide then goes through eight causes in
this order, one step at a time:

| Step | Likely cause when | Ruled out when | Fix offered |
| --- | --- | --- | --- |
| Local network | the system reports no network (`navigator.onLine`) | the tunnel is up (`local_tunnel` passes) | none; the step explains captive portals |
| Name lookup (DNS) | the VPS resolver fails (`dns`, `dns_resolver_response`) | the VPS resolver answers, or the server address is an IP address | **Repair VPS configuration** (Owner) |
| Reaching your VPS | the tunnel fails with Automatic transport | the tunnel is up | **Move to a new address** / **Apply address update** |
| Blocked connection method | the tunnel fails while one fixed method is chosen | the tunnel is up | **Open connection settings** (choose Automatic); an Owner without CDN mode gets **Repair VPS configuration** to turn on HTTPS or CDN mode |
| Date and time | management fails the TLS handshake | management authenticates | none; the step says where to turn on automatic time |
| Device keys and enrollment | a key rotation is pending, the saved identity can't load, or the VPS rejects the device certificate | management authenticates | **Resume key rotation** or **Restore device backup** |
| Membership | the VPS rejects this device's current access | management authenticates, or this is the Owner, who can't be suspended | none; members ask the Owner |
| VPN service on the VPS | `server_process`, `interface`, `wireguard` or `server_ports` fail, or management times out over a working tunnel | management authenticates | **Repair VPS configuration** (Owner) |

Each step shows one of three states: **Likely cause**, **Worth checking** (no
evidence either way) or **Looks fine**. The guide opens at the first likely
cause, or else at the first step worth checking. Every message is a fixed
sentence from the `help` text catalog; the guide never shows the diagnostic
report's own text, raw errors or addresses. The logic is
`apps/desktop/src/features/connection/troubleshooting.ts`.

It only reads checks whose result is real evidence (`diagnosticGroup` in
`components/diagnosticEvidence.ts`): a check that couldn't run is neither a
cause nor a pass. Remote checks reach it already sanitized by
`crates/core/src/diagnostics/remote.rs`. The management check's cause comes from
core's fixed `management_failure` messages; a unit test reads
`crates/core/src/diagnostics.rs` so that changing those messages fails the test
instead of silently weakening the guide.

While disconnected, the VPS can't be asked anything, so most steps stay at
**Worth checking**. That's deliberate: the guide doesn't guess.

Choosing a fix closes the guide and opens the existing dialog or settings page.
Repair and address moves still ask for their usual confirmations.

## Demo

**Explore the demo** on the first screen (shown while no server is saved) opens
the app with the sample server, devices and traffic from `tests/ui/fixtures.js`,
the same data the visual tests use. A banner, **Demo · Sample data only**,
stays on every page with **Exit demo**. It works for screenshots and for a first
look before setting up a VPS.

### Isolation

- **No backend calls.** Every app command goes through `invoke` in
  `apps/desktop/src/platform.ts`. In the demo, that function answers from the
  fixture and never calls the native bridge, so no profile, key, secret or VPN
  state is read or written, and nothing reaches the network. The Android status
  watch, the only other direct native call, is off in the demo. Window controls,
  the Android back gesture and the system file and confirmation dialogs still
  work; they carry no app data.
- **No storage.** The demo replaces the page's `localStorage` with memory, so
  demo settings and the fixture's saved preferences disappear on exit.
- **No shared page.** Entering and leaving the demo reload the interface. The
  flag lives in `sessionStorage`, so closing the app also ends the demo. Real
  and demo state never share a page load, and the real profiles are never
  loaded while the demo runs.

Tauri's bridge object is read-only in a real webview, so the demo takes the
fixture's command handler (via `window.__sirinDemo`) instead of letting the
fixture replace the bridge as it does in the visual tests.

Actions the fixture doesn't cover, such as exporting a backup, fail with an
error inside the demo. Setup in the demo never finishes.

## Tests

- `features/connection/troubleshooting.test.ts`: step order, likely-cause
  selection, fixes by role, checks that couldn't run, and the pinned core
  messages.
- `features/connection/Troubleshooter.test.tsx`: the dialog opens at the
  likely cause, steps back and forth, hands off to a fix, and still works when
  diagnostics are unavailable.
- `demo.test.ts`: demo commands never reach the native bridge (desktop and
  Android), demo writes never reach the real storage, the real app never uses
  demo data, and entering or leaving always reloads.
