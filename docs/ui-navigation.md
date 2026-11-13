# How the app is organised

The basics come first on every page: connect, the server you use, your devices,
protection and recovery. Owner and Admin power features sit one level down,
under **Advanced**, at most two steps from the page they belong to. A first-run
Owner or a Member sees the basics without scrolling past forms they will never
use. This replaced a layout that showed every feature at the same level (2026-11-03).

## One place for each job

| Job | Desktop | Android |
| --- | --- | --- |
| Connect and see the state | Home: the status card is the focus | Home |
| Switch servers | the sidebar's **Servers** list, with a search field from six servers | Home: the **Server** row opens a sheet |
| Manage servers (rename, favorites, maintenance, add) | sidebar → **Manage** (the Servers page) | the **Servers** tab, or the sheet's **Manage servers** |
| Add a device, for yourself or anyone else | Devices → **Add device** (or a person's **Add device for …**) | the same |
| A device: name, network, port forwarding, removal | Devices → select the device (its panel) | the same, full screen |
| A person: name, role, limits and permissions, suspend, remove | Devices → select the person's name (their panel) | the same, full screen |
| Protection: method, kill switch, reconnect | Settings → Connection | Settings → Connection |
| Recovery: recovery key, device and VPS backups | Settings → Keys & recovery | Settings → Keys & recovery |
| Health, diagnostics, VPS update and repair, remove | Settings → VPS maintenance | Settings → Diagnostics |
| Auto-connect on untrusted Wi-Fi, trusted networks | Settings → General → Wi-Fi auto-connect | Settings → General → Wi-Fi auto-connect (not on Android TV) |

Wi-Fi auto-connect behaves the same on both: it connects once per Wi-Fi network
that isn't trusted, never disconnects, and after a Disconnect waits until the
network changes. Android adds a notice in that card when Location, precise or
"all the time" location access, or battery use stops it from recognising trusted
Wi-Fi, with the one button that fixes it. See
[Android Wi-Fi auto-connect](android/security-and-platform.md#wi-fi-auto-connect).

The desktop's primary navigation is Home, Devices and Settings: the sidebar's
server list already is the servers section, so a Servers item beside it only
repeated it. The Servers page outlines the selected server and says that switching
happens in the sidebar; on that page the sidebar's **Manage** button is marked as
the current place. A window 760 px wide or narrower hides the sidebar and shows a
bottom bar with **Servers**; there each other server's row has **Switch**, and the
page's hint says so. Home names the server once, in its title. The server address moved
to Device details, and the status card says "Connected" without repeating the
name. Android keeps its four tabs: a phone has no sidebar.

## The Advanced level

| Feature | Where |
| --- | --- |
| Port forwarding | Devices → the device's panel → Network |
| VPS alerts | Settings → Advanced (Owner) |
| Scheduled VPS backups | Settings → Advanced → Automatic VPS backups (Owner) |
| Device key rotation | Settings → Advanced. An unfinished rotation also stays in Keys & recovery and on Home. |
| WireGuard configurations | Devices → Add device → “How will it connect?” → WireGuard app (desktop) |
| Device-to-device access, device pairs, local networks | Devices → the device's panel → Network |
| Creating a Hetzner server | Add a server → Advanced (the row says it holds Hetzner Cloud) |

On Android's settings index the Advanced row lists what that role finds there.
Settings → Advanced also says that device network features, port forwarding
included, are on each device's panel in Devices. Release sources stay in the update dialogs: SirinVPN ships
no built-in address, so the first check needs one, and a saved source shows as
one line with **Change**.

## By role

- **Members** see no VPS resource stats, which they can't act on. The desktop
  Home has no server health row, and Android's Connection details has no Server
  group; Android's Home keeps its Server picker row for every role. Their
  Advanced page holds key rotation; port forwarding, when their permissions
  allow it, is on their device's panel in Devices.
- **Owners and Admins** see one compact server row under Home's status card:
  CPU, memory, storage, uptime and active devices. The used and total amounts
  are under Server details. This device's traffic is one strip, not three tiles.

## Devices

Redesigned 2026-11-12, after the Owner found the tab confusing: **Add device**
mostly created members, and five words named the same role.

- **One word per thing.** People have a role (Owner, Admin, Member) and devices.
  A join code brings a device, for a new person or an existing one. See the
  terminology in [Interface text](ui-text.md#terminology).
- **The page** lists devices grouped by person. **My devices** comes first and
  marks **This device**; then the Owner, Admins and Members. Each group shows the
  role, Suspended and limit chips and the device count. Each device row says in
  one line what the device can do (app, device-to-device access or pairs, shared
  networks, forwarded ports) and its activity, with one rule for every device.
  Codes not yet used are listed under **Waiting to join (N)**.
- **Add device always adds a device**: one wizard asks whose device it is
  (Mine, someone already here, Someone new with a role and, for a
  Member, limits and permissions; the person joining chooses their own name and
  their device's name, except on older servers that can't let them), how it connects (SirinVPN app, or the
  WireGuard app on the desktop), then hands over the join code and follows it
  until the device joins, the code expires or is cancelled. A person's group has
  **Add device for …** with the person chosen. Options the caller can't use are
  absent; with nothing to offer, the button is replaced by one line saying why.
- **One place per thing.** Selecting a person opens their panel: name, role
  (with **Make Owner…**, which lets the Owner pick the receiving device), their
  devices, **Limits and permissions**, and Suspend or Remove person. Selecting a
  device opens its panel: name, owner, connection, address, activity, the
  Network section (device-to-device access, pairs, local networks, port
  forwards) and Remove device. There are no ⋯ menus.
- **Couplings are said where they bite**: a role change while a join code waits
  offers to cancel it first; saving limits says how many waiting codes it cancels.
- **Weekly hours** are a grid in the viewer's local time, stored as the UTC
  windows the VPS expects.
- **Disconnected**, the page shows the last list read in this session, read only
  and dated, with **Connect**; with nothing read yet, this device alone.
- **For tests and agents**, the page root and the wizard carry `data-state`, and
  the main actions a `data-testid` (`add-device`, `add-device-for`, `open-person`,
  `open-device`, `wizard-next`, `wizard-create`, `wizard-done`, `remove-device`,
  `remove-person`, `change-role`, `save-limits`, `make-owner`, `cancel-code`).
  The demo's people follow `sessionStorage["sirin.demo.role"]` (owner, admin,
  member); `sessionStorage["sirin.demo.future"] = "1"` adds the server features
  not released yet.

## Long operations

`OperationProgress` (`components/OperationResult.tsx`) takes `steps`: each
step is done, running or not started, for screen readers too.

- **Diagnostics** and the troubleshooter list the check groups they run: this
  device, the saved identity, and, while connected, the VPS and leak tests. The
  backend runs them together and returns one report, so the groups spin
  together.
- **Backup, restore, repair and uninstall** show the phases the app runs in
  order: confirm the VPS identity, run the operation, then refresh the status or
  remove the server here. Each phase ticks as it finishes.
- **Install** lists the checked identity and network, then the install itself.
  Its stages (connect, check, upload, configure) are one backend call, so they
  are one running step.

Showing each backend stage separately would need progress events from the
backend; the app shows only what it knows.

## Primary buttons

The platform difference is deliberate. The desktop's primary action uses the
cyan-to-magenta brand gradient from the logo. Android uses Material's flat
accent fill. Within each platform, every primary button looks the same:

- On Android, a selected segment or a button left in its hover state after a
  tap no longer turns into the desktop gradient.
- On the desktop, a disabled primary or danger button has one flat neutral
  fill everywhere. Before, pages showed an empty outline and dialogs a fill.

## Checking it

`tests/ui/catalog/full_capture.py` reaches the moved controls through their new
paths ([UI state catalog](testing.md#ui-state-catalog)). Both runs below used the
same harness, on desktop (1280×860) and Android (412×915) in dark and light; the
after run also renders a few states in the smallest desktop window (760×760),
where the sidebar is hidden. The original UI was served from `main` with
`tests/ui/catalog/serve_ui.sh`.

| | Before (`main`) | After |
|---|---|---|
| Scenarios | 670 | 682 |
| States captured | 2,302 of 2,302 | 2,336 of 2,336 |
| Audit findings (contrast, text under 12px, small targets, clipping, names) | 0 | 0 |
| English UI messages shown by some state | 1,604 of 2,157 | 1,654 of 2,201 |

The new states are the Advanced settings page for each role, the Add device
menu, a member's menu, Android's Connection details and settings index for a
Member, and the 760 px window's Home, Servers (before and after **Switch**),
Devices and Advanced; the expanded-device-rows state went away with the
expandable rows. `tests/ui/android_tv_dpad.py` drives the Devices sheets with a
D-pad. Four reviewers
compared every changed family before and after; their findings were fixed
before the final run.

In each image the top row is before and the bottom row is after; desktop dark
comes first in each row, then Android dark.

| | |
|---|---|
| Home: the status card leads; this device and the server are one strip each | ![](images/ui-navigation-2026-11-03/home-connected-home.webp) |
| Home for a Member: no VPS resource stats | ![](images/ui-navigation-2026-11-03/home-member-connected-home.webp) |
| Devices: one Add device button and one menu per row | ![](images/ui-navigation-2026-11-03/devices-owner-device-list.webp) |
| A device's Details dialog, from its menu | ![](images/ui-navigation-2026-11-03/devices-details-android-phone.webp) |
| Servers page: managing only; the sidebar switches | ![](images/ui-navigation-2026-11-03/servers-saved-server-list.webp) |
| Diagnostics while it runs | ![](images/ui-navigation-2026-11-03/diagnostics-run-diagnostics-in-progress.webp) |
| Install while it runs | ![](images/ui-navigation-2026-11-03/provisioning-password-install-in-progress.webp) |
