# Connection state and scrolling refinements — 5 September 2026

This pass keeps the existing Inter typography, navigation, title bar, thin window border, and device/VPS metric separation. It fixes protection presentation, recovery-page scrolling, startup-state visibility, and measurement details. Changes remain in the working tree for review.

## Protection evidence

The helper already compared the complete owned nftables `inet` guard against its expected ordered rules and published an observation that expires after 15 seconds. That guard covers IPv4, IPv6, and DNS, subject to the explicit LAN, selected-route, tunnel-interface, and reconnect-endpoint exceptions. The frontend ignored this evidence when displaying IPv6 blocking and always used the old “enforcement unverified” wording.

The shared protection presenter now uses the fresh helper observation and acknowledged policy. It reports verified blocking only with that evidence, describes routing exceptions, and exposes missing IPv6 verification beside the main protection status. Configured IPv6 tunnel routing is described separately from firewall verification. System health uses the same evidence. An unavailable/stale monitor does not become an armed policy or a disabled one.

A real interface-loss edge case was also corrected: when the interface disappears between monitor samples, a still-fresh, verified guard is reported as **Blocking traffic**, including IPv6, rather than **Armed**. Helper protocol 12 includes this change. Connection request schema 7, stored preference schema 2, root intent schema 2, and runtime schema 3 retain their existing semantics.

Packet tests applied the production rules in disposable containers with no host or VPS network connection. The final guard run passed **247 packet checks**, covering IPv4/IPv6, UDP/TCP DNS ports, LAN exceptions, selected routes, marked reconnect endpoints, deliberate release, actual interface removal, and restoration from root-owned boot intent. Across 30 rule updates, **1,157,564 continuous IPv4/IPv6 probes observed zero escapes**. Tests also retained an unrelated firewall table. These observations verify the tested packet paths; they do not certify every protocol, DNS resolver, or system boot sequence.

Existing state-machine tests still cover all four kill-switch/reconnect combinations, initial transport selection, retries, manual resume/disconnect, migration, service/helper failure, key rotation, and server switching. Their service and tunnel operations are doubles; the packet tests exercise the kernel separately.

## Saved preferences and startup

Home, Connection settings, and System health distinguish **Not active · enabled for next connection**, **Disabled**, **Armed**, **Blocking traffic**, failed enforcement, and unknown status. Saved choices cannot overwrite the displayed active policy merely by selecting another server or editing a setting. The disclosure is now named **Current status**.

Startup service enablement is observed through a read-only systemd query, independently of the saved checkbox. A disabled service is distinguished from an unreadable/missing service; enabling a service is not represented as proof that a reboot will connect successfully. The app can make this observation with an older installed helper without changing it. Queries have a two-second deadline, and native status work runs off the UI thread.

When startup is saved but inactive, Settings shows **Not active** and an explicit **Connect & activate startup** action. This starts the existing connection flow, uses saved preferences, and reports failure instead of claiming success. It does not invent a remembered cause for the pause: no manual-disconnect history is stored. A startup service whose server cannot be established is labelled accordingly.

**Manual Disconnect is unchanged:** it releases the owned block, stops automatic recovery, and cancels boot intent until another explicit connection. Saved switches stay saved. Closing to tray or quitting the GUI continues to leave the VPN running. No post-Disconnect lockdown or new preference migration was introduced.

## Layout and measurements

- Wide desktop windows have one fixed application frame and an independently scrolling main content pane. The sidebar and title bar stay stationary. Sticky settings tabs and keyboard-focus scrolling use that pane; narrow/mobile layouts retain page scrolling.
- Home loses a small amount of connection-block spacing, including an old short-window rule that actually enlarged it. At 1220×780 the ordinary connected summary fits with LAN access and protection enabled. Font sizes are preserved; technical details still scroll naturally.
- Tunnel duration includes seconds (`00:24`, then `1:00:01`). VPS uptime keeps its day/hour/minute format. Packet counts use English numeric grouping (`160,292`) even on a Turkish locale; identifiers are unchanged.
- Disconnected Devices offers **Open Home**. Disconnected VPS metrics offer a connection action; active/unknown states retain useful status refresh. CPU percentages are captioned **CPU usage**.
- Device menus intercept outside taps and temporarily disable covered row-detail controls; dismissal restores those controls and keyboard access. This fixes the partially covered fingerprint action found by the accessibility pass.
- DNS copy distinguishes live status through the VPN management connection from configuration through verified SSH. Maintenance prerequisites remain enforced.

The server activity collector was verified with two actual WireGuard peers inside a disposable network environment: **0 active before a handshake, then 1 of 2 authorized peers active**. Removing an authorization excludes it from the count; a missing peer reading remains unknown. “Recently active” still means a handshake within three minutes, not continuous presence. The server sends an additive capability field so the frontend can distinguish an older VPS from a failed current reading and offer an update or health review. No new counters, timestamps, or activity history are persisted.

## Validation and delivery

Rust workspace and updated desktop/helper tests passed, including all independent-policy combinations. The source inventory is 352 first-party files / 84,957 lines, with zero files over 1,000 lines. Across the workspace and updated helper/desktop runs, 298 distinct Rust tests passed. The final frontend suite has **79 passing tests**. Clippy with warnings denied, formatting, production frontend compilation, privacy checks, and the maintainability gate passed.

Native WebKitGTK checks passed at 100% and 125% on private KWin outputs, including unchanged font loading and the stationary recovery sidebar. Browser checks exercised wheel/keyboard scrolling at 958×620, connected Home at 1220×780, English numbers on a Turkish locale, 200% text, unavailable protection evidence, saved versus inactive startup, and maintenance gates. The broader operational browser pass also covers 200% text on Home, Devices, Settings and Servers, long mobile device names, action menus, and server switching, with zero automated accessibility findings in the final run. Seven native Wayland window/storage checks passed, including close-to-tray, reopening, and preference persistence across process exit. These UI tests use synthetic server responses, not live VPN measurements.

The [evidence manifest](audit/2026-09-05/state-reliability.json) records the validation results, source inventory, and rebuilt Linux binary, Debian package, and AppImage hashes. The rebuilt [AppImage](../target/release/bundle/appimage/SirinVPN_0.1.0_amd64.AppImage) and [Debian package](../target/release/bundle/deb/SirinVPN_0.1.0_amd64.deb) are available. Quit and reopen the application to load the rebuilt UI; closing to tray does not reload it. The updated helper is bundled for the existing component-update flow. Neither the installed helper nor the live VPS was upgraded during testing, and the user's active VPN, firewall, and desktop settings were left untouched. Android's native capability boundaries remain unchanged; this pass targets desktop delivery.

## Completion and next step

The original overhaul acceptance checklist remains **23/24 = 95.8%**. This is checklist completion, not a percentage of all possible product features or a security guarantee. This pass closes the requested implementation refinements; it does not close the remaining release-qualification item.

The next milestone is a disposable VM/VPS qualification run covering actual systemd boot ordering, reboot with each supported policy, helper upgrades/restarts, established-session failure across every transport, DNS/IPv6 under physical-network changes, management outages, and interrupted recovery. Apply the bundled helper/server updates through their existing reviewed workflows when ready; an older running VPS cannot acquire the new activity-reporting behavior from a frontend update alone. Previously documented platform gaps and dependency warnings remain tracked in the [policy audit](connection-policy-audit-2026-09-05.md).
