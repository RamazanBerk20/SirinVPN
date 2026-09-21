# Desktop layout and performance — 13 September 2026

The seven screenshot corrections are implemented with the existing palette, typography, and controls. Performance work reduces unnecessary React updates and suspends UI monitoring while the window is hidden. Native VPN operation, tray controls, Wi-Fi automation, and protocol interfaces are unchanged.

## Layout

- Active invitation headings retain left alignment, with vertically centered icons, title, count, and chevron. Removed the extra 20px top padding. Metadata contains only the role and expiry; additional-device invitations use the associated member's role, including Owner when applicable. Cancellation permissions are preserved.
- Added 16px between server search and results, 12px below the Wi-Fi preference divider, and 8px above the unavailable-metrics Connect button.
- Onboarding copy and form align at their tops. The landscape is anchored below the left-hand copy, with a viewport-sized decorative layer; the ambient background uses viewport coordinates. Loading messages, errors, and authentication changes no longer move the left content or landscape. Document scrolling remains available.
- The SSH verification key and heading share a row, with a 12px gap. The numbered instructions start 16px below the fingerprint. Back, copy buttons, warnings, and the fingerprint confirmation remain available.

## Runtime changes

The observation timestamp produced by every local traffic sample was included in the connection-control comparison. Consequently, traffic-only readings replaced application-wide state even though a dedicated traffic store already existed. That timestamp now stays with the traffic measurements; changes to connection state and protection still update the controls immediately.

Hiding the window now cancels both local and remote UI subscriptions, resets the traffic sampling anchor, and stops the tunnel-duration clock. The legacy local polling fallback also pauses. Returning starts local observation immediately and waits for a fresh local server identity before subscribing to remote status; late remote events cannot restore stale readings or authority.

Wi-Fi settings stop their UI polling timer while hidden and refresh immediately on return. Reads from before a visibility change are discarded, overlapping reads are avoided, and in-flight preference saves can finish. A changed network still requires explicit review before trust. The native automation loop continues independently.

The catalog fixture now implements the current local subscription API and clears its initial delayed publications on cancellation, allowing the existing production UI to be exercised accurately.

## Measurements

Artifacts and reproducible local review scripts are under [`target/ui-polish-2026-09-13`](../target/ui-polish-2026-09-13/). The `before/src` snapshot preserves the starting frontend, including the work already in the checkout.

The connected-Settings measurements use minified production catalog bundles, Chromium, a fictional connected VPS, and explicitly simulated document visibility. Each state has three 60-second samples. Counts below are per minute; timings are medians. These are UI measurements, not VPN throughput benchmarks.

| Measurement | Before | After |
| --- | ---: | ---: |
| Visible Settings: React commits | 162 | 72 |
| Visible Settings: local traffic publications | 120 | 120 |
| Visible Settings: remote publications / Wi-Fi reads | 30 / 12 | 30 / 12 |
| Visible Settings: renderer task time | 0.168s | 0.060s |
| Hidden Settings: remote publications | 30–31 | 0 |
| Hidden Settings: Wi-Fi reads | 12 | 0 |
| Hidden Settings: React commits | 42–43 | 0 |

The visible commit count falls by **55.6%**, while visible observation frequencies remain intact. The fixture's hidden state produces no UI status work after cancellation. The fixture records messages, so its uncollected heap totals must not be interpreted as production memory growth.

Native measurements use optimized Rust release builds with the WebKit inspector enabled, isolated empty profile stores, and private virtual Wayland sessions. Native helper status reads are real and read-only. Three 60-second samples cover each visible/hidden state; baseline hidden samples use a separate process. The window is actually closed to the tray and `document.hidden` is verified. Median visible process-tree CPU was 0.880% before and 0.332% after, expressed relative to one CPU core. Hidden CPU was already low: 0.050% and 0.033%. Shared-host activity and short-lived helper processes limit the precision of these CPU totals.

Initial sequential native startup and RSS readings varied between virtual sessions. A follow-up alternated five launches of each version in the same compositor:

| Native follow-up | Before | After |
| --- | ---: | ---: |
| Median observed input-readiness upper bound | 901ms | 899ms |
| Observed readiness range | 873–1344ms | 829–1133ms |
| Median private process-tree memory (USS), after 2s | 280.48 MiB | 280.73 MiB |
| Median native status round trip, 20 reads | 12.87ms | 12.78ms |

There is no demonstrated startup, memory-footprint, or native-status latency improvement. Readiness includes inspector attachment and is an upper bound, not a first-paint measurement. Existing lazy loading, the 250ms SSH-login debounce, and native monitoring frequencies were retained. Performance samples cover the runtime optimization; the final decorative refinements were verified separately.

## Verification and limits

- Full frontend suite: **38 files, 177 tests passed**. The final lifecycle guard also passed the affected 17 tests. Production frontend type checking, bundling, and the Linux release desktop build passed (`pnpm exec tauri build --no-bundle`).
- Chromium layout review: 760×620, 759×780, 761×780, 1220×780, and 1600×1000. Native WebKitGTK review covers those sizes at or above the app's enforced 760px minimum. Checked 150% text sizing, horizontal overflow, spacing, heading alignment, and stable onboarding geometry through loading, wallet errors, and authentication changes.
- Keyboard disclosure toggling, both SSH copy controls, and verification gating passed. Twenty navigation/dialog cycles and thirty hide/show cycles completed without page errors or duplicate subscriptions. After the visibility cycles, a 5.5-second visible sample had 11 local publications, two remote publications, and one Wi-Fi read; the hidden sample had none.
- A separate 25-cycle review avoided retaining automation element handles: DOM nodes stayed at 441 and event listeners at 319. Post-GC JS heap rose from 5.95 to 6.42 MiB between cycles 5 and 25. This bounded review does not establish a long-term memory-leak guarantee or a memory reduction.
- No Rust source, public API, saved-data schema, live VPN configuration, or installed app was changed. Native throughput, deployed-VPS performance, and Windows behavior were not benchmarked.

The JSON records in `before/` and `after/`, `native-paired.json`, screenshots in `after/chromium/` and `after/native-layout/`, and build/test logs provide the detailed evidence. `measure_catalog.py`, `measure_native.py`, `measure_pair.py`, and `launch_native.py` preserve the local measurement setup; `layout_review.py`, `check_cycles.py`, and `check_heap.py` preserve the visual and interaction review setup. Their Python dependencies are installed in the artifact directory's isolated `venv`.
