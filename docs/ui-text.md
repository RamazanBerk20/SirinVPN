# Interface text and localization

All interface text lives in [`apps/desktop/src/locales`](../apps/desktop/src/locales).
English (`en`) is the source language. This guide covers how the text should read and
how code must use it so the app can be translated without code changes.

## How text should read

SirinVPN is a security tool, so text has to be calm, exact and short. People scan;
they read only when something needs a decision.

- **Say it once.** A fact appears once per screen. Don't repeat “applies on your next
  connection” under every control; put it once where it matters.
- **Lead with the outcome.** “Blocks internet if the VPN drops”, not “When enabled, this
  setting will cause traffic to be blocked in the event that…”.
- **Use the reader's words.** “Server”, “device”, “connection”. Implementation detail
  (coordinator, supervisor, baseline, handshake, ICMP) belongs in diagnostics only.
- **Plain, neutral tone.** Second person, present tense, active voice. No exclamation
  marks, no blame (“You entered an invalid…” → “Enter a valid…”).
- **Sentence case** everywhere: “Add server”, not “Add Server”. Role names (Owner, Admin,
  Member) and Android's own setting names are capitalized as proper nouns.
- **Ellipsis** (…) only for progress states (“Saving…”) and for buttons that open a
  further step that asks for input.
- Use the typographic apostrophe (’) and quotes (“ ”) in English text.

### Length limits

| Element | Limit | Notes |
| --- | --- | --- |
| Page or dialog title | 4 words | No final period |
| Button / menu item | 1–3 words, verb first | “Revoke device”, “Save name”. No final period |
| List row title | 4 words | |
| Row subtitle / setting summary | 1 line, ~60 characters | Fragment, no final period |
| Helper text under a control | 1 sentence, ~90 characters | |
| Expanded explanation (`InfoHint`) | 2–3 short sentences | Only when the summary can't carry it |
| Status line | 1 sentence | |
| Error | 2 short sentences | What happened, then what to do |
| Confirmation | Title is the question; body ≤ 2 sentences | Buttons name the action (“Revoke”), never “OK” |

Anything longer goes behind an `InfoHint` (an ⓘ button that expands the explanation
inline) or into documentation. Never stack more than one note paragraph under a control.

### Terminology

| Use | Avoid | Notes |
| --- | --- | --- |
| server | VPS (in everyday UI) | “VPS” only where the user administers the machine itself: VPS maintenance, VPS backup |
| connection method | transport | Options keep their names: Direct UDP, Obfuscated UDP, TLS fallback, TCP fallback |
| network conditions | network profile | |
| kill switch | traffic block, protection | “Kill switch” is the feature; “blocking” is its state |
| device | peer, client, identity | “identity” only for the cryptographic fingerprint |
| member, invitation | user, invite code | |
| this device | this phone / this computer | Unless the platform difference matters |
| VPN address | tunnel IP, client tunnel address | |
| Connected for | tunnel duration, uptime (for the device) | “Uptime” is for the server |
| recovery key, backup | recovery package, archive | |
| Always-on VPN, Block connections without VPN | | Android's own names, unchanged |

## Code rules

1. **Every visible string goes through `t()`** from `src/i18n`: JSX text, `aria-label`,
   `title`, `placeholder`, `alt`, `confirm()`/`prompt()` text, notifications and error
   fallbacks. Test files may use `t()` too, so copy edits don't break them.
2. **Keys describe purpose, not wording**: `devices.row.revoke`, not
   `devices.revokeThisDevice`. Format: `namespace.area.element`, camelCase segments.
   The namespace is the JSON file name.
3. **Never build sentences from pieces.** One message per sentence with `{{placeholders}}`:
   `"{{name}} was removed"`, not `name + t("wasRemoved")`. Translators need to reorder.
   Separators belong in messages too (`"{{role}} · {{status}}"`).
4. **Plurals** use i18next suffixes and the `count` parameter:
   `"devices_one": "{{count}} device", "devices_other": "{{count}} devices"` →
   `t("devices.summary.devices", { count })`. Never `"device" + (n === 1 ? "" : "s")`.
5. **Never use display text for logic.** Compare codes or enums, map them to text at the
   edge (`status === "reconnecting"`, not `label === "Reconnecting"`).
6. **Format values before inserting them.** Use `formatNumber`, `formatList`,
   `formatDateTime` from `src/i18n` or the helpers in `src/format.ts`. Ports, addresses
   and versions are inserted raw.
7. **Inline markup** uses `<Rich id="…" tags={{ strong: c => <strong>{c}</strong> }} />`
   with `<strong>…</strong>` in the message. Keep tags few and unnested.
8. **Leave room.** Translations run 30–40% longer. No fixed widths on text, allow
   wrapping, never truncate meaning-bearing text.
9. **Platform-specific text** uses separate keys (`…Android`, `…Desktop`) rather than
   inserting “phone”/“computer” into a sentence.

### Errors from the backend

Rust commands and the server return English error text. `errorMessage(error, fallback)`
shows that specific text when the interface is in English; in any other language it shows
`fallback`, the caller's localized summary of what failed. Always pass a fallback that
stands on its own (“Couldn’t save the backup. Try again.”). Backend messages follow the
same writing rules as interface text.

### Desktop tray and notifications

The tray menu, its dialogs and desktop notifications are drawn by the Rust shell, but
their text lives in `native.json` like the rest. Rust compiles in the English file as its
fallback and names keys as full string literals (`text("native.tray.menu.open")`), which
the catalog test also scans. At startup the interface sends the active language’s
`native.*` messages to the shell (`set_native_text`), which checks keys and placeholders
and then redraws the tray.

### Checks

`src/i18n/catalog.test.ts` verifies the catalogs: every key used in code exists, every
English key is used, placeholders and tags are well formed, plural groups are complete,
and translations use the same placeholders as English. It also rejects literal text in
JSX. In development builds, set `localStorage["sirin.locale"] = "en-XA"` and reload to
see the pseudo-locale: accented, ~35% longer text that exposes anything not
translated and any layout that clips.

## Adding a language

Copy `src/locales/en` to `src/locales/<tag>` (for example `tr`, `pt-BR`) and translate the
values. Keys missing from a translation fall back to English. The catalogs use
i18next JSON v4 conventions, which Weblate, Crowdin and Lokalise import directly.
Native Android text (notifications, the Quick Settings tile, native dialogs, the QR
scanner and errors returned to the app) is in
`apps/desktop/android/src/main/res/values/strings.xml`; add
`values-<tag>/strings.xml` alongside it.
