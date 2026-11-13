# Translating SirinVPN

SirinVPN's client is offered in English, Turkish, Spanish, French, German, Russian, Arabic,
Chinese (Simplified), Japanese and Korean. English is the source. This guide is everything you
need to translate one language; no code changes are needed.

## Files for one language

Language codes: `tr`, `es`, `fr`, `de`, `ru`, `ar`, `zh-Hans`, `ja`, `ko`.

| What | File(s) | Format |
|---|---|---|
| App interface, tray menu, desktop notifications | `apps/desktop/src/locales/<code>/*.json` (16 files: app, common, connection, devices, dns, format, help, home, maintenance, native, onboarding, release, servers, settings, ssh, vps) | JSON, syntax below |
| Android notification, Quick Settings tile, widget, Android dialogs | `apps/desktop/android/src/main/res/<folder>/strings.xml` | Android string resources |

Android folders: `values-tr`, `values-es`, `values-fr`, `values-de`, `values-ru`, `values-ar`,
`values-b+zh+Hans`, `values-ja`, `values-ko`.

Each folder starts as an exact copy of English and is marked as untranslated: the web folder
contains a file named `UNTRANSLATED`, the Android file starts with a `<!-- UNTRANSLATED … -->`
comment. Translate the values, then **delete the `UNTRANSLATED` file and the comment** so the
check treats any remaining English as a mistake.

Translate only the text values. Never change keys (`"label":`), `name="…"` attributes, the file
structure, or `translatable="false"` strings (they are not in the copies).

## Checking your work

From `apps/desktop`:

```sh
pnpm install        # once
pnpm i18n:check     # prints, per language: missing keys, extra keys, failures, untranslated values
pnpm test           # the same checks run inside the test suite
```

A language passes when it has the same keys as English, the same placeholders and rich-text tags,
valid plural syntax with every plural form the language needs, no empty values, and (once the
`UNTRANSLATED` marker is gone) no value longer than three words left identical to English. If a
value really is the same in your language (a product name, "WireGuard", an example command), add
its key to `apps/desktop/src/locales/allowlist.json` under your language code:

```json
{ "*": [], "de": ["connection.methods.tls_like"] }
```

To see your language in the app while you work: `pnpm dev`, open
`http://localhost:1420/?demo=1&role=owner&future=1&lang=<code>` (add `&platform=android` for the
phone layout), or choose it in Settings → Language.

## Message syntax

### Values: `{{name}}`

`{{name}}` is replaced by a value: a person's name, a server, a number. **Never translate or
rename what is inside the braces**; you may move the placeholder anywhere in the sentence.

```json
"removeTitle": "Remove {{name}}?"          // en
"removeTitle": "{{name}} kaldırılsın mı?"    // tr
```

Numbers are formatted for your language automatically (digits, grouping, decimal comma).

### Plurals: `{count, plural, …}`

When the words depend on a number, English uses ICU plural syntax:

```json
"people": "{count, plural, one {# person} other {# people}}"
```

- `count` is the number's name: keep it exactly.
- `one`, `other` … are CLDR plural categories. **Write the categories your language uses**, not
  English's: `#` is the number, formatted.
- `=0 {…}` (an exact number) is optional in every language.
- Every plural must have an `other` form. Don't add categories your language never uses.

| Language | Categories |
|---|---|
| tr, de | one, other |
| es, fr | one, many, other (`many` is for millions: “1 millón de dispositivos”) |
| ru | one, few, many, other |
| ar | zero, one, two, few, many, other |
| zh-Hans, ja, ko | other only |

`pnpm i18n:check` names the exact categories it expects for your language (from your system's
CLDR data), so follow it when in doubt.

Russian (`1 устройство`, `3 устройства`, `5 устройств`, `1,5 устройства`):

```json
"devices": "{count, plural, one {# устройство} few {# устройства} many {# устройств} other {# устройства}}"
```

Arabic (all six forms; `=0` is optional):

```json
"devices": "{count, plural, =0 {لا توجد أجهزة} zero {# جهاز} one {جهاز واحد} two {جهازان} few {# أجهزة} many {# جهازًا} other {# جهاز}}"
```

Japanese, Chinese, Korean: one form.

```json
"devices": "{count, plural, other {#台のデバイス}}"
```

Plurals can contain `{{name}}` placeholders and can be nested; copy the structure from English.
Some messages pluralise on other names than `count` (`{max, plural, …}`): keep the name.

### Rich text: `<tag>…</tag>`

Tags such as `<b>…</b>`, `<settings>…</settings>` or `<path>…</path>` turn part of a sentence into
bold text, a link or a code value. **Keep every tag, with its exact name, around the words that mean
the same thing in your language.** You may move tags; never translate their names or drop one.

```json
"hint": "Open <settings>Android settings</settings> to allow it."
```

### Punctuation

Use typographic apostrophes and quotes (`’`, `“ ”`, `« »`, `「 」`), never `'` — the check rejects
the straight apostrophe. Use your language's own punctuation (Arabic `،` and `؟`, CJK full-width
`。`, `、`, `？`).

## Product vocabulary (keep it consistent)

| English | Meaning |
|---|---|
| server | The person's own VPN server (a VPS they rent). Not "a VPN location". |
| VPS | The rented virtual machine that runs the server; keep "VPS" or use the usual local term. |
| people | Everyone with access to one server. One "person" can have several devices. |
| device | A phone or computer of one person, with its own key. |
| Role: Owner / Admin / Member | Owner: full control, exactly one. Admin: adds people and manages Members. Member: uses the VPN only. Capitalised as role names. |
| join code | A one-time code that lets a new device or person join a server. |
| Device-to-device access | Permission for devices on the same server to reach each other directly. |
| Remove device / Remove person | Permanently take away one device's access / a person and all their devices. |
| Suspend / Resume | Temporarily block a person's devices / give the access back. Nothing is deleted. |
| kill switch | Blocks all internet traffic when the VPN is not connected, so nothing leaks. |
| connection method | How the device reaches the server: Standard WireGuard (Direct UDP), Obfuscated UDP, QUIC (HTTP/3), TLS fallback, HTTPS, HTTPS through a CDN. Translate the descriptive words; keep protocol names (UDP, QUIC, HTTP/3, TLS, HTTPS, CDN). |
| recovery key | A secret that restores Owner access when every Owner device is lost. |
| backup | An encrypted file with this device's VPN identity or the server's data. |

## Tone

Plain, short and calm. Say what happened and what to do next. No marketing words, no
exclamation marks, no "please" padding. Address the user the way apps in your language usually do
(e.g. informal `du` in German apps is fine if consistent; Turkish uses `siz`). Buttons are short
verbs ("Remove", "Try again").

## Keep in English / Latin script

- The product name **SirinVPN** and **WireGuard**.
- Protocol and technology names: UDP, TCP, QUIC, HTTP/3, TLS, HTTPS, DNS, DNS-over-TLS, IPv4, IPv6,
  NAT64, MTU, CDN, SSH, VPS, nftables, UFW, Docker.
- Commands, file paths, addresses, ports, keys and example values (`sudo …`, `/etc/…`,
  `10.77.0.0/24`, `sirin1.…`): copy them unchanged. They are shown left-to-right in every language.
- Some technical detail from the server (diagnostic and error details) is shown in English, under a
  translated summary. That text is not in these files.

## Right-to-left (Arabic)

Write naturally; the app mirrors the layout and isolates names and addresses so they don't
reorder your sentence. Don't add direction marks (U+200F etc.) yourself, and don't reverse arrows:
messages avoid arrows.
