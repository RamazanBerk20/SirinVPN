#!/usr/bin/env node
// Layout audit of the demo UI in headless Chromium: overlapping controls and focus rings, clipped
// or overflowing text, horizontal scrolling, controls hidden under fixed bars, badly wrapped
// buttons, and (in the en-XA pseudo-locale) text that bypassed translation.
// See docs/development.md#layout-audit. Needs a running dev server (`pnpm dev`) and Playwright.
//
//   node scripts/ui-audit.mjs [--url http://127.0.0.1:1420/] [--quick] [--text]
//     [--lang en,tr] [--size min,typical,large,phone] [--zoom 1,1.5] [--role owner,admin,member]
//     [--platform desktop,android] [--state <substring>] [--workers 4] [--out .audit/ui]
//     [--ignore <file with one sample value per line>] [--shots (a screenshot of every check that found something)] [--reuse (the click paths of the last run in --out)]
//
// Playwright is not a project dependency: PLAYWRIGHT_MODULE names a directory whose node_modules
// holds it (else `import("playwright")`), CHROMIUM_PATH an existing Chromium binary.
import { createRequire } from "node:module";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../..");
const { values: opt } = parseArgs({ options: {
  url: { type: "string", default: "http://127.0.0.1:1420/" },
  out: { type: "string", default: join(here, "../.audit/ui") },
  lang: { type: "string" }, size: { type: "string" }, zoom: { type: "string" },
  role: { type: "string" }, platform: { type: "string" }, state: { type: "string" },
  workers: { type: "string", default: "4" }, ignore: { type: "string", multiple: true, default: [] },
  quick: { type: "boolean", default: false }, shots: { type: "boolean", default: false }, reuse: { type: "boolean", default: false }, text: { type: "boolean", default: false },
  depth: { type: "string", default: "3" }, help: { type: "boolean", default: false },
} });
if (opt.help) { console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\nimport")[0]); process.exit(0); }

async function loadPlaywright() {
  try {
    if (process.env.PLAYWRIGHT_MODULE) return createRequire(join(resolve(process.env.PLAYWRIGHT_MODULE), "noop.js"))("playwright");
    return await import("playwright");
  } catch (cause) {
    console.error("Playwright was not found. Install it outside the project (e.g. `npx playwright --version`) and set\n"
      + "PLAYWRIGHT_MODULE to the directory holding its node_modules, plus CHROMIUM_PATH if its browser is missing.\n" + cause.message);
    process.exit(2);
  }
}

const list = (value, all) => value ? value.split(",").map((v) => v.trim()).filter(Boolean) : all;
const LANGS = ["en", "tr", "es", "fr", "de", "ru", "ar", "zh-Hans", "ja", "ko", "en-XA", "ar-XB"];
// min = tauri.conf.json minWidth/minHeight; phone = a small Android phone in CSS pixels.
const SIZES = { min: [760, 620], typical: [1220, 780], large: [1920, 1080], phone: [360, 740] };
const quick = opt.quick;
const langs = opt.text ? ["en-XA"] : list(opt.lang, quick ? ["en", "tr", "de", "ar", "ja", "en-XA"] : LANGS);
const sizeNames = list(opt.size, opt.text ? ["typical", "phone"] : quick ? ["min", "phone"] : Object.keys(SIZES));
const zooms = list(opt.zoom, opt.text || quick ? ["1"] : ["1", "1.5"]).map(Number);
const roles = list(opt.role, ["owner", "admin", "member"]);
const platforms = list(opt.platform, ["desktop", "android"]);
for (const s of sizeNames) if (!SIZES[s]) throw new Error(`unknown size ${s}`);

// Starting points. `init` sets fixture switches (tests/ui/fixtures.js) before the app loads.
const SETTINGS = ["settings/general", "settings/connection", "settings/network", "settings/recovery", "settings/maintenance", "settings/advanced"];
const ALL = ["home", "servers", "devices", ...SETTINGS];
const BASES = [
  { id: "owner", role: "owner", hashes: ALL },
  { id: "owner-disconnected", role: "owner", init: { __sirinScenario: "disconnected" }, hashes: ["home", "servers"] },
  { id: "owner-onboarding", role: "owner", init: { __sirinScenario: "onboarding" }, hashes: ["home"] },
  // Setup reaches its failure screen: the installer refuses its input (install_input_rejected).
  { id: "owner-install-fails", role: "owner", init: { __sirinScenario: "onboarding", __sirinProvisionFails: true }, hashes: ["home"] },
  { id: "owner-remote-fails", role: "owner", init: { __sirinRemoteFails: true }, hashes: ["home", "servers", "devices"], depth: 0 },
  { id: "owner-local-fails", role: "owner", init: { __sirinLocalFails: true }, hashes: ["home"], depth: 0 },
  { id: "owner-save-fails", role: "owner", init: { __sirinPreferenceFails: true, __sirinConnectionSaveFails: true, __sirinConnectionLoadFails: false }, hashes: ["settings/general", "settings/connection"], depth: 1 },
  { id: "owner-connection-load-fails", role: "owner", init: { __sirinConnectionLoadFails: true }, hashes: ["settings/connection"], depth: 0 },
  { id: "admin", role: "admin", hashes: ["home", "devices", "settings/general"] },
  { id: "member", role: "member", hashes: ["home", "servers", "devices", "settings/general", "settings/connection"] },
].flatMap((base) => [{ ...base, platform: "desktop" },
  ...(base.id.includes("fails") && base.id !== "owner-remote-fails" ? [] : [{ ...base, id: `${base.id}-android`, platform: "android" }])])
  .filter((base) => roles.includes(base.role) && platforms.includes(base.platform));

const pw = await loadPlaywright();
const chromium = pw.chromium ?? pw.default?.chromium;
// Never reach a display: everything renders offscreen.
const launch = () => chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined, env: { ...process.env, DISPLAY: "", WAYLAND_DISPLAY: "" } });
// Fails early, with Playwright's own message, when the browser can't start.
await (await launch()).close();
const outDir = resolve(opt.out);
mkdirSync(outDir, { recursive: true });

// ---------- page helpers ----------
const crawlSize = (base) => SIZES[base.platform === "android" ? "phone" : "min"];
// Fixture switches ride in the address (the app ignores unknown parameters), read by one init script per page.
const urlFor = (base, hash, lang) => `${opt.url}?demo=1&role=${base.role}&future=1&platform=${base.platform}&lang=${lang}`
  + `&auditInit=${encodeURIComponent(JSON.stringify({ __sirinComponentUpdated: true, ...base.init }))}#${hash}`;

async function newPage(browser) {
  // A fixed browser locale: the app falls back to it when `?lang=` is ignored (production builds).
  const context = await browser.newContext({ reducedMotion: "reduce", locale: "en-US", viewport: { width: 760, height: 620 } });
  const page = await context.newPage();
  page.errors = [];
  page.on("pageerror", (error) => page.errors.push(String(error).split("\n")[0]));
  page.on("dialog", (dialog) => dialog.dismiss().catch(() => {}));
  page.on("popup", (popup) => popup.close().catch(() => {}));
  await page.addInitScript(() => { try { Object.assign(window, JSON.parse(new URLSearchParams(location.search).get("auditInit") || "{}")); } catch { /* not an audit load */ } });
  return page;
}

async function settle(page) {
  await page.waitForFunction(() => document.querySelector("#root > *") && !document.querySelector(".inline-loading, .loading-screen"), null, { timeout: 8000 }).catch(() => {});
  await page.evaluate(() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))));
  await page.waitForTimeout(250);
}

async function open(page, base, hash, lang, size) {
  await page.setViewportSize({ width: size[0], height: size[1] });
  await page.goto("about:blank");
  await page.goto(urlFor(base, hash, lang), { waitUntil: "load" });
  await settle(page);
}

// Steps are language independent: a CSS signature plus its index among all matches in the document.
async function perform(page, step) {
  if (step.fill) await page.evaluate(fillInputs); // wizards: fill the empty fields first so Next is enabled
  {
    const target = page.locator(step.sel).nth(step.nth);
    if (!(await target.waitFor({ state: "visible", timeout: 2500 }).then(() => true, () => false))) return false;
    try { await target.click({ timeout: 1500 }); } catch { await target.evaluate((el) => el.click()).catch(() => {}); }
  }
  await settle(page);
  return true;
}

async function replay(page, state, lang, size) {
  await open(page, state.base, state.hash, lang, size);
  for (const step of state.path) if (!(await perform(page, step))) return false;
  return true;
}

// ---------- in-page functions ----------
function fillInputs() {
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value").set;
    setter.call(el, value); el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const scope = [...document.querySelectorAll("[role=dialog], dialog[open]")].filter((d) => d.checkVisibility()).at(-1) || document;
  for (const el of scope.querySelectorAll("input:not([type=checkbox]):not([type=radio]):not([type=hidden]):not([type=file]), textarea")) {
    if (el.value || el.disabled || el.readOnly || !el.checkVisibility()) continue;
    const hint = `${el.name} ${el.id} ${el.autocomplete} ${el.inputMode}`.toLowerCase();
    set(el, el.type === "number" || el.inputMode === "numeric" ? (el.min && Number(el.min) > 22 ? el.min : "22")
      : el.type === "password" ? "demo-password-123" : /host|address|server|endpoint/.test(hint) ? "vpn.example.com"
      : /user/.test(hint) ? "root" : /path|key/.test(hint) ? "/home/demo/.ssh/id_ed25519" : "Demo");
  }
}

function pageSnapshot() {
  const visible = (el) => el.checkVisibility({ visibilityProperty: true }) && el.getClientRects().length > 0;
  const dialogs = [...document.querySelectorAll("[role=dialog], dialog[open], [role=menu], [role=listbox]")].filter(visible);
  const scope = dialogs.at(-1) || document.body;
  const sig = (el) => {
    let s = el.tagName.toLowerCase();
    for (const c of [...el.classList].filter((c) => /^[a-z][\w-]*$/i.test(c)).sort()) s += `.${CSS.escape(c)}`;
    for (const a of ["role", "type", "name", "aria-haspopup", "aria-controls"]) {
      const v = el.getAttribute(a); if (v && !/\d{3,}|:r/.test(v)) s += `[${a}="${CSS.escape(v)}"]`;
    }
    return s;
  };
  // The set of kinds of visible elements: a toggled box or one more list row is the same state.
  const fingerprint = [...new Set([...scope.querySelectorAll("*")].filter((el) => !el.closest("svg, .toast-region") && visible(el))
    .map((el) => sig(el) + (el.getAttribute("aria-expanded") === "true" ? ":x" : "") + (el.getAttribute("aria-selected") === "true" ? ":s" : "")))]
    .sort().join("|") + `#${location.hash}#${dialogs.length}`;
  const interactive = "button, a[href], input:not([type=hidden]), summary, [role=button], [role=tab], [role=switch], [role=checkbox], [role=radio], [role=menuitem], [role=option]";
  const candidates = [...scope.querySelectorAll(interactive)]
    .filter((el) => visible(el) && !el.disabled && el.getAttribute("aria-disabled") !== "true" && !el.closest(".demo-banner, .toast-region")
      && !(el.matches("a[href]") && !el.getAttribute("href").startsWith("#")) && !(el.matches("input") && !["checkbox", "radio"].includes(el.type)))
    .map((el) => { const s = sig(el); return { sel: s, nth: [...document.querySelectorAll(s)].indexOf(el), label: (el.textContent || el.getAttribute("aria-label") || "").trim().slice(0, 40) }; });
  const fillable = [...scope.querySelectorAll("input:not([type=checkbox]):not([type=radio]):not([type=hidden]):not([type=file]), textarea")]
    .some((el) => visible(el) && !el.value && !el.disabled && !el.readOnly);
  return { fingerprint, candidates, inDialog: dialogs.length > 0, fillable };
}

// The checks. Returns { issues, leaks }; every issue names its element by a state-independent descriptor.
function auditPage({ layout, text, sampleValues, samplePatterns }) {
  const issues = [];
  const add = (cat, el, detail, other) => issues.push({ cat, sel: desc(el), ...(other ? { other: desc(other) } : {}), detail });
  const css = (el) => getComputedStyle(el);
  // Visually hidden text (.sr-only and the like) is a 1px box: present for screen readers, not on screen.
  const visible = (el) => el.checkVisibility({ visibilityProperty: true }) && el.getClientRects().length > 0 && !srOnly(el);
  const srOnly = (el) => { for (let e = el, i = 0; e && i < 3; e = e.parentElement, i++) { const r = e.getBoundingClientRect(); if (r.width <= 1 || r.height <= 1) return css(e).position === "absolute"; } return false; };
  function desc(el) {
    if (!el || el === document.body) return "body";
    const own = (e) => e.tagName.toLowerCase() + [...e.classList].filter((c) => /^[a-z][\w-]*$/i.test(c)).slice(0, 3).map((c) => `.${c}`).join("")
      + (e.getAttribute("role") ? `[role=${e.getAttribute("role")}]` : "");
    const parts = [own(el)];
    for (let p = el.parentElement; p && p !== document.body && parts.length < 3; p = p.parentElement) if (p.classList.length) parts.unshift(own(p));
    return parts.join(" > ");
  }
  const dialogs = [...document.querySelectorAll("[role=dialog], dialog[open]")].filter(visible);
  const scope = dialogs.at(-1) || document.body;
  const inScope = (el) => scope.contains(el) && !el.closest(".toast-region");
  const pinned = (el) => { for (let e = el; e; e = e.parentElement) { const p = css(e).position; if (p === "fixed" || p === "sticky") return e; } return null; };
  // The visible part of an element: its box cut by every ancestor that clips (hidden/clip/auto/scroll).
  const clipOf = (el, self = false) => {
    let r = { left: -1e6, top: -1e6, right: 1e6, bottom: 1e6 };
    for (let p = self ? el : el.parentElement; p; p = p.parentElement) {
      const s = css(p);
      if (s.position === "fixed") { r = cut(r, { left: 0, top: 0, right: innerWidth, bottom: innerHeight }); }
      if (s.overflowX !== "visible" || s.overflowY !== "visible") {
        const b = p.getBoundingClientRect();
        if (s.overflowX !== "visible") r = cut(r, { left: b.left, right: b.right, top: r.top, bottom: r.bottom });
        if (s.overflowY !== "visible") r = cut(r, { left: r.left, right: r.right, top: b.top, bottom: b.bottom });
      }
    }
    return r;
  };
  const cut = (a, b) => ({ left: Math.max(a.left, b.left), top: Math.max(a.top, b.top), right: Math.min(a.right, b.right), bottom: Math.min(a.bottom, b.bottom) });
  const fmt = (r) => `${Math.round(r.left)},${Math.round(r.top)} ${Math.round(r.right - r.left)}x${Math.round(r.bottom - r.top)}`;
  const area = (r) => Math.max(0, r.right - r.left) * Math.max(0, r.bottom - r.top);
  const overlaps = (a, b) => Math.min(a.right, b.right) - Math.max(a.left, b.left) > 0.5 && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 0.5;
  const related = (a, b) => a.contains(b) || b.contains(a) || (a.id && b.matches?.(`label[for="${CSS.escape(a.id)}"]`)) || (b.id && a.matches?.(`label[for="${CSS.escape(b.id)}"]`));

  const textNodes = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const parent = n.parentElement;
    if (!parent || /^(SCRIPT|STYLE|NOSCRIPT|TEXTAREA|OPTION)$/.test(parent.tagName) || parent.closest("svg")) continue;
    textNodes.push(n);
  }

  if (layout) {
    const interactiveSel = "button, a[href], input:not([type=hidden]), select, textarea, summary, [role=button], [role=tab], [role=switch], [role=checkbox], [role=radio], [role=menuitem], [role=option], [tabindex]:not([tabindex='-1'])";
    const controls = [...document.querySelectorAll(interactiveSel)].filter((el) => inScope(el) && visible(el) && !el.closest("[inert], [aria-hidden=true]"));
    const before = document.activeElement;
    const scrolls = [...document.querySelectorAll("*")].filter((e) => e.scrollTop || e.scrollLeft).map((e) => [e, e.scrollTop, e.scrollLeft]);
    const docScroll = [scrollX, scrollY];
    // Each control's box, the ring it draws when focused (its own outline, or a :focus-within one up to 3 levels up), and its clip.
    // Text line boxes, for rings that run over neighbouring text.
    const lines = [];
    for (const n of textNodes) {
      if (!n.textContent.trim() || !inScope(n.parentElement) || !visible(n.parentElement)) continue;
      const range = document.createRange(); range.selectNodeContents(n);
      for (const r of range.getClientRects()) if (r.width > 1 && r.height > 1) lines.push({ el: n.parentElement, r });
    }
    // Geometry is read with nothing focused (focus can reveal hints and move things); focus only tells which outlines draw.
    const chains = controls.map((el) => { const chain = []; for (let e = el, i = 0; e && i < 4; e = e.parentElement, i++) chain.push([e, e.getBoundingClientRect()]); return chain; });
    const items = controls.map((el, index) => {
      const item = {};
      el.focus({ preventScroll: true });
      // Every outline drawn while it has focus (its own, and :focus-within ones on wrappers); the ring is their union.
      let ringEl = null, ring = null;
      for (const [e, b] of document.activeElement === el ? chains[index] : []) {
        const s = css(e);
        if (s.outlineStyle === "none" || !(parseFloat(s.outlineWidth) > 0)) continue;
        const grow = parseFloat(s.outlineWidth) + parseFloat(s.outlineOffset);
        const r = { left: b.left - grow, top: b.top - grow, right: b.right + grow, bottom: b.bottom + grow };
        ring = ring ? { left: Math.min(ring.left, r.left), top: Math.min(ring.top, r.top), right: Math.max(ring.right, r.right), bottom: Math.max(ring.bottom, r.bottom) } : r;
        ringEl = e; item.ringBox = b;
      }
      const box = chains[index][0][1];
      return Object.assign(item, { el, ringEl: ringEl || el, box, ring });
    });
    if (before instanceof HTMLElement) before.focus({ preventScroll: true }); else document.activeElement?.blur?.();
    for (const item of items) { item.clip = clipOf(item.ringEl); item.pin = pinned(item.el); }
    for (const line of lines) { line.clip = clipOf(line.el, true); line.pin = pinned(line.el); } // text is cut by its own box too

    const seen = new Set();
    for (const a of items) {
      const shape = a.ring || a.box;
      const visibleBox = cut(a.box, a.clip);
      if (area(visibleBox) < 4) continue;
      // Ring cut off for good by an ancestor, while the control itself is fully in view. An edge that
      // scrolling can move (a scroll box that actually scrolls on that axis) only depends on the scroll position.
      if (a.ring && area(cut(a.ringBox, a.clip)) >= area(a.ringBox) - 1) {
        const r = a.ring;
        let scrollsX = false, scrollsY = false; // past a box that scrolls on an axis, outer edges on it are positional too
        for (let p = a.ringEl.parentElement; p; p = p.parentElement) {
          const s = css(p), b = p.getBoundingClientRect();
          const canX = /auto|scroll/.test(s.overflowX) && p.scrollWidth > p.clientWidth + 1, canY = /auto|scroll/.test(s.overflowY) && p.scrollHeight > p.clientHeight + 1;
          const fixedX = !scrollsX && !canX && s.overflowX !== "visible", fixedY = !scrollsY && !canY && s.overflowY !== "visible";
          scrollsX ||= canX; scrollsY ||= canY;
          if ((fixedX && (r.left < b.left - 1 || r.right > b.right + 1)) || (fixedY && (r.top < b.top - 1 || r.bottom > b.bottom + 1))) {
            add("focus-ring-clipped", a.el, `ring ${fmt(r)} cut by ${desc(p)} ${fmt(b)}`);
            break;
          }
        }
      }
      const mine = cut(shape, a.clip);
      for (const b of items) {
        if (a === b || a.pin !== b.pin || related(a.ringEl, b.el) || related(a.el, b.el)) continue;
        const theirs = cut(b.box, b.clip);
        if (area(theirs) < 4 || !overlaps(mine, theirs)) continue;
        const boxHit = overlaps(cut(a.box, a.clip), theirs);
        const key = [boxHit ? "overlap" : "focus-ring-overlap", desc(a.el), desc(b.el)].join("|");
        if (boxHit && seen.has(["overlap", desc(b.el), desc(a.el)].join("|"))) continue;
        if (!seen.has(key)) { seen.add(key); add(boxHit ? "overlap" : "focus-ring-overlap", a.el, `${boxHit ? "control boxes intersect" : "focus ring runs over another control"}: ${fmt(shape)} / ${fmt(b.box)}`, b.el); }
      }
      if (a.ring) for (const t of lines) {
        if (a.pin !== t.pin || a.ringEl.contains(t.el) || t.el.contains(a.ringEl)) continue;
        if (!overlaps(mine, cut(t.r, t.clip))) continue;
        const key = ["focus-ring-text", desc(a.el), desc(t.el)].join("|");
        if (!seen.has(key)) { seen.add(key); add("focus-ring-text", a.el, `focus ring runs over text "${t.el.textContent.trim().slice(0, 40)}"`, t.el); }
      }
    }

    // Controls hidden under fixed or sticky bars once scrolled into view (as keyboard focus would).
    for (const a of items) {
      if (a.el.closest("select, option") || area(a.box) < 4 || a.box.height > innerHeight * 0.6) continue;
      a.el.scrollIntoView({ block: "nearest", inline: "nearest" });
      const b = a.el.getBoundingClientRect();
      const x = Math.min(Math.max(b.left + b.width / 2, 0), innerWidth - 1), y = Math.min(Math.max(b.top + b.height / 2, 0), innerHeight - 1);
      if (b.bottom < 0 || b.top > innerHeight || b.right < 0 || b.left > innerWidth) continue;
      const hit = document.elementFromPoint(x, y);
      // Window resize edges are 4px transparent grips along the window border.
      // An open menu's backdrop covers the page on purpose.
      if (!hit || related(a.el, hit) || a.ringEl.contains(hit) || hit.closest(".toast-region, .window-resize-edge, .action-menu-backdrop")) continue;
      const bar = pinned(hit);
      if (bar && bar !== pinned(a.el) && !bar.contains(a.el)) add("hidden-under-bar", a.el, "covered when scrolled into view", bar);
      else if (!bar && !hit.contains(a.el)) add("covered", a.el, "another element sits on top of it", hit);
    }
    for (const [e, top, left] of scrolls) { e.scrollTop = top; e.scrollLeft = left; }
    scrollTo(...docScroll);

    // Text that spills out of its box, is clipped, or truncated without a way to read it.
    const checked = new Set();
    for (const n of textNodes) {
      const el = n.parentElement;
      if (!n.textContent.trim() || checked.has(el) || !inScope(el) || !visible(el)) continue;
      checked.add(el);
      let box = el;
      while (box && css(box).display.startsWith("inline") && box.parentElement) box = box.parentElement;
      const s = css(box);
      const titled = (e) => { for (let p = e, i = 0; p && i < 4; p = p.parentElement, i++) if (p.title || p.getAttribute("aria-label") || p.getAttribute("data-tooltip")) return true; return false; };
      const xOver = box.scrollWidth > box.clientWidth + 1, yOver = box.scrollHeight > box.clientHeight + 1;
      if (s.textOverflow === "ellipsis" && xOver && s.overflowX !== "visible") { if (!titled(box)) add("truncated-no-tooltip", box, "ellipsis without a title or label"); continue; }
      if (s.webkitLineClamp !== "none" && s.webkitLineClamp && yOver) { if (!titled(box)) add("truncated-no-tooltip", box, "line clamp without a title or label"); continue; }
      if ((xOver && /hidden|clip/.test(s.overflowX)) || (yOver && /hidden|clip/.test(s.overflowY))) { add("text-clipped", box, `content ${box.scrollWidth}x${box.scrollHeight} in ${box.clientWidth}x${box.clientHeight}`); continue; }
      const range = document.createRange(); range.selectNodeContents(n);
      const r = range.getBoundingClientRect(), b = box.getBoundingClientRect();
      // Text inside a sideways scroller close by (a command line, a code block) can be scrolled to.
      const scrolls = (() => { for (let p = box, i = 0; p && i < 3; p = p.parentElement, i++) if (/auto|scroll/.test(css(p).overflowX)) return true; return false; })();
      if (r.width && !scrolls && (r.right > b.right + 2 || r.left < b.left - 2)) { add("text-overflow", box, `text ${Math.round(r.width)}px wide in a ${Math.round(b.width)}px box`); continue; }
      const c = clipOf(el);
      if (r.width && (r.right > c.right + 2 || r.left < c.left - 2) && b.right <= c.right + 2 && b.left >= c.left - 2) add("text-clipped", box, "text runs past a clipping ancestor");
    }

    // Horizontal scrolling: the page itself, and any scroll box not meant to scroll sideways.
    const root = document.scrollingElement;
    if (root.scrollWidth > root.clientWidth + 1) {
      const wide = [...document.querySelectorAll("body *")].filter((e) => visible(e) && e.getBoundingClientRect().right > root.clientWidth + 1 && !pinned(e))
        .filter((e, _, all) => !all.some((o) => o !== e && e.contains(o))).slice(0, 3);
      add("page-h-scroll", wide[0] || document.body, `document ${root.scrollWidth}px in ${root.clientWidth}px; ${wide.map(desc).join("; ")}`);
    }
    for (const e of document.querySelectorAll("body *")) {
      if (e === root || !inScope(e)) continue;
      const s = css(e);
      if (!/auto|scroll/.test(s.overflowX) || e.scrollWidth <= e.clientWidth + 1 || !visible(e)) continue;
      if (e.matches("[role=tablist], pre, code, .allow-h-scroll") || e.closest("pre")) continue;
      add("element-h-scroll", e, `${e.scrollWidth}px in ${e.clientWidth}px`);
    }

    // Buttons, tabs and headings whose words break mid-word, and buttons wrapping to three or more lines.
    for (const el of document.querySelectorAll("button, [role=tab], [role=button], h1, h2, h3, h4")) {
      if (!inScope(el) || !visible(el)) continue;
      const nodes = textNodes.filter((n) => el.contains(n) && n.textContent.trim());
      const tops = new Set();
      let broken = null;
      for (const n of nodes) {
        const range = document.createRange(); range.selectNodeContents(n);
        for (const r of range.getClientRects()) if (r.width > 1) tops.add(Math.round(r.top / 4));
        for (const m of n.textContent.matchAll(/\S+/g)) {
          const word = m[0];
          if (word.length < 4 || word.length > 24 || /[\d:./@_\-\u00ad]|[　-鿿가-힯]/.test(word)) continue;
          const w = document.createRange(); w.setStart(n, m.index); w.setEnd(n, m.index + word.length);
          const rects = [...w.getClientRects()].filter((r) => r.width > 1);
          // A word wider than its whole line has to break; only a word that would fit on a line of its own counts.
          let line = n.parentElement;
          while (css(line).display.startsWith("inline") && line.parentElement) line = line.parentElement;
          const ls = css(line), room = line.clientWidth - parseFloat(ls.paddingLeft) - parseFloat(ls.paddingRight);
          const fits = !line.clientWidth || rects.reduce((sum, r) => sum + r.width, 0) <= room;
          if (rects.length > 1 && Math.abs(rects[0].top - rects.at(-1).top) > 2 && fits) { broken = word; break; }
        }
        if (broken) break;
      }
      // Row buttons (a title over a description) wrap by design; only a plain label counts.
      const plainLabel = ![...el.querySelectorAll("*")].some((child) => !css(child).display.startsWith("inline") && child.textContent.trim());
      if (broken) add("word-broken", el, `"${broken}" breaks mid-word`);
      else if (el.matches("button, [role=button]") && plainLabel && tops.size >= 3) add("button-wraps", el, `label wraps to ${tops.size} lines`);
    }
  }

  // Text that bypassed translation: in en-XA every message is wrapped in ⟦…⟧ (nested), so what is
  // left outside the brackets is either sample data or a leak.
  const leaks = [];
  if (text) {
    const latin = /\p{Script=Latin}{2,}/u;
    const clean = (s) => {
      for (const v of sampleValues) if (s.includes(v)) s = s.split(v).join(" ");
      for (const p of samplePatterns) s = s.replace(new RegExp(p, "gu"), " ");
      return s;
    };
    const strip = (s) => { let prev; do { prev = s; s = s.replace(/⟦[^⟦⟧]*⟧/g, " "); } while (s !== prev); return s; };
    const report = (kind, el, full, rest) => { const left = clean(rest); if (latin.test(left)) leaks.push({ kind, sel: desc(el), text: full.trim().slice(0, 160), rest: left.replace(/\s+/g, " ").trim().slice(0, 120) }); };
    let depth = 0;
    const outside = new Map();
    for (const n of textNodes) {
      let rest = "";
      for (const ch of n.textContent) {
        if (ch === "⟦") depth++;
        else if (ch === "⟧") depth = Math.max(0, depth - 1);
        else if (depth === 0) rest += ch;
      }
      const el = n.parentElement;
      // Commands and code samples are not prose to translate.
      if (rest.trim() && visible(el) && !el.closest("code, pre, kbd, samp")) outside.set(el, (outside.get(el) || "") + " " + rest);
    }
    for (const [el, rest] of outside) report("text", el, el.textContent, rest);
    for (const el of document.querySelectorAll("[aria-label], [title], [placeholder], [alt], [aria-description], [aria-valuetext]")) {
      if (el.closest("svg") && !el.matches("svg")) continue;
      if (!visible(el) && !el.matches("svg, [role=img]")) continue;
      for (const a of ["aria-label", "title", "placeholder", "alt", "aria-description", "aria-valuetext"]) {
        const v = el.getAttribute(a); if (v) report(a, el, v, strip(v));
      }
    }
    report("document.title", document.documentElement, document.title, strip(document.title));
  }
  return { issues, leaks };
}

// ---------- sample data that legitimately stays untranslated ----------
function sampleData() {
  const values = new Set();
  for (const file of ["tests/ui/fixtures.js", "apps/desktop/src/features/devices/demoDevices.ts", ...opt.ignore]) {
    const source = readFileSync(resolve(repo, file), "utf8");
    if (opt.ignore.includes(file)) { for (const line of source.split("\n")) if (line.trim()) values.add(line.trim()); continue; }
    for (const m of source.matchAll(/(Error\(\s*)?(["'`])((?:\\.|(?!\2)[^\\\n])*)\2/g)) {
      const v = m[3];
      // Names, hosts and the like; not lowercase identifiers (they would hide raw enum leaks) or error messages.
      if (m[1] || v.length < 3 || v.includes("${") || !/[A-Z0-9 .’']/.test(v) || /^[a-z_:|]+$/.test(v)) continue;
      values.add(v);
    }
  }
  return {
    sampleValues: [...values, "SirinVPN"].sort((a, b) => b.length - a.length),
    samplePatterns: ["SHA256:[A-Za-z0-9+/=]+", "\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b",
      "\\b(?:[a-z0-9-]+\\.)+(?:com|net|org|example|local|test)\\b", "\\b\\d{1,3}(?:\\.\\d{1,3}){3}(?:/\\d+)?\\b", "\\b[0-9a-f:]*::[0-9a-f:]*(?:/\\d+)?",
      "~?/[\\w./-]+", "\\b[A-Z0-9]{4}(?:-[A-Z0-9]{4}){2,}\\b",
      // Demo fingerprints are one letter repeated (also shortened with an ellipsis); a fixture without an answer names the command.
      "(\\p{Lu})\\1{3,}(?:…\\1+)?", "Unexpected visual fixture command: \\w+"],
  };
}

// ---------- worker pool ----------
async function pool(tasks, run) {
  const workers = Math.max(1, Number(opt.workers));
  let next = 0, done = 0;
  const started = Date.now();
  await Promise.all(Array.from({ length: Math.min(workers, tasks.length) }, async () => {
    // Each worker has its own browser and starts a new one every 60 tasks: a long-lived Chromium
    // leaks shared memory (ERR_INSUFFICIENT_RESOURCES, then crashes) over thousands of page loads.
    let browser = await launch(), page = await newPage(browser), used = 0;
    // A fresh context after any failure (a crashed or exhausted page); a closed browser is launched again.
    const renew = async (fresh) => {
      await page.context().close().catch(() => {});
      if (fresh || !browser.isConnected()) { await browser.close().catch(() => {}); browser = await launch(); used = 0; }
      page = await newPage(browser);
    };
    while (next < tasks.length) {
      const task = tasks[next++];
      if (++used > 60) await renew(true);
      for (let attempt = 0; attempt < 2; attempt++) {
        try { await run(page, task); break; } catch (error) {
          if (process.env.AUDIT_DEBUG) console.error(new Date().toISOString(), task.state?.name, error);
          await renew();
          if (attempt) failures.push(`${task.state?.name ?? task.name} [${task.lang ?? "crawl"}]: ${String(error).split("\n")[0]}`);
        }
      }
      if (++done % 25 === 0 || done === tasks.length) process.stdout.write(`\r  ${done}/${tasks.length} (${Math.round((Date.now() - started) / 1000)}s)   `);
    }
    await browser.close().catch(() => {});
  }));
  process.stdout.write("\n");
}

// ---------- 1. crawl: record click paths to every distinct state ----------
const maxDepth = Number(opt.depth);
async function crawl() {
  const states = [];
  const seen = new Map(BASES.map((b) => [b.id, new Set()]));
  const frontier = BASES.flatMap((base) => base.hashes.map((hash) => ({ base, hash, path: [], name: `${base.id}/${hash}` })))
    .filter((s) => !opt.state || opt.state.startsWith(s.name) || s.name.includes(opt.state));
  // Breadth first; each round expands every state found in the previous one, in parallel.
  let round = frontier.filter((s) => {
    states.push(s); return true;
  });
  const lang = "en";
  for (let depth = 0; round.length && depth <= maxDepth; depth++) {
    console.log(`crawl depth ${depth}: ${round.length} states to expand`);
    const found = [];
    await pool(round, async (page, state) => {
      const size = crawlSize(state.base);
      if (!(await replay(page, state, lang, size))) return;
      const here = await page.evaluate(pageSnapshot);
      seen.get(state.base.id).add(here.fingerprint);
      if (depth >= (state.base.depth ?? maxDepth)) return;
      // Below the first level, only explore inside dialogs and menus (wizards, pickers): the page itself was covered at depth 0.
      if (depth > 0 && !here.inDialog) return;
      const steps = here.candidates.slice(0, depth ? 25 : 60).map((c) => here.fillable && here.inDialog ? { ...c, fill: true } : c);
      let fresh = true;
      for (const step of steps) {
        if (!fresh && !(await replay(page, state, lang, size))) return;
        if (!(await perform(page, step))) { fresh = true; continue; }
        const after = await page.evaluate(pageSnapshot);
        const route = (f) => f.match(/#([^#]*)#\d+$/)[1];
        if (route(after.fingerprint) !== route(here.fingerprint)) { fresh = false; continue; } // another page: covered on its own
        const known = seen.get(state.base.id);
        fresh = after.fingerprint === here.fingerprint;
        if (fresh || known.has(after.fingerprint)) continue;
        known.add(after.fingerprint);
        found.push({ base: state.base, hash: state.hash, path: [...state.path, step], name: `${state.name} > ${step.label || step.sel}` });
      }
    });
    states.push(...found);
    round = found;
  }
  return states;
}

// ---------- 2. audit each state in each language, size and zoom ----------
const pageErrors = new Set(), failures = [];
const keyOf = (i) => `${i.cat}|${i.sel}|${i.other || ""}`;
async function audit(states) {
  const sample = sampleData();
  const problems = new Map(), leaks = new Map(), skipped = [];
  const tasks = states.flatMap((state) => langs.map((lang) => ({ state, lang })));
  let checks = 0;
  await pool(tasks, async (page, { state, lang }) => {
    const sizes = sizeNames.filter((s) => (s === "phone") === (state.base.platform === "android"));
    if (!sizes.length) return;
    if (!(await replay(page, state, lang, SIZES[sizes[0]]))) { skipped.push(`${state.name} [${lang}]`); return; }
    const textOnly = opt.text;
    for (const size of sizes) {
      await page.setViewportSize({ width: SIZES[size][0], height: SIZES[size][1] });
      for (const zoom of zooms) {
        // Text zoom: the CSS sizes text in rem, so a larger root font size is what the OS text-scaling setting does; Android also gets its large-font layout.
        await page.evaluate(({ zoom, android }) => {
          document.documentElement.style.fontSize = zoom === 1 ? "" : `${zoom * 100}%`;
          if (android) document.documentElement.dataset.fontScale = zoom >= 1.5 ? "large" : "normal";
        }, { zoom, android: state.base.platform === "android" });
        // Keyboard modality, so programmatic focus shows :focus-visible rings; then drop the focus Tab gave (the skip link).
        await page.keyboard.press("Tab").catch(() => {});
        await page.evaluate(() => document.activeElement?.blur?.());
        await page.evaluate(() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))));
        await page.waitForTimeout(120);
        const result = await page.evaluate(auditPage, { layout: !textOnly, text: lang === "en-XA", ...sample });
        checks++;
        const where = { state: state.name, lang, size, zoom };
        if (opt.shots && result.issues.length) {
          where.shot = join(outDir, "shots", `${checks}-${state.name.replace(/[^\w-]+/g, "_").slice(0, 80)}-${lang}-${size}-${zoom}.png`);
          mkdirSync(dirname(where.shot), { recursive: true });
          await page.screenshot({ path: where.shot, fullPage: true });
        }
        for (const issue of result.issues) {
          const k = keyOf(issue);
          if (!problems.has(k)) problems.set(k, { ...issue, count: 0, where: [], langs: new Set(), sizes: new Set(), states: new Set() });
          const p = problems.get(k);
          p.count++; p.langs.add(lang); p.sizes.add(`${size}@${zoom}`); p.states.add(state.name);
          if (p.where.length < 5) p.where.push({ ...where, detail: issue.detail });
        }
        for (const leak of result.leaks) {
          const k = `${leak.kind}|${leak.rest}`;
          if (!leaks.has(k)) leaks.set(k, { ...leak, states: new Set() });
          leaks.get(k).states.add(state.name);
        }
      }
    }
    for (const e of page.errors.splice(0)) pageErrors.add(`${e} (${state.name})`);
  });
  return { problems, leaks, skipped, checks, tasks };
}

const started = Date.now();
const statesFile = join(outDir, "states.json");
let states;
if (opt.reuse) {
  const byId = new Map(BASES.map((b) => [b.id, b]));
  states = JSON.parse(readFileSync(statesFile, "utf8")).filter((s) => byId.has(s.base)).map((s) => ({ ...s, base: byId.get(s.base) }));
} else {
  states = await crawl();
  writeFileSync(statesFile, JSON.stringify(states.map((s) => ({ ...s, base: s.base.id })), null, 1));
}
if (opt.state) states = states.filter((s) => s.name.includes(opt.state));
console.log(`${states.length} states; auditing ${langs.join(",")} at ${sizeNames.join(",")} x zoom ${zooms.join(",")}`);
const { problems, leaks, skipped, checks, tasks } = await audit(states);

const plain = (p) => ({ ...p, langs: [...(p.langs || [])], sizes: [...(p.sizes || [])], states: [...p.states].slice(0, 20), stateCount: p.states.size });
const sorted = [...problems.values()].sort((a, b) => a.cat.localeCompare(b.cat) || b.count - a.count);
const leakList = [...leaks.values()].map(plain).sort((a, b) => a.rest.localeCompare(b.rest));
const seconds = Math.round((Date.now() - started) / 1000);
const summary = { url: opt.url, langs, sizes: sizeNames, zooms, bases: BASES.map((b) => b.id), states: states.length, replays: tasks.length,
  checks, seconds, failures, problems: sorted.length, leaks: leakList.length, skipped, pageErrors: [...pageErrors].slice(0, 50) };
writeFileSync(join(outDir, "report.json"), JSON.stringify({ summary, states: states.map((s) => ({ name: s.name, path: s.path })), problems: sorted.map(plain), leaks: leakList }, null, 2));
const lines = [`UI audit: ${states.length} states, ${checks} checks in ${seconds}s; ${sorted.length} distinct problems, ${leakList.length} untranslated strings.`, ""];
const byCat = Object.groupBy(sorted, (p) => p.cat);
for (const [cat, items] of Object.entries(byCat)) {
  lines.push(`== ${cat} (${items.length})`);
  for (const p of items) {
    const w = p.where[0];
    lines.push(`- ${p.sel}${p.other ? `  vs  ${p.other}` : ""}`,
      `    ${p.count}x in ${p.states.size} states; langs ${[...p.langs].join(",")}; sizes ${[...p.sizes].join(",")}`,
      `    e.g. ${w.state} [${w.lang} ${w.size} @${w.zoom}]: ${w.detail}`);
  }
  lines.push("");
}
if (leakList.length) {
  lines.push(`== untranslated text in en-XA (${leakList.length})`);
  for (const l of leakList) lines.push(`- ${l.kind} "${l.rest}"  (${l.sel})`, `    full: ${l.text}`, `    in: ${l.states.slice(0, 3).join(" | ")}${l.stateCount > 3 ? ` (+${l.stateCount - 3})` : ""}`);
  lines.push("");
}
if (failures.length) lines.push(`Failed (the audit itself threw): ${failures.length}`, ...failures.slice(0, 20).map((s) => `  ${s}`), "");
if (skipped.length) lines.push(`Skipped (path did not replay): ${skipped.length}`, ...skipped.slice(0, 20).map((s) => `  ${s}`), "");
if (summary.pageErrors.length) lines.push("Page errors:", ...summary.pageErrors.map((e) => `  ${e}`), "");
writeFileSync(join(outDir, "report.txt"), lines.join("\n"));
console.log(lines.slice(0, 1).join("\n") + `\nReport: ${join(outDir, "report.txt")} (and report.json)`);
process.exitCode = sorted.length || (opt.text && leakList.length) ? 1 : 0;
