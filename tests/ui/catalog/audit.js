// In-page UX audit for one rendered catalog state. Evaluated by full_capture.py as `(form) => findings`.
(form) => {
  const findings = [];
  const minTarget = form === "mobile" ? 44 : 24;
  const shown = el => {
    if (!el.getClientRects().length) return false;
    // Content of a closed <details> keeps boxes in Chromium but is not rendered.
    const closed = el.closest("details:not([open])");
    const ownSummary = el.closest("summary")?.parentElement === closed;
    if (closed && (!ownSummary || closed.parentElement?.closest("details:not([open])"))) return false;
    for (let node = el; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.visibility === "hidden" || style.display === "none" || Number(style.opacity) === 0 || node.hasAttribute("inert") || node.getAttribute("aria-hidden") === "true") return false;
    }
    return true;
  };
  const describe = el => {
    const text = (el.getAttribute("aria-label") || el.innerText || el.value || el.placeholder || "").replace(/\s+/g, " ").trim().slice(0, 60);
    const cls = typeof el.className === "string" ? el.className.split(/\s+/).filter(Boolean).slice(0, 2).join(".") : "";
    return `${el.tagName.toLowerCase()}${cls ? "." + cls : ""}${text ? ` "${text}"` : ""}`;
  };
  // Only report what a front dialog or menu leaves reachable.
  const front = document.querySelector('[role="menu"]') ?? [...document.querySelectorAll('[role="dialog"],[role="alertdialog"]')].filter(shown).at(-1);
  const inScope = el => !front || front.contains(el);
  const add = (kind, el, detail) => findings.push({ kind, target: describe(el), detail });

  if (document.documentElement.scrollWidth > innerWidth + 1)
    findings.push({ kind: "page-overflow", target: "document", detail: `${document.documentElement.scrollWidth}px wide in a ${innerWidth}px viewport` });

  const scrollsX = el => { for (let node = el.parentElement; node; node = node.parentElement) if (/(auto|scroll)/.test(getComputedStyle(node).overflowX) && node.scrollWidth > node.clientWidth + 1) return true; return false; };
  const all = [...document.body.querySelectorAll("*")].filter(el => inScope(el) && shown(el));
  const offscreen = new Set();
  for (const el of all) {
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2 || scrollsX(el)) continue;
    if ((r.right > innerWidth + 1 || r.left < -1) && !(el.parentElement && offscreen.has(el.parentElement))) {
      offscreen.add(el);
      add("offscreen", el, `x ${Math.round(r.left)}–${Math.round(r.right)} of ${innerWidth}`);
    }
    const style = getComputedStyle(el);
    if (/(hidden|clip)/.test(style.overflowX) && el.scrollWidth > el.clientWidth + 2 && el.innerText?.trim() && !el.querySelector("input,textarea,select"))
      add(style.textOverflow === "ellipsis" ? "truncated" : "clipped-text", el, `${el.scrollWidth}px content in ${el.clientWidth}px`);
  }

  const interactive = all.filter(el => el.matches('button,a[href],input:not([type=hidden]),select,textarea,summary,[role=button],[role=menuitem],[role=tab],[role=switch],[role=checkbox],[role=radio]'));
  for (const el of interactive) {
    if (el.disabled) continue;
    let box = el.getBoundingClientRect();
    const label = el.closest("label") ?? (el.id ? document.querySelector(`label[for="${CSS.escape(el.id)}"]`) : null);
    if (label && /checkbox|radio/.test(el.type)) box = label.getBoundingClientRect();
    // An absolutely placed ::before/::after with negative insets widens the hit area (info buttons do this).
    for (const pseudo of ["::before", "::after"]) {
      const ps = getComputedStyle(el, pseudo);
      if (ps.content === "none" || ps.position !== "absolute") continue;
      const grow = side => Math.max(0, -parseFloat(ps[side]) || 0);
      box = { width: Math.max(box.width, box.width + grow("left") + grow("right")), height: Math.max(box.height, box.height + grow("top") + grow("bottom")) };
    }
    // Inline links inside running text are exempt (WCAG 2.5.8).
    if (el.tagName === "A" && getComputedStyle(el).display === "inline") continue;
    if (box.width < minTarget - 0.5 || box.height < minTarget - 0.5) add("small-target", el, `${Math.round(box.width)}×${Math.round(box.height)} (min ${minTarget})`);
    const name = el.getAttribute("aria-label") || el.getAttribute("aria-labelledby") && document.getElementById(el.getAttribute("aria-labelledby"))?.innerText || el.getAttribute("title") || (el.matches("input,select,textarea") ? label?.innerText || el.placeholder : el.innerText) || "";
    if (!name.trim() && el.type !== "file") add("no-name", el, "no accessible name");
  }
  for (const img of all.filter(el => el.matches("img:not([alt]),svg[role=img]:not([aria-label])"))) add("no-alt", img, "image without text alternative");

  // Contrast: text colour against the composited background; gradients and images are skipped as unknown.
  const ctx = document.createElement("canvas").getContext("2d", { willReadFrequently: true });
  const rgba = color => { ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = "#000"; ctx.fillStyle = color; ctx.fillRect(0, 0, 1, 1); const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data; return [r, g, b, a / 255]; };
  const over = (top, bottom) => [0, 1, 2].map(i => top[i] * top[3] + bottom[i] * (1 - top[3])).concat(1);
  const lum = c => { const [r, g, b] = c.slice(0, 3).map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  const background = el => {
    const layers = [];
    for (let node = el; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      // Page-sized decorative glows count as their base colour; a gradient on a control or card is unknown.
      if (style.backgroundImage !== "none") { const r = node.getBoundingClientRect(); if (r.width * r.height < innerWidth * innerHeight / 2) return null; }
      const color = rgba(style.backgroundColor);
      if (color[3] > 0) layers.push(color);
      if (color[3] >= 1) break;
    }
    let base = rgba(getComputedStyle(document.body).backgroundColor);
    if (base[3] < 1) base = [255, 255, 255, 1];
    for (const layer of layers.reverse()) base = over(layer, base);
    return base;
  };
  const seen = new Set();
  for (const el of all) {
    if (![...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) continue;
    if (el.closest(":disabled,[aria-disabled=true]")) continue;
    const style = getComputedStyle(el);
    const bg = background(el);
    if (!bg) continue;
    let opacity = 1;
    for (let node = el; node; node = node.parentElement) opacity *= Number(getComputedStyle(node).opacity);
    const fg = rgba(style.color);
    fg[3] *= opacity;
    const text = over(fg, bg);
    const l1 = lum(text), l2 = lum(bg);
    const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    const size = parseFloat(style.fontSize), bold = Number(style.fontWeight) >= 700;
    if (size < 12) add("tiny-text", el, `${size}px`);
    const need = size >= 24 || bold && size >= 18.66 ? 3 : 4.5;
    const key = `${style.color}|${bg}|${size}`;
    if (ratio < need && !seen.has(key)) { seen.add(key); add("low-contrast", el, `${ratio.toFixed(2)}:1 at ${size}px (needs ${need}:1)`); }
  }
  return findings;
}
