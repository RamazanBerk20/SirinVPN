// Keyboard focus check for the element Tab just reached. Evaluated by full_capture.py.
() => {
  const el = document.activeElement;
  if (!el || el === document.body) return null;
  const look = () => { const s = getComputedStyle(el); return [s.outlineStyle, s.outlineWidth, s.outlineColor, s.boxShadow, s.borderColor, s.backgroundColor, s.textDecorationLine].join("|"); };
  const focused = look();
  el.blur();
  const resting = look();
  el.focus();
  const r = el.getBoundingClientRect();
  const label = (el.getAttribute("aria-label") || el.innerText || el.value || el.placeholder || el.tagName).replace(/\s+/g, " ").trim().slice(0, 50);
  return { target: `${el.tagName.toLowerCase()} "${label}"`, visible: focused !== resting, onscreen: r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth };
}
