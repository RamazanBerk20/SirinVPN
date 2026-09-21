/** Visible evidence must intersect its scroll viewport and survive overlay hit testing. */
export function visibleBox(element: Element, hitTest = true) {
  const rect = element.getBoundingClientRect();
  let left = Math.max(0, rect.left), top = Math.max(0, rect.top);
  let right = Math.min(innerWidth, rect.right), bottom = Math.min(innerHeight, rect.bottom);
  for (let node: Element | null = element; node; node = node.parentElement) {
    const style = getComputedStyle(node);
    if (style.visibility === "hidden" || style.display === "none" || Number(style.opacity) === 0 || node.hasAttribute("inert")) return null;
    if (node !== element) {
      const box = node.getBoundingClientRect();
      if (/(auto|scroll|hidden|clip)/.test(style.overflowX)) { left = Math.max(left, box.left); right = Math.min(right, box.right); }
      if (/(auto|scroll|hidden|clip)/.test(style.overflowY)) { top = Math.max(top, box.top); bottom = Math.min(bottom, box.bottom); }
    }
  }
  if (right - left < 2 || bottom - top < 2) return null;
  if (hitTest) {
    const hit = document.elementFromPoint((left + right) / 2, (top + bottom) / 2);
    if (!hit || !(element.contains(hit) || hit.contains(element))) return null;
  }
  return { left, top, right, bottom, fullyVisible: rect.left >= left - 1 && rect.top >= top - 1 && rect.right <= right + 1 && rect.bottom <= bottom + 1 };
}
export async function settled() {
  await document.fonts.ready;
  await new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
}
export async function assertVisible(spec: { selector?: string; text?: string; scroll?: boolean; complete?: boolean }) {
  let nodes = spec.selector ? [...document.querySelectorAll(spec.selector)] : [...document.querySelectorAll("h1,h2,h3,p,span,button,small,label,summary,div[role]")]
    .filter(element => element.textContent?.replace(/\s+/g, " ").includes(spec.text ?? ""));
  nodes = nodes.filter(element => element.getClientRects().length && getComputedStyle(element).display !== "none");
  // A large tabpanel containing the text is not evidence that the text is visible.
  if (!spec.selector) nodes = nodes.filter(element => !nodes.some(other => other !== element && element.contains(other)));
  if (!nodes.length) throw Error(`Missing evidence target: ${JSON.stringify(spec)}`);
  let found = nodes.find(element => visibleBox(element));
  if (!found && spec.scroll !== false) { nodes[0].scrollIntoView({ block: "center", inline: "nearest" }); await settled(); found = nodes.find(element => visibleBox(element)); }
  if (!found) throw Error(`Evidence is outside the viewport or obscured: ${JSON.stringify(spec)}`);
  const box = visibleBox(found)!;
  if (spec.complete && !box.fullyVisible) throw Error(`Evidence is clipped: ${JSON.stringify(spec)}`);
  return { spec, box };
}
