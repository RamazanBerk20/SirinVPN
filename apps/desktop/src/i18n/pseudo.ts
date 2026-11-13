const ACCENTED: Record<string, string> = {
  a: "á", b: "ƀ", c: "ç", d: "ð", e: "é", f: "ƒ", g: "ĝ", h: "ĥ", i: "í", j: "ĵ", k: "ķ", l: "ļ", m: "ɱ",
  n: "ñ", o: "ó", p: "þ", q: "ǫ", r: "ŕ", s: "š", t: "ţ", u: "ú", v: "ṽ", w: "ŵ", x: "ẋ", y: "ý", z: "ž",
  A: "Á", B: "Ɓ", C: "Ç", D: "Ð", E: "É", F: "Ƒ", G: "Ĝ", H: "Ĥ", I: "Í", J: "Ĵ", K: "Ķ", L: "Ļ", M: "Ṁ",
  N: "Ñ", O: "Ó", P: "Þ", Q: "Ǫ", R: "Ŕ", S: "Š", T: "Ţ", U: "Ú", V: "Ṽ", W: "Ŵ", X: "Ẋ", Y: "Ý", Z: "Ž",
};

/**
 * Pseudo-localizes literal message text, leaving rich-text tags intact. Values placed into the
 * message are not passed through here, so they stay readable.
 * - expanded (en-XA): accented letters; `pseudoWrap` then pads the whole message.
 * - rtl (ar-XB): each word is a right-to-left override run, so English reads mirrored like an
 *   RTL script and anything not isolated shows up in the wrong place.
 */
export function pseudoLiteral(text: string, rtl: boolean): string {
  return text.split(/(<\/?\w+>)/).map((part, index) => index % 2 ? part
    : rtl ? part.replace(/[A-Za-z]+/g, word => `\u202E${word}\u202C`)
    : [...part].map(c => ACCENTED[c] ?? c).join("")).join("");
}

/** Pads text by 40% and brackets it, so clipped or concatenated strings stand out. */
export function pseudoWrap(text: string): string {
  const letters = text.replace(/<[^>]+>|\s/g, "").length;
  return `⟦${text}${"·".repeat(Math.ceil(letters * 0.4))}⟧`;
}

/** Accents and pads a whole string (tests and quick checks). */
export function pseudoLocalize(text: string): string {
  return pseudoWrap(pseudoLiteral(text, false));
}
