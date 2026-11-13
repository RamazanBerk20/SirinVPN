/**
 * Message syntax for the catalogs (also documented for translators in docs/translating.md):
 *
 * - `{{name}}` inserts a value. Numbers are formatted for the active language.
 * - `{name, plural, =0 {…} one {…} few {…} other {…}}` picks a form by the number in `name`
 *   (ICU MessageFormat plural syntax, CLDR categories zero/one/two/few/many/other, `=N` for an
 *   exact number). Inside a form, `#` is that number, formatted.
 * - `<tag>…</tag>` marks rich text rendered by <Rich>; tags are plain text to this parser.
 *
 * Pure and dependency-free: the app, the catalog test and `pnpm i18n:check` (Node) share it.
 */
export type MessageNode = string | { arg: string } | { pound: true } | { plural: string; options: Record<string, MessageNode[]> };
export type Message = MessageNode[];

const CATEGORIES = new Set(["zero", "one", "two", "few", "many", "other"]);

export function parseMessage(text: string): Message {
  let i = 0;
  const fail = (what: string): never => { throw new Error(`${what} at ${i}`); };

  function sequence(inPlural: boolean, nested: boolean): Message {
    const out: Message = [];
    let literal = "";
    const flush = () => { if (literal) out.push(literal); literal = ""; };
    while (i < text.length) {
      const c = text[i];
      if (c === "{" && text[i + 1] === "{") {
        const close = text.indexOf("}}", i + 2);
        const name = close < 0 ? "" : text.slice(i + 2, close).trim();
        if (!/^[\w.]+$/.test(name)) fail("malformed {{placeholder}}");
        flush();
        out.push({ arg: name });
        i = close + 2;
      } else if (c === "{") {
        flush();
        out.push(plural());
      } else if (c === "}") {
        if (!nested) fail("unexpected }");
        flush();
        return out;
      } else if (c === "#" && inPlural) {
        flush();
        out.push({ pound: true });
        i++;
      } else {
        literal += c;
        i++;
      }
    }
    if (nested) fail("unclosed {");
    flush();
    return out;
  }

  function plural(): MessageNode {
    i++;
    const head = /^\s*([\w.]+)\s*,\s*plural\s*,/.exec(text.slice(i)) ?? fail("expected {name, plural, …}");
    i += head[0].length;
    const options: Record<string, Message> = {};
    for (let option; (option = /^\s*(=\d+|[a-z]+)\s*\{/.exec(text.slice(i)));) {
      const selector = option[1];
      if (!selector.startsWith("=") && !CATEGORIES.has(selector)) fail(`unknown plural category "${selector}"`);
      if (selector in options) fail(`duplicate plural form "${selector}"`);
      i += option[0].length;
      options[selector] = sequence(true, true);
      i++;
    }
    const close = /^\s*\}/.exec(text.slice(i)) ?? fail("malformed plural");
    i += close[0].length;
    if (!options.other) fail("plural without an \"other\" form");
    return { plural: head[1], options };
  }

  return sequence(false, false);
}

export type FormatContext = {
  /** CLDR category of a number in the active language. */
  plural: (value: number) => string;
  number: (value: number) => string;
  /** Formats a string value, e.g. to isolate its direction. */
  text: (value: string) => string;
  /** Transforms literal message text (pseudo-localization); identity otherwise. */
  literal?: (value: string) => string;
  missing?: (name: string) => void;
};

export function formatMessage(message: Message, params: Readonly<Record<string, string | number>> | undefined, context: FormatContext, pound?: number): string {
  let out = "";
  for (const node of message) {
    if (typeof node === "string") out += context.literal ? context.literal(node) : node;
    else if ("pound" in node) out += pound === undefined ? "#" : context.number(pound);
    else if ("arg" in node) {
      const value = params?.[node.arg];
      if (value === undefined) { context.missing?.(node.arg); out += `{{${node.arg}}}`; }
      else out += typeof value === "number" ? context.number(value) : context.text(value);
    } else {
      const raw = params?.[node.plural];
      const value = typeof raw === "number" ? raw : Number(raw);
      if (raw === undefined) context.missing?.(node.plural);
      const form = Number.isFinite(value)
        ? node.options[`=${value}`] ?? node.options[context.plural(value)] ?? node.options.other
        : node.options.other;
      out += formatMessage(form, params, context, Number.isFinite(value) ? value : undefined);
    }
  }
  return out;
}

/** Every value name a message reads, plural or not, sorted and unique. */
export function messageArguments(message: Message, out = new Set<string>()): string[] {
  for (const node of message) {
    if (typeof node === "string" || "pound" in node) continue;
    if ("arg" in node) out.add(node.arg);
    else {
      out.add(node.plural);
      for (const form of Object.values(node.options)) messageArguments(form, out);
    }
  }
  return [...out].sort();
}

/** Each plural in a message: the value it reads and the forms it has. */
export function messagePlurals(message: Message, out: { name: string; forms: string[] }[] = []): { name: string; forms: string[] }[] {
  for (const node of message) {
    if (typeof node === "object" && "plural" in node) {
      out.push({ name: node.plural, forms: Object.keys(node.options) });
      for (const form of Object.values(node.options)) messagePlurals(form, out);
    }
  }
  return out;
}

/** Rich-text tag names used in a message, sorted and unique. */
export function messageTags(text: string): string[] {
  return [...new Set([...text.matchAll(/<\/?(\w+)>/g)].map(match => match[1]))].sort();
}

/** Rich-text tags are balanced and not nested across plural forms. */
export function tagsBalanced(text: string): boolean {
  const stack: string[] = [];
  for (const [, closing, name] of text.matchAll(/<(\/?)(\w+)>/g)) {
    if (!closing) stack.push(name);
    else if (stack.pop() !== name) return false;
  }
  return stack.length === 0;
}

export type Flat = Map<string, string>;
export type CatalogTree = { readonly [key: string]: string | CatalogTree };

export function flattenCatalog(catalog: CatalogTree, prefix = "", out: Flat = new Map()): Flat {
  for (const [key, value] of Object.entries(catalog)) {
    if (typeof value === "string") out.set(prefix + key, value);
    else flattenCatalog(value, `${prefix}${key}.`, out);
  }
  return out;
}

export type LocaleReport = {
  missing: string[];
  extra: string[];
  /** Structural problems: always fail the check. */
  failures: string[];
  /** Values identical to English (longer than a few words), not on the allow-list. */
  untranslated: string[];
};

const words = (text: string) => text.replace(/<[^>]+>|\{\{[^}]*\}\}/g, " ").trim().split(/\s+/).filter(Boolean).length;

/**
 * Compares one locale's flattened catalog with English. A value identical to English is treated as
 * not yet translated: it skips the plural-category check, and is listed in `untranslated` when it is
 * longer than three words and its key is not allow-listed.
 */
export function checkLocale(locale: string, english: Flat, translated: Flat, allowed: ReadonlySet<string> = new Set()): LocaleReport {
  const report: LocaleReport = { missing: [], extra: [], failures: [], untranslated: [] };
  let categories: string[];
  try { categories = new Intl.PluralRules(locale).resolvedOptions().pluralCategories; }
  catch { categories = ["other"]; report.failures.push(`${locale}: not a valid language tag`); }
  for (const key of english.keys()) if (!translated.has(key)) report.missing.push(key);
  for (const [key, text] of translated) {
    const source = english.get(key);
    if (source === undefined) { report.extra.push(key); continue; }
    const problem = (what: string) => report.failures.push(`${key}: ${what}`);
    if (!text.trim()) { problem("empty"); continue; }
    let parsed: Message;
    try { parsed = parseMessage(text); } catch (error) { problem(`syntax: ${(error as Error).message}`); continue; }
    const original = parseMessage(source);
    if (messageArguments(parsed).join() !== messageArguments(original).join())
      problem(`placeholders differ: ${messageArguments(parsed).join(", ") || "none"} instead of ${messageArguments(original).join(", ") || "none"}`);
    if (messageTags(text).join() !== messageTags(source).join() || !tagsBalanced(text)) problem("rich-text tags differ or are unbalanced");
    if (text === source) {
      if (words(text) > 3 && !allowed.has(key)) report.untranslated.push(key);
      continue;
    }
    for (const { name, forms } of messagePlurals(parsed)) {
      const lacking = categories.filter(category => !forms.includes(category));
      const unused = forms.filter(form => !form.startsWith("=") && !categories.includes(form));
      if (lacking.length) problem(`plural "${name}" lacks ${lacking.join(", ")} (${locale} uses ${categories.join(", ")})`);
      if (unused.length) problem(`plural "${name}" has ${unused.join(", ")}, which ${locale} never uses`);
    }
  }
  return report;
}

/** English source checks: syntax, balanced tags, plural forms English needs. */
export function checkSource(english: Flat): string[] {
  const problems: string[] = [];
  for (const [key, text] of english) {
    try {
      for (const { name, forms } of messagePlurals(parseMessage(text)))
        if (!forms.includes("one")) problems.push(`${key}: plural "${name}" lacks "one"`);
    } catch (error) { problems.push(`${key}: syntax: ${(error as Error).message}`); }
    if (!tagsBalanced(text)) problems.push(`${key}: unbalanced tags`);
  }
  return problems;
}
