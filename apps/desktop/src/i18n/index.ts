import { useSyncExternalStore } from "react";
import { en, type Messages } from "./en";
import { formatMessage, parseMessage, type CatalogTree, type FormatContext, type Message } from "./message";
import { pseudoLiteral, pseudoWrap } from "./pseudo";

/**
 * Interface text lives in src/locales/<locale>/<namespace>.json: nested keys, `{{name}}`
 * values, ICU plurals `{name, plural, one {…} other {…}}` and `<tag>` rich text (see
 * ./message.ts and docs/translating.md). English is bundled; every other language is loaded
 * on demand, one chunk per namespace, and falls back to English key by key.
 */
type Leaves<T, P extends string = ""> = {
  [K in keyof T & string]: T[K] extends string ? `${P}${K}` : Leaves<T[K], `${P}${K}.`>;
}[keyof T & string];

export type MessageKey = Leaves<Messages>;
export type MessageParams = Readonly<Record<string, string | number>>;
export type Catalog = CatalogTree;

export const sourceLocale = "en";
/** The languages offered, each named in itself. Codes match the locale folders and Android's locales_config. */
export const LANGUAGES = [
  { tag: "en", name: "English" },
  { tag: "tr", name: "Türkçe" },
  { tag: "es", name: "Español" },
  { tag: "fr", name: "Français" },
  { tag: "de", name: "Deutsch" },
  { tag: "ru", name: "Русский" },
  { tag: "ar", name: "\u0627\u0644\u0639\u0631\u0628\u064A\u0629" },
  { tag: "zh-Hans", name: "中文（简体）" },
  { tag: "ja", name: "日本語" },
  { tag: "ko", name: "한국어" },
] as const;
/** Development-only pseudo-locales: accented and 40% longer text, and mirrored right-to-left text. */
export const pseudoLocales = { expanded: "en-XA", rtl: "ar-XB" } as const;
export const SYSTEM_LANGUAGE = "system";
const RTL_LANGUAGES = new Set(["ar", "ckb", "dv", "fa", "he", "ps", "sd", "ug", "ur", "yi"]);

const loaders = import.meta.glob<{ default: Catalog }>(["../locales/*/*.json", "!../locales/en/*.json"]);
const catalogs: Record<string, Record<string, Catalog>> = { [sourceLocale]: en as unknown as Record<string, Catalog> };
const parsed = new Map<string, Message | null>();

let locale: string = sourceLocale;
let chain: { locale: string; catalog: Record<string, Catalog> }[] = [{ locale: sourceLocale, catalog: catalogs[sourceLocale] }];
let pluralRules = new Intl.PluralRules(sourceLocale);
let numberFormat = new Intl.NumberFormat(sourceLocale);
const listeners = new Set<() => void>();

const isPseudo = (tag: string) => import.meta.env.DEV && (tag === pseudoLocales.expanded || tag === pseudoLocales.rtl);

/** Languages with a catalog (English is always one). */
export function availableLocales(): string[] {
  const tags = new Set([sourceLocale]);
  for (const path of Object.keys(loaders)) tags.add(/locales\/([^/]+)\//.exec(path)![1]);
  return [...tags];
}

export function getLocale(): string {
  return locale;
}

export function isRtl(tag = locale): boolean {
  return tag === pseudoLocales.rtl || RTL_LANGUAGES.has(tag.split("-")[0]);
}

/**
 * Picks the first offered language from a preference list (an OS language list, or one saved
 * choice): exact tag, then base language; any Chinese goes to Simplified Chinese, which is the
 * only Chinese offered. Anything else falls through to the next entry, then English.
 */
export function resolveLocale(preferred: readonly string[]): string {
  const offered = new Set(availableLocales());
  for (const tag of preferred) {
    if (isPseudo(tag)) return tag;
    let canonical: string;
    try { [canonical] = Intl.getCanonicalLocales(tag); } catch { continue; }
    if (!canonical) continue;
    const base = canonical.split("-")[0];
    const candidate = offered.has(canonical) ? canonical : base === "zh" ? "zh-Hans" : base;
    if (offered.has(candidate)) return candidate;
  }
  return sourceLocale;
}

/** The language a saved preference ("system" or a tag) means on this device now. */
export function preferredLocale(preference: string | null | undefined): string {
  const system = typeof navigator === "undefined" ? [] : navigator.languages?.length ? navigator.languages : [navigator.language];
  return resolveLocale(preference && preference !== SYSTEM_LANGUAGE ? [preference] : system);
}

/** Loads a language's catalog. Resolves even if a chunk fails: missing text falls back to English. */
export async function loadLocale(tag: string): Promise<void> {
  if (catalogs[tag]) return;
  const entries = Object.entries(loaders).filter(([path]) => path.includes(`/locales/${tag}/`));
  const modules = await Promise.all(entries.map(([path, load]) => load().then(module => [path, module.default] as const, () => null)));
  const catalog: Record<string, Catalog> = {};
  for (const entry of modules) if (entry) catalog[/([^/]+)\.json$/.exec(entry[0])![1]] = entry[1];
  catalogs[tag] = catalog;
}

/** Switches the active language. Load its catalog first with `loadLocale`; until then English is shown. */
export function setLocale(next: string): void {
  locale = isPseudo(next) ? next : resolveLocale([next]);
  const order = locale === sourceLocale || isPseudo(locale) ? [sourceLocale] : [locale, sourceLocale];
  chain = order.map(tag => ({ locale: tag, catalog: catalogs[tag] ?? {} }));
  pluralRules = new Intl.PluralRules(intlLocale());
  numberFormat = new Intl.NumberFormat(intlLocale());
  parsed.clear();
  if (typeof document !== "undefined") {
    document.documentElement.lang = locale === pseudoLocales.rtl ? "ar" : locale === pseudoLocales.expanded ? "en" : locale;
    document.documentElement.dir = isRtl() ? "rtl" : "ltr";
  }
  for (const listener of listeners) listener();
}

/** Re-renders the caller when the language changes. */
export function useLocale(): string {
  return useSyncExternalStore(subscribe, getLocale, getLocale);
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

function lookup(catalog: Record<string, Catalog>, key: string): string | undefined {
  let node: string | Catalog | undefined = catalog;
  for (const part of key.split(".")) {
    if (node === undefined || typeof node === "string") return undefined;
    node = node[part];
  }
  return typeof node === "string" ? node : undefined;
}

function message(key: string): Message | null {
  const cacheKey = `${locale}\u0000${key}`;
  let result = parsed.get(cacheKey);
  if (result !== undefined) return result;
  result = null;
  for (const entry of chain) {
    const text = lookup(entry.catalog, key);
    if (text === undefined) continue;
    try { result = parseMessage(text); break; } catch {
      // A malformed translation falls back to English rather than showing syntax.
      if (import.meta.env.DEV) console.warn(`Malformed message "${key}" in ${entry.locale}`);
    }
  }
  parsed.set(cacheKey, result);
  return result;
}

const STRONG_RTL = /[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFF]/;
/**
 * First-strong isolation (FSI…PDI) keeps a value's own direction from reordering the sentence around it.
 * Values without letters (numbers, clock parts, addresses) are left bare: digits already keep their
 * order, and isolating each part of "1:05:09" separately would reverse the parts in RTL text.
 */
const isolate = (value: string) => /\p{L}/u.test(value) && (isRtl() || STRONG_RTL.test(value)) ? `\u2068${value}\u2069` : value;

function context(): FormatContext {
  return {
    plural: value => pluralRules.select(value),
    number: value => numberFormat.format(value),
    text: isolate,
    literal: locale === pseudoLocales.expanded || locale === pseudoLocales.rtl ? text => pseudoLiteral(text, locale === pseudoLocales.rtl) : undefined,
    missing: name => { if (import.meta.env.DEV) console.warn(`Missing message parameter "${name}"`); },
  };
}

/** Formats a message string directly (for tests and text that is not in the catalog). */
export function interpolate(text: string, params?: MessageParams): string {
  return formatMessage(parseMessage(text), params, context());
}

/** Returns the interface text for a key, with values and plural forms filled in. */
export function t(key: MessageKey, params?: MessageParams): string {
  const found = message(key);
  if (!found) {
    if (import.meta.env.DEV) console.warn(`Missing message "${key}"`);
    return key;
  }
  const text = formatMessage(found, params, context());
  return locale === pseudoLocales.expanded ? pseudoWrap(text) : text;
}

/** Locale-aware formatters for values placed inside messages. */
export function formatNumber(value: number, options?: Intl.NumberFormatOptions): string {
  return new Intl.NumberFormat(intlLocale(), options).format(value);
}

export function formatList(items: readonly string[], type: Intl.ListFormatType = "conjunction"): string {
  return new Intl.ListFormat(intlLocale(), { style: "long", type }).format(items);
}

export function formatDateTime(value: Date, options: Intl.DateTimeFormatOptions): string {
  return new Intl.DateTimeFormat(intlLocale(), options).format(value);
}

export function formatRelativeTime(value: number, unit: Intl.RelativeTimeFormatUnit, options?: Intl.RelativeTimeFormatOptions): string {
  return new Intl.RelativeTimeFormat(intlLocale(), { numeric: "auto", ...options }).format(value, unit);
}

/** Compares and folds interface text by the active language's rules (sorting, search). */
export function compareText(a: string, b: string): number {
  return a.localeCompare(b, intlLocale(), { sensitivity: "base", numeric: true });
}

export function foldText(text: string): string {
  return text.toLocaleLowerCase(intlLocale());
}

/** The tag to pass to Intl APIs: pseudo-locales format like English. */
export function intlLocale(): string {
  return locale === pseudoLocales.expanded ? sourceLocale : locale === pseudoLocales.rtl ? "ar" : locale;
}

// English needs no loading; the saved language is applied by ./language before the first render.
setLocale(sourceLocale);
