import { en, type Messages } from "./en";
import { pseudoLocalize } from "./pseudo";

/**
 * Interface text lives in src/locales/<locale>/<namespace>.json, using i18next-style
 * JSON: nested keys, {{name}} placeholders and _one/_other plural suffixes. English is
 * the source catalog; any other locale folder is picked up automatically and falls
 * back to English key by key.
 */
type PluralCategory = Intl.LDMLPluralRule;
type Leaves<T, P extends string = ""> = {
  [K in keyof T & string]: T[K] extends string ? `${P}${K}` : Leaves<T[K], `${P}${K}.`>;
}[keyof T & string];
type StripPlural<K extends string> = K extends `${infer Base}_${PluralCategory}` ? Base : K;

export type MessageKey = StripPlural<Leaves<Messages>>;
export type MessageParams = Readonly<Record<string, string | number>>;
export type Catalog = { readonly [key: string]: string | Catalog };

export const sourceLocale = "en";
/** Development-only pseudo-locale: accented, padded text exposes hard-coded or clipped strings. */
export const pseudoLocale = "en-XA";
const LOCALE_STORAGE_KEY = "sirin.locale";
const RTL_LANGUAGES = new Set(["ar", "ckb", "dv", "fa", "he", "ps", "sd", "ug", "ur", "yi"]);

const catalogs: Record<string, Record<string, Catalog>> = { [sourceLocale]: en };
const translations = import.meta.glob<{ default: Catalog }>("../locales/*/*.json", { eager: true });
for (const [path, module] of Object.entries(translations)) {
  const match = /locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
  if (!match || match[1] === sourceLocale) continue;
  (catalogs[match[1]] ??= {})[match[2]] = module.default;
}

let locale = sourceLocale;
let chain: { locale: string; catalog: Catalog; rules: Intl.PluralRules }[] = [];

export function availableLocales(): string[] {
  return Object.keys(catalogs);
}

export function getLocale(): string {
  return locale;
}

/** Picks the first supported locale from a preference list, matching base languages too. */
export function resolveLocale(preferred: readonly string[]): string {
  for (const tag of preferred) {
    let canonical: string;
    try { [canonical] = Intl.getCanonicalLocales(tag); } catch { continue; }
    if (!canonical) continue;
    if (catalogs[canonical]) return canonical;
    const base = canonical.split("-")[0];
    if (catalogs[base]) return base;
  }
  return sourceLocale;
}

export function setLocale(next: string): void {
  const pseudo = import.meta.env.DEV && next === pseudoLocale;
  locale = pseudo ? pseudoLocale : resolveLocale([next]);
  const order = locale === sourceLocale || pseudo ? [sourceLocale] : [locale, sourceLocale];
  chain = order.map(tag => ({ locale: tag, catalog: catalogs[tag], rules: new Intl.PluralRules(tag) }));
  if (typeof document !== "undefined") {
    document.documentElement.lang = locale;
    document.documentElement.dir = RTL_LANGUAGES.has(locale.split("-")[0]) ? "rtl" : "ltr";
  }
}

/** Chooses the interface locale from saved choice or system languages. Changing it later requires a reload. */
export function initLocale(): void {
  let stored: string | null = null;
  try { stored = localStorage.getItem(LOCALE_STORAGE_KEY); } catch { /* Storage can be unavailable. */ }
  if (stored === pseudoLocale && import.meta.env.DEV) return setLocale(pseudoLocale);
  setLocale(resolveLocale([...(stored ? [stored] : []), ...(typeof navigator === "undefined" ? [] : navigator.languages ?? [navigator.language])]));
}

function lookup(catalog: Catalog | undefined, key: string): string | undefined {
  let node: string | Catalog | undefined = catalog;
  for (const part of key.split(".")) {
    if (node === undefined || typeof node === "string") return undefined;
    node = node[part];
  }
  return typeof node === "string" ? node : undefined;
}

function select({ catalog, rules }: (typeof chain)[number], key: string, count: unknown): string | undefined {
  if (typeof count === "number") {
    return (count === 0 ? lookup(catalog, `${key}_zero`) : undefined)
      ?? lookup(catalog, `${key}_${rules.select(count)}`)
      ?? lookup(catalog, `${key}_other`)
      ?? lookup(catalog, key);
  }
  return lookup(catalog, key);
}

export function interpolate(message: string, params?: MessageParams): string {
  return message.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (placeholder, name: string) => {
    const value = params?.[name];
    if (value === undefined) {
      if (import.meta.env.DEV) console.warn(`Missing message parameter "${name}"`);
      return placeholder;
    }
    return String(value);
  });
}

/** Returns the interface text for a key. Pass `count` to select a plural form. */
export function t(key: MessageKey, params?: MessageParams): string {
  for (const entry of chain) {
    const message = select(entry, key, params?.count);
    if (message !== undefined) {
      const text = interpolate(message, params);
      return locale === pseudoLocale ? pseudoLocalize(text) : text;
    }
  }
  if (import.meta.env.DEV) console.warn(`Missing message "${key}"`);
  return key;
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

function intlLocale(): string {
  return locale === pseudoLocale ? sourceLocale : locale;
}

// Runs on first import, before any module asks for text.
initLocale();
