import { describe, expect, it } from "vitest";
import { en } from "./en";
import { availableLocales, interpolate, LANGUAGES, preferredLocale, pseudoLocales, resolveLocale, setLocale, sourceLocale, t, loadLocale, getLocale } from ".";
import { checkLocale, checkSource, flattenCatalog, formatMessage, parseMessage, type CatalogTree, type Flat } from "./message";
import { pseudoLocalize } from "./pseudo";
import allowList from "../locales/allowlist.json";

const english = flattenCatalog(en as unknown as CatalogTree);
const translations = import.meta.glob<{ default: CatalogTree }>(["../locales/*/*.json", "!../locales/en/*.json"], { eager: true });
const markers = Object.keys(import.meta.glob("../locales/*/UNTRANSLATED", { query: "?raw", eager: true }))
  .map(path => /locales\/([^/]+)\//.exec(path)![1]);
const sources = Object.entries(import.meta.glob<string>(["../**/*.{ts,tsx}", "!../**/*.test.{ts,tsx}", "!../test/**"], { query: "?raw", import: "default", eager: true }));
// Tray and notification text (native.*) is used from the Rust desktop shell.
const rust = Object.values(import.meta.glob<string>(["../../src-tauri/src/**/*.rs", "!../../src-tauri/src/**/tests.rs"], { query: "?raw", import: "default", eager: true }));
const code = [...sources.map(([, text]) => text), ...rust].join("\n");

describe("English catalog", () => {
  it("has clean, well-formed messages", () => {
    const problems: string[] = [...checkSource(english)];
    for (const [key, text] of english) {
      if (!/^[a-z][\w]*(\.[a-zA-Z][\w]*)*$/.test(key)) problems.push(`${key}: key format`);
      if (!text.trim() || text !== text.trim() || /\s{2,}/.test(text)) problems.push(`${key}: whitespace`);
      if (/'/.test(text)) problems.push(`${key}: use ’ instead of '`);
      if (/_(zero|one|two|few|many|other)$/.test(key)) problems.push(`${key}: plural suffix keys are replaced by {n, plural, …}`);
    }
    expect(problems).toEqual([]);
  });

  it("contains every key the code uses and nothing else", () => {
    const literals = new Set([...code.matchAll(/["'`]([a-z][\w]*(?:\.[a-zA-Z][\w]*)+)["'`]/g)].map(match => match[1]));
    const dynamic = [...code.matchAll(/`([a-z][\w]*(?:\.[a-zA-Z][\w]*)*\.)\$\{/g)].map(match => match[1]);
    const keys = new Set(english.keys());
    const unused = [...keys].filter(key => !literals.has(key) && !dynamic.some(prefix => key.startsWith(prefix)));
    const namespaces = new Set(Object.keys(en));
    const missing = [...code.matchAll(/(?:\bt\(|<Rich\s+id=)\s*["']([^"']+)["']/g)].map(match => match[1])
      .filter(key => namespaces.has(key.split(".")[0]) && !keys.has(key));
    expect({ unused, missing }).toEqual({ unused: [], missing: [] });
  });
});

describe("Translations", () => {
  const byLocale = new Map<string, Flat>();
  for (const [path, module] of Object.entries(translations)) {
    const [, locale, namespace] = /locales\/([^/]+)\/([^/]+)\.json$/.exec(path)!;
    flattenCatalog(module.default, `${namespace}.`, byLocale.get(locale) ?? byLocale.set(locale, new Map()).get(locale));
  }

  it("exist for every offered language", () => {
    expect(LANGUAGES.map(language => language.tag).filter(tag => tag !== sourceLocale && !byLocale.has(tag))).toEqual([]);
  });

  // Same keys, placeholders and tags as English, valid plurals with the language's CLDR forms, no
  // empty values; a value identical to English fails unless the folder is marked UNTRANSLATED.
  it.each([...byLocale.keys()])("%s matches English", locale => {
    const list = allowList as Record<string, string[]>;
    const report = checkLocale(locale, english, byLocale.get(locale)!, new Set([...(list["*"] ?? []), ...(list[locale] ?? [])]));
    if (markers.includes(locale)) report.untranslated = [];
    expect(report).toEqual({ missing: [], extra: [], failures: [], untranslated: [] });
  });

  it("reports what a translator would get wrong", () => {
    const source: Flat = new Map([["a.b", "{count, plural, one {# device} other {# devices}} for {{name}}"], ["a.c", "Open <b>the settings</b> now please"]]);
    const report = checkLocale("ru", source, new Map([["a.b", "{count, plural, one {# устройство} other {# устройств}} для {{label}}"], ["a.c", "Open <b>the settings</b> now please"], ["a.d", "x"]]));
    expect(report.extra).toEqual(["a.d"]);
    expect(report.untranslated).toEqual(["a.c"]);
    expect(report.failures.join("\n")).toMatch(/placeholders differ/);
    expect(report.failures.join("\n")).toMatch(/lacks few, many/);
    expect(checkLocale("ja", source, new Map([["a.b", "{count, plural, one {#台} other {#台}} {{name}}"]])).failures.join()).toMatch(/one, which ja never uses/);
    expect(checkLocale("de", source, new Map([["a.b", "{count, plural, one {# Gerät} other {# Geräte} für {{name}}"]])).failures.join()).toMatch(/syntax/);
  });
});

describe("Message lookup", () => {
  const format = (text: string, locale: string, params: Record<string, string | number>) => formatMessage(parseMessage(text), params, {
    plural: value => new Intl.PluralRules(locale).select(value), number: value => new Intl.NumberFormat(locale).format(value), text: value => value,
  });

  it("interpolates, pluralizes on any numeric value and falls back", () => {
    expect(interpolate("{{a}} and {{ b }}", { a: 1, b: "two" })).toBe("1 and two");
    expect(interpolate("{{n}} items", { n: 12345 })).toBe("12,345 items");
    expect(interpolate("{left, plural, =0 {None left} one {# use left} other {# uses left}} of {{max}}", { left: 0, max: 5 })).toBe("None left of 5");
    expect(interpolate("{left, plural, =0 {None left} one {# use left} other {# uses left}} of {{max}}", { left: 1, max: 5 })).toBe("1 use left of 5");
    expect(t("format.dnsPolicy.dnsOverTls", { count: 1 })).toBe("DNS over TLS · 1 server");
    expect(t("format.dnsPolicy.dnsOverTls", { count: 3 })).toBe("DNS over TLS · 3 servers");
    expect(availableLocales()).toContain(sourceLocale);
  });

  it("selects every CLDR plural form, with nested plurals and exact matches", () => {
    const ar = (n: number) => new Intl.NumberFormat("ar").format(n);
    const arabic = "{n, plural, =0 {لا أجهزة} zero {zero} one {جهاز واحد} two {جهازان} few {# أجهزة} many {# جهازًا} other {# جهاز}}";
    expect([0, 1, 2, 3, 11, 100].map(n => format(arabic, "ar", { n }))).toEqual(["لا أجهزة", "جهاز واحد", "جهازان", `${ar(3)} أجهزة`, `${ar(11)} جهازًا`, `${ar(100)} جهاز`]);
    const russian = "{n, plural, one {# устройство} few {# устройства} many {# устройств} other {# устройства}}";
    expect([1, 3, 5, 21, 1.5].map(n => format(russian, "ru", { n }))).toEqual(["1 устройство", "3 устройства", "5 устройств", "21 устройство", "1,5 устройства"]);
    expect(format("{a, plural, one {# of {b, plural, one {# item} other {# items}}} other {# of {b, plural, one {# item} other {# items}}}}", "en", { a: 2, b: 1 })).toBe("2 of 1 item");
    expect(format("{n, plural, other {# 台}}", "ja", { n: 1 })).toBe("1 台");
    expect(() => parseMessage("{n, plural, one {x}}")).toThrow(/other/);
    expect(() => parseMessage("{n, plural, single {x} other {y}}")).toThrow(/category/);
    expect(() => parseMessage("Hi {{ name }")).toThrow();
  });

  it("matches system languages to offered ones", () => {
    expect(resolveLocale(["xx-YY", "en-GB"])).toBe("en");
    expect(resolveLocale(["tr-TR"])).toBe("tr");
    for (const tag of ["zh-Hans-CN", "zh-CN", "zh-SG", "zh-TW", "zh-Hant", "zh-HK", "zh"]) expect(resolveLocale([tag])).toBe("zh-Hans");
    expect(resolveLocale(["pt-BR"])).toBe("en");
    expect(resolveLocale(["pt-BR", "de-AT"])).toBe("de");
    expect(resolveLocale(["not a tag", "ar-EG"])).toBe("ar");
    expect(preferredLocale("ko")).toBe("ko");
  });

  it("switches language, direction and document language", async () => {
    await loadLocale("ar");
    setLocale("ar");
    expect([getLocale(), document.documentElement.dir, document.documentElement.lang]).toEqual(["ar", "rtl", "ar"]);
    // In a right-to-left interface every string value is isolated; numbers use the language's digits.
    expect(interpolate("{{name}}: {{n}}", { name: "Home", n: 3 })).toBe(`\u2068Home\u2069: ${new Intl.NumberFormat("ar").format(3)}`);
    // Letter-free values (clock parts, addresses) are not isolated piece by piece.
    expect(interpolate("{{h}}:{{m}}", { h: "1", m: "05" })).toBe("1:05");
    setLocale("zh-Hans");
    expect([document.documentElement.dir, document.documentElement.lang]).toEqual(["ltr", "zh-Hans"]);
    setLocale(sourceLocale);
    // A right-to-left value inside left-to-right text is isolated too.
    expect(interpolate("Remove {{name}}?", { name: "محمد" })).toBe("Remove \u2068محمد\u2069?");
    expect(interpolate("Remove {{name}}?", { name: "Home" })).toBe("Remove Home?");
  });

  it("pseudo-localizes literal text only, keeping tags and values", () => {
    expect(pseudoLocalize("Open <b>Settings</b>")).toMatch(/^⟦Óþéñ <b>Šéţţíñĝš<\/b>·+⟧$/);
    setLocale(pseudoLocales.expanded);
    expect(interpolate("Hi {{name}}", { name: "Ann" })).toBe("Ĥí Ann");
    setLocale(pseudoLocales.rtl);
    expect(document.documentElement.dir).toBe("rtl");
    expect(interpolate("Hi {{name}}", { name: "Ann" })).toBe("\u202EHi\u202C \u2068Ann\u2069");
    setLocale(sourceLocale);
  });
});

describe("Component text", () => {
  it("routes visible JSX text through the catalog", () => {
    const attributes = /\s(?:aria-label|aria-description|title|placeholder|alt|label|heading|description|hint|message|summary)="([^"]*[A-Za-z][^"]*)"/g;
    const problems: string[] = [];
    for (const [path, text] of sources) {
      if (!path.endsWith(".tsx")) continue;
      text.split("\n").forEach((line, index) => {
        if (line.includes("i18n-ignore") || /^\s*(\/\/|\*|\/\*)/.test(line)) return;
        for (const match of line.matchAll(attributes)) problems.push(`${path}:${index + 1}: ${match[0].trim()}`);
        // Text between tags on one line, e.g. <span>Copy</span>; arrows and generics are not tags.
        for (const match of line.matchAll(/(?<![=-])>\s*([A-Za-z][^<>{}=;&|?:()]*?)\s*(?:<|$)/g)) {
          const value = match[1].trim();
          if (/[A-Za-z]{2,}/.test(value) && !/^(extends|as|keyof|typeof|infer|is|void|string|number|boolean|null|undefined|never|unknown)\b/.test(value))
            problems.push(`${path}:${index + 1}: ${value}`);
        }
        // A line of prose inside a multi-line element.
        if (/^\s*[A-Z][a-z’']+(\s+[\w’',.-]+)+[.,!?]?\s*$/.test(line) && !/[(){};=]/.test(line))
          problems.push(`${path}:${index + 1}: ${line.trim()}`);
      });
    }
    expect(problems).toEqual([]);
  });
});
