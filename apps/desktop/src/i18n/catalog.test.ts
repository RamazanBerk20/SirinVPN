import { describe, expect, it } from "vitest";
import { en } from "./en";
import { availableLocales, interpolate, resolveLocale, setLocale, sourceLocale, t, type Catalog } from ".";
import { pseudoLocalize } from "./pseudo";

type Flat = Map<string, string>;
const PLURAL = /_(zero|one|two|few|many|other)$/;

function flatten(catalog: Catalog, prefix = "", out: Flat = new Map()): Flat {
  for (const [key, value] of Object.entries(catalog)) {
    if (typeof value === "string") out.set(prefix + key, value);
    else flatten(value, `${prefix}${key}.`, out);
  }
  return out;
}

const placeholders = (text: string) => [...text.matchAll(/\{\{\s*([\w.]+)\s*\}\}/g)].map(match => match[1]).sort();
const tags = (text: string) => [...text.matchAll(/<\/?(\w+)>/g)].map(match => match[0]).sort();
const base = (key: string) => key.replace(PLURAL, "");

const english = flatten(en as unknown as Catalog);
const translations = import.meta.glob<{ default: Catalog }>("../locales/*/*.json", { eager: true });
const sources = Object.entries(import.meta.glob<string>(["../**/*.{ts,tsx}", "!../**/*.test.{ts,tsx}", "!../test/**"], { query: "?raw", import: "default", eager: true }));
// Tray and notification text (native.*) is used from the Rust desktop shell.
const rust = Object.values(import.meta.glob<string>(["../../src-tauri/src/**/*.rs", "!../../src-tauri/src/**/tests.rs"], { query: "?raw", import: "default", eager: true }));
const code = [...sources.map(([, text]) => text), ...rust].join("\n");

describe("English catalog", () => {
  it("has clean, well-formed messages", () => {
    const problems: string[] = [];
    for (const [key, text] of english) {
      if (!/^[a-z][\w]*(\.[a-zA-Z][\w]*)*$/.test(key)) problems.push(`${key}: key format`);
      if (!text.trim() || text !== text.trim() || /\s{2,}/.test(text)) problems.push(`${key}: whitespace`);
      if (/(^|[^{])\{(?!\{)|[^}]\}(?!\})/.test(text.replace(/\{\{\s*[\w.]+\s*\}\}/g, ""))) problems.push(`${key}: malformed placeholder`);
      const opened = [...text.matchAll(/<(\w+)>/g)].map(match => match[1]);
      const closed = [...text.matchAll(/<\/(\w+)>/g)].map(match => match[1]);
      if (opened.join() !== closed.join()) problems.push(`${key}: unbalanced tags`);
      if (/'/.test(text)) problems.push(`${key}: use ’ instead of '`);
      if (PLURAL.test(key) && !english.has(`${base(key)}_other`)) problems.push(`${key}: plural group without _other`);
    }
    expect(problems).toEqual([]);
  });

  it("contains every key the code uses and nothing else", () => {
    const literals = new Set([...code.matchAll(/["'`]([a-z][\w]*(?:\.[a-zA-Z][\w]*)+)["'`]/g)].map(match => match[1]));
    const dynamic = [...code.matchAll(/`([a-z][\w]*(?:\.[a-zA-Z][\w]*)*\.)\$\{/g)].map(match => match[1]);
    const keys = new Set([...english.keys()].map(base));
    const unused = [...keys].filter(key => !literals.has(key) && !dynamic.some(prefix => key.startsWith(prefix)));
    const namespaces = new Set(Object.keys(en));
    const missing = [...code.matchAll(/(?:\bt\(|<Rich\s+id=)\s*["']([^"']+)["']/g)].map(match => match[1])
      .filter(key => namespaces.has(key.split(".")[0]) && !keys.has(key));
    expect({ unused, missing }).toEqual({ unused: [], missing: [] });
  });
});

describe("Translations", () => {
  it("match the English keys, placeholders, tags and plural rules", () => {
    const problems: string[] = [];
    for (const [path, module] of Object.entries(translations)) {
      const [, locale, namespace] = /locales\/([^/]+)\/([^/]+)\.json$/.exec(path)!;
      if (locale === sourceLocale) continue;
      if (!(namespace in en)) problems.push(`${path}: unknown namespace`);
      const categories = new Intl.PluralRules(locale).resolvedOptions().pluralCategories;
      const translated = flatten(module.default, `${namespace}.`);
      for (const [key, text] of translated) {
        const source = english.get(key) ?? english.get(`${base(key)}_other`);
        if (source === undefined) { problems.push(`${locale}/${key}: not in English`); continue; }
        if (placeholders(text).filter(name => name !== "count").join() !== placeholders(source).filter(name => name !== "count").join()) problems.push(`${locale}/${key}: placeholders differ`);
        if (tags(text).join() !== tags(source).join()) problems.push(`${locale}/${key}: tags differ`);
      }
      for (const key of new Set([...english.keys()].filter(key => PLURAL.test(key) && key.startsWith(`${namespace}.`)).map(base))) {
        if ([...translated.keys()].some(item => base(item) === key))
          for (const category of categories) if (!translated.has(`${key}_${category}`) && !(category === "other")) problems.push(`${locale}/${key}: missing _${category}`);
      }
    }
    expect(problems).toEqual([]);
  });
});

describe("Message lookup", () => {
  it("interpolates, pluralizes and falls back", () => {
    expect(interpolate("{{a}} and {{ b }}", { a: 1, b: "two" })).toBe("1 and two");
    expect(t("format.dnsPolicy.dnsOverTls", { count: 1 })).toBe("DNS over TLS · 1 server");
    expect(t("format.dnsPolicy.dnsOverTls", { count: 3 })).toBe("DNS over TLS · 3 servers");
    expect(resolveLocale(["xx-YY", "en-GB"])).toBe("en");
    expect(availableLocales()).toContain(sourceLocale);
    setLocale(sourceLocale);
  });

  it("pseudo-localizes without breaking rich-text tags", () => {
    expect(pseudoLocalize("Open <b>Settings</b>")).toMatch(/^⟦Óþéñ <b>Šéţţíñĝš<\/b>·+⟧$/);
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
        for (const match of line.matchAll(/(?<![=\-])>\s*([A-Za-z][^<>{}=;&|?:()]*?)\s*(?:<|$)/g)) {
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
