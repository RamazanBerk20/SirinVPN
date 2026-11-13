// Translation check: `pnpm i18n:check`. Runs on Node's built-in TypeScript support; no build step.
// For each language it prints missing keys, extra keys, failures and untranslated values, for the
// web catalogs (src/locales/<locale>/*.json) and Android (android/src/main/res/values-*/strings.xml).
// Exit code 1 on any failure. A locale folder with an UNTRANSLATED file (web) or an
// "<!-- UNTRANSLATED" comment (Android) is a fresh copy of English: identical text is reported, not failed.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { checkLocale, checkSource, flattenCatalog, type Flat } from "../src/i18n/message.ts";

const root = join(import.meta.dirname, "..");
const locales = join(root, "src/locales");
const res = join(root, "android/src/main/res");
const ANDROID_FOLDERS: Record<string, string> = {
  tr: "values-tr", es: "values-es", fr: "values-fr", de: "values-de", ru: "values-ru",
  ar: "values-ar", "zh-Hans": "values-b+zh+Hans", ja: "values-ja", ko: "values-ko",
};

function readCatalog(locale: string): Flat {
  const flat: Flat = new Map();
  const folder = join(locales, locale);
  for (const file of readdirSync(folder).filter(name => name.endsWith(".json")).sort())
    flattenCatalog(JSON.parse(readFileSync(join(folder, file), "utf8")), `${file.slice(0, -5)}.`, flat);
  return flat;
}

const allowList: Record<string, string[]> = JSON.parse(readFileSync(join(locales, "allowlist.json"), "utf8"));
const allowed = (locale: string) => new Set([...(allowList["*"] ?? []), ...(allowList[locale] ?? [])]);

let failed = false;
const english = readCatalog("en");
const sourceProblems = checkSource(english);
if (sourceProblems.length) { failed = true; console.log(`en: ${sourceProblems.length} problems\n  ${sourceProblems.join("\n  ")}`); }
const list = (label: string, items: string[], limit = 20) =>
  items.length ? `\n  ${label} (${items.length}):\n    ${items.slice(0, limit).join("\n    ")}${items.length > limit ? `\n    … ${items.length - limit} more` : ""}` : "";

console.log(`Web catalog: ${english.size} English messages`);
const webLocales = readdirSync(locales, { withFileTypes: true }).filter(entry => entry.isDirectory() && entry.name !== "en").map(entry => entry.name).sort();
for (const locale of webLocales) {
  const marked = existsSync(join(locales, locale, "UNTRANSLATED"));
  const catalog = readCatalog(locale);
  const report = checkLocale(locale, english, catalog, allowed(locale));
  const translated = [...catalog].filter(([key, value]) => english.has(key) && (value !== english.get(key) || allowed(locale).has(key))).length;
  const broken = report.missing.length + report.extra.length + report.failures.length + (marked ? 0 : report.untranslated.length) > 0;
  failed ||= broken;
  console.log(`${broken ? "FAIL" : "ok  "} ${locale}: ${marked ? "marked UNTRANSLATED, " : ""}${translated} of ${english.size} differ from English (${Math.round(translated / english.size * 100)}%), ${report.untranslated.length} longer values still identical`
    + list("missing keys", report.missing) + list("extra keys", report.extra) + list("failures", report.failures, 50)
    + (marked ? "" : list("identical to English (translate, or add to src/locales/allowlist.json)", report.untranslated)));
}

// Android: <string name="…">text</string> and <plurals name="…"><item quantity="…">text</item></plurals>.
type AndroidStrings = { values: Map<string, string>; untranslatable: Set<string>; plurals: Map<string, string[]>; problems: string[] };
function readAndroid(file: string): AndroidStrings {
  const text = readFileSync(file, "utf8");
  const result: AndroidStrings = { values: new Map(), untranslatable: new Set(), plurals: new Map(), problems: [] };
  // Well-formedness, enough for flat resource files: every element opens and closes in order.
  const stack: string[] = [];
  for (const [tag, closing, name, selfClosing] of text.replace(/<!--[\s\S]*?-->|<\?[\s\S]*?\?>/g, "").matchAll(/<(\/?)([\w:.-]+)[^>]*?(\/?)>/g)) {
    if (selfClosing) continue;
    if (!closing) stack.push(name);
    else if (stack.pop() !== name) { result.problems.push(`malformed XML near ${tag}`); break; }
  }
  if (stack.length) result.problems.push(`unclosed <${stack.join("> <")}>`);
  for (const [, attributes, value] of text.matchAll(/<string\s+([^>]*)>([\s\S]*?)<\/string>/g)) {
    const name = /name="([^"]+)"/.exec(attributes)![1];
    if (/translatable="false"/.test(attributes)) result.untranslatable.add(name);
    result.values.set(name, value);
  }
  for (const [, name, body] of text.matchAll(/<plurals\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/plurals>/g)) {
    const items = [...body.matchAll(/<item\s+quantity="(\w+)">([\s\S]*?)<\/item>/g)];
    result.plurals.set(name, items.map(item => item[1]));
    result.values.set(name, items.map(item => item[2]).join("\u0000"));
  }
  return result;
}
// Distinct arguments: a plural's forms are compared as one text, and languages differ in how many forms they have.
const formatArgs = (text: string) => [...new Set([...text.matchAll(/%(\d+\$)?[-#+ 0,(]*\d*(\.\d+)?[sdfxXc]/g)].map(match => match[0]))].sort().join();

const androidSource = readAndroid(join(res, "values/strings.xml"));
const translatable = [...androidSource.values.keys()].filter(name => !androidSource.untranslatable.has(name));
console.log(`\nAndroid: ${translatable.length} translatable strings`);
if (androidSource.problems.length) { failed = true; console.log(`FAIL values: ${androidSource.problems.join("; ")}`); }
for (const [locale, folder] of Object.entries(ANDROID_FOLDERS)) {
  const file = join(res, folder, "strings.xml");
  if (!existsSync(file)) { failed = true; console.log(`FAIL ${locale}: ${folder}/strings.xml is missing`); continue; }
  const marked = readFileSync(file, "utf8").includes("<!-- UNTRANSLATED");
  const target = readAndroid(file);
  const categories = new Intl.PluralRules(locale).resolvedOptions().pluralCategories;
  const missing = translatable.filter(name => !target.values.has(name));
  const extra = [...target.values.keys()].filter(name => !translatable.includes(name));
  const failures = [...target.problems];
  const untranslated: string[] = [];
  for (const [name, value] of target.values) {
    const source = androidSource.values.get(name);
    if (source === undefined || !translatable.includes(name)) continue;
    if (!value.trim()) failures.push(`${name}: empty`);
    if (formatArgs(value) !== formatArgs(source)) failures.push(`${name}: format arguments differ`);
    if (value === source) { if (value.split(/\s+/).length > 3) untranslated.push(name); continue; }
    const forms = target.plurals.get(name);
    if (forms) for (const category of categories) if (!forms.includes(category)) failures.push(`${name}: plural lacks quantity="${category}"`);
  }
  const broken = missing.length + extra.length + failures.length + (marked ? 0 : untranslated.length) > 0;
  failed ||= broken;
  console.log(`${broken ? "FAIL" : "ok  "} ${locale} (${folder}): ${marked ? "marked UNTRANSLATED, " : ""}${untranslated.length} untranslated`
    + list("missing", missing) + list("extra (or translatable=\"false\" in English)", extra) + list("failures", failures, 50)
    + (marked ? "" : list("identical to English", untranslated)));
}

process.exit(failed ? 1 : 0);
