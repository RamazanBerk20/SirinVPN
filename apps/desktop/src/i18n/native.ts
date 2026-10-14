import { en } from "./en";
import { t, type Catalog, type MessageKey } from ".";
import { invoke, isAndroid } from "../platform";

const PLACEHOLDER = /\{\{\s*([\w.]+)\s*\}\}/g;
// Private-use markers carry placeholders through t(); pseudo-localization leaves them intact.
const MARKER = /(\d+)/g;

function entries(catalog: Catalog, prefix: string, out: [string, string][] = []): [string, string][] {
  for (const [key, value] of Object.entries(catalog)) {
    if (typeof value === "string") out.push([prefix + key, value]);
    else entries(value, `${prefix}${key}.`, out);
  }
  return out;
}

/**
 * Sends the tray, tray dialog and notification text for the active locale to the
 * desktop shell, which fills in placeholders itself. Plural forms are sent key by key.
 * If this fails, the shell keeps its built-in English text.
 */
export async function pushNativeText(): Promise<void> {
  if (isAndroid) return;
  const texts: Record<string, string> = {};
  for (const [key, source] of entries(en.native as Catalog, "native.")) {
    const names = [...new Set([...source.matchAll(PLACEHOLDER)].map(match => match[1]))];
    const params = Object.fromEntries(names.map((name, index) => [name, `${index}`]));
    texts[key] = t(key as MessageKey, params).replace(MARKER, (_, index: string) => `{{${names[Number(index)]}}}`);
  }
  try {
    await invoke("set_native_text", { texts });
  } catch {
    // Native text stays in English.
  }
}
