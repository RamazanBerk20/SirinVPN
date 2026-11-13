import { isAndroid } from "./platform";
import { demoCaller, demoDevices } from "./features/devices/demoDevices";

type FixtureInvoke = (command: string, args: Record<string, unknown>) => Promise<unknown>;
declare global {
  interface Window { __sirinDemo?: { invoke?: FixtureInvoke }; __sirinPlatform?: string; __sirinServerOverride?: Record<string, unknown> }
}

// Demo and fixture writes stay in memory, so leaving the demo (a reload) leaves nothing behind in the real browser storage.
const stored = new Map<string, string>();
Object.defineProperty(window, "localStorage", { configurable: true, value: {
  get length() { return stored.size; },
  key: (index: number) => [...stored.keys()][index] ?? null,
  getItem: (key: string) => stored.get(key) ?? null,
  setItem: (key: string, value: string) => { stored.set(key, String(value)); },
  removeItem: (key: string) => { stored.delete(key); },
  clear: () => stored.clear(),
} satisfies Storage });
window.__sirinPlatform = isAndroid ? "android" : "desktop";
window.__sirinDemo = {};
// The visual-test fixture answers with sample data; given __sirinDemo, it hands over its handler instead of replacing the Tauri bridge.
// @ts-expect-error A plain script with no exports or types.
const fixture = import("../../../tests/ui/fixtures.js").then(() => window.__sirinDemo!.invoke!);

// People and devices come from their own demo server, which follows the role chosen for the demo.
window.__sirinServerOverride = { ...demoCaller, ...window.__sirinServerOverride };

export const demoInvoke = <T>(command: string, args: Record<string, unknown>) => {
  try {
    const devices = demoDevices(command, args);
    if (devices.handled) return Promise.resolve(devices.value as T);
  } catch (reason) { return Promise.reject(reason); }
  return fixture.then((invoke) => invoke(command, args) as Promise<T>);
};
