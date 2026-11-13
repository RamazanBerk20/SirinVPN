import { defineConfig, type Plugin } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Vitest loads a fresh module graph for every test file, and the icon barrel alone is
// about 4,500 modules (1.6 s per file). Tests import each icon's own module instead.
function iconsPerModule(): Plugin {
  return {
    name: "phosphor-icons-per-module",
    enforce: "pre",
    transform(code, id) {
      if (id.includes("/node_modules/") || !code.includes("@phosphor-icons/react")) return;
      return code.replace(/import\s*\{([^}]*)\}\s*from\s*"@phosphor-icons\/react";?/g, (_, names: string) =>
        names.split(",").map((name) => name.trim()).filter((name) => name && !name.startsWith("type "))
          .map((name) => `import { ${name} } from "@phosphor-icons/react/dist/csr/${name.split(/\s+as\s+/)[0]}";`)
          .join("\n"));
    },
  };
}

export default defineConfig(({ mode }) => ({
  plugins: [react(), tailwindcss(), mode === "test" ? iconsPerModule() : null],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
    // Outside the app root: the demo's sample data, and Rust sources tests read (core messages a
    // troubleshooting test pins; the error codes, diagnostic causes and blockers errorCodes.test.ts checks).
    fs: { allow: [".", "../../tests/ui/fixtures.js", "../../crates/core/src", "../../crates/android-runtime/src", "../../crates/installer/src"] },
  },
  envPrefix: ["VITE_", "TAURI_"],
  test: {
    environment: "jsdom",
    maxWorkers: 4,
  },
}));
