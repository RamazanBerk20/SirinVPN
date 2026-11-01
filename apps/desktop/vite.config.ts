import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
    // Outside the app root: the demo's sample data, and the core messages a troubleshooting test pins.
    fs: { allow: [".", "../../tests/ui/fixtures.js", "../../crates/core/src"] },
  },
  envPrefix: ["VITE_", "TAURI_"],
  test: {
    environment: "jsdom",
    maxWorkers: 4,
  },
});
