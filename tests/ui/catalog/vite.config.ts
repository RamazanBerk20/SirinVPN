import { defineConfig } from "../../../apps/desktop/node_modules/vite/dist/node/index.js";
import react from "../../../apps/desktop/node_modules/@vitejs/plugin-react/dist/index.js";
import tailwind from "../../../apps/desktop/node_modules/@tailwindcss/vite/dist/index.mjs";
import path from "node:path";
const root = path.resolve(import.meta.dirname, "../../..");
const desktop = path.join(root, "apps/desktop");
const apiPath = path.join(desktop, "src/api");
export default defineConfig({
  root: desktop,
  plugins: [{
    name: "isolated-screenshot-catalog",
    enforce: "pre",
    resolveId(id, importer) {
      if (importer && id.startsWith(".") && path.resolve(path.dirname(importer.split("?")[0]), id).replace(/\.ts$/, "") === apiPath) return "\0catalog-api";
      if (id === "@tauri-apps/plugin-dialog") return "\0catalog-dialog";
      if (id === "@tauri-apps/api/core") return "\0catalog-core";
    },
    load(id) {
      if (id === "\0catalog-api") return `export const api = new Proxy({}, {get: (_,name) => name === 'watchServerStatus' ? (...args) => window.__catalog.watch(...args) : name === 'watchLocalStatus' ? (...args) => window.__catalog.watchLocal(...args) : (...args) => window.__catalog.call(String(name),args)});`;
      if (id === "\0catalog-dialog") return `export const confirm=(message,options)=>window.__catalog.confirm(message,options); export const open=(options)=>window.__catalog.call('chooseOpenFile',[options]); export const save=(options)=>window.__catalog.call('chooseSaveFile',[options]);`;
      if (id === "\0catalog-core") return `export const invoke=(command,args)=>window.__catalog.native(command,args); export class Channel {id=1; onmessage=()=>{};} export const transformCallback=()=>1; export const convertFileSrc=(path)=>path; export const isTauri=()=>true; export const SERIALIZE_TO_IPC_FN='__TAURI_TO_IPC_KEY__'; export class Resource { constructor(rid){this.rid=rid;} close(){return Promise.resolve();} }`;
    },
    transformIndexHtml(html) {
      return html.replace('<head>','<head><script>if(!window.__TAURI_INTERNALS__)window.__TAURI_INTERNALS__={metadata:{currentWindow:{label:"main"},currentWebview:{label:"main"}}};</script>').replace('/src/main.tsx', '/@fs/'+path.join(root,'tests/ui/catalog/main.tsx'));
    },
  }, react(), tailwind()],
  resolve: { alias: {
    react: path.join(desktop,"node_modules/react"),
    "react-dom": path.join(desktop,"node_modules/react-dom"),
    "@fontsource-variable/inter": path.join(desktop,"node_modules/@fontsource-variable/inter"),
    "@fontsource-variable/jetbrains-mono": path.join(desktop,"node_modules/@fontsource-variable/jetbrains-mono"),
  } },
  server: { host:"127.0.0.1", port:1422, strictPort:true, hmr:false, fs:{allow:[root]} },
});
