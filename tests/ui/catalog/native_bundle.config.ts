import config from './vite.config';
import path from 'node:path';
export default {...config,define:{'process.env.NODE_ENV':'"production"'},build:{outDir:path.resolve(import.meta.dirname,'../../../.cache/screenshot-catalog-2026-09-12/native-bundle'),emptyOutDir:true,lib:{entry:path.resolve(import.meta.dirname,'main.tsx'),name:'SirinCatalog',formats:['iife'],fileName:()=> 'catalog.js'},minify:true,cssCodeSplit:false}};
