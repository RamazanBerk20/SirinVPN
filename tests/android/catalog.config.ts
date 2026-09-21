import config from '../ui/catalog/vite.config';
import path from 'node:path';
export default {
  ...config,
  define:{'process.env.NODE_ENV':'"production"'},
  build:{outDir:path.resolve(import.meta.dirname,'../../target/android-catalog'),emptyOutDir:true,
    lib:{entry:path.resolve(import.meta.dirname,'catalog.ts'),name:'SirinAndroidCatalog',formats:['iife'],fileName:()=> 'catalog.js',cssFileName:'catalog'},
    minify:true,cssCodeSplit:false},
};
