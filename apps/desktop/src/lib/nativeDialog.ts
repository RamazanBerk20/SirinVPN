import * as desktop from "@tauri-apps/plugin-dialog";
import { invoke, isAndroid } from "../platform";

export const open: typeof desktop.open = options => isAndroid
  ? invoke("android_open_document", { options: options ?? {} }) : desktop.open(options);
export const save: typeof desktop.save = options => isAndroid
  ? invoke("android_save_document", { options: options ?? {} }) : desktop.save(options);
export const confirm: typeof desktop.confirm = (message, options) => isAndroid
  ? invoke("android_confirm", { message, options: options ?? {} }) : desktop.confirm(message, options);
