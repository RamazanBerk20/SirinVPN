import * as desktop from "@tauri-apps/plugin-dialog";
import { browserDemo, invoke, isAndroid } from "../platform";

/** What a chosen file is for. On desktop the chooser runs in Rust, and native code
 * accepts the returned path only for this purpose (`picked_files.rs`). */
export type PickPurpose = "program" | "backup_export" | "backup_import" | "vps_backup_export"
  | "vps_backup_restore" | "vps_backup_folder" | "ssh_key" | "recovery_export" | "recovery_import" | "wireguard_export";

export const open = ({ purpose, ...options }: desktop.OpenDialogOptions & { purpose: PickPurpose }): Promise<string | null> => isAndroid
  ? invoke("android_open_document", { options }) : invoke("pick_path", { purpose, options });
export const save = ({ purpose, ...options }: desktop.SaveDialogOptions & { purpose: PickPurpose }): Promise<string | null> => isAndroid
  ? invoke("android_save_document", { options }) : invoke("pick_path", { purpose, options });
export const confirm: typeof desktop.confirm = async (message, options) => browserDemo ? window.confirm(message)
  : isAndroid ? invoke("android_confirm", { message, options: options ?? {} }) : desktop.confirm(message, options);
