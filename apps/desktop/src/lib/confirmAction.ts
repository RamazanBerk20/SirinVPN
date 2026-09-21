import * as dialog from "./nativeDialog";
/** Native confirmations name the committed action; browser previews retain their host dialog. */
let showing = false;
function actionLabel(message: string) {
  if (/^Transfer ownership/i.test(message)) return "Transfer ownership";
  if (/^Permanently uninstall/i.test(message)) return "Uninstall SirinVPN";
  if (/^Replace/i.test(message)) return "Replace installation";
  if (/^Remove Admin access|^Remove .*Admin access/i.test(message)) return "Remove Admin access";
  if (/^Make .* an Admin/i.test(message)) return "Grant Admin access";
  if (/^Remove/i.test(message)) return "Remove from this device";
  if (/^Revoke all/i.test(message)) return "Revoke all member devices";
  if (/^Revoke this offline/i.test(message)) return "Revoke recovery key";
  if (/^Revoke/i.test(message)) return "Revoke device access";
  if (/^Suspend/i.test(message)) return "Suspend member";
  if (/^Reactivate/i.test(message)) return "Reactivate member";
  if (/^Expose public/i.test(message)) return "Open public port";
  if (/^Close public/i.test(message)) return "Close public port";
  if (/^Disconnect/i.test(message)) return "Disconnect VPN";
  if (/^Allow these Administrators/i.test(message)) return "Save recovery policy";
  if (/^Allow/i.test(message)) return "Allow device access";
  if (/^Return/i.test(message)) return "Isolate device";
  return "Change member access";
}
export async function confirmAction(message: string, label = actionLabel(message)): Promise<boolean> {
  if (showing) return false;
  showing = true;
  try {
    if (!("__TAURI_INTERNALS__" in window)) return await Promise.resolve(window.confirm(message));
    return await dialog.confirm(message, { title: label, kind: "warning", okLabel: label, cancelLabel: "Cancel" });
  } catch { return false; }
  finally { showing = false; }
}
