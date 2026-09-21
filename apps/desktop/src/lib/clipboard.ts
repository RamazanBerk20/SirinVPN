import { invoke, isAndroid } from "../platform";
export function copyText(value: string): Promise<void> {
  return isAndroid && value.startsWith("native-secret:")
    ? invoke("android_copy_secret", { reference: value })
    : navigator.clipboard.writeText(value);
}
