import { t } from "../../i18n";

/** The VPS accepts 1–64 visible characters for a person's or a device's name. */
export const MAX_NAME = 64;

function nameProblem(name: string): string | null {
  const trimmed = name.trim();
  if (!trimmed) return t("devices.name.empty");
  if ([...trimmed].length > MAX_NAME) return t("devices.name.tooLong", { count: MAX_NAME });
  if (/[\u0000-\u001f\u007f-\u009f]/.test(trimmed)) return t("devices.name.invalid");
  return null;
}

export const deviceNameProblem = nameProblem;
export const personNameProblem = nameProblem;

/** Matches the native file name rule: wg-quick takes the tunnel name from it. */
export function wireguardFileName(deviceName: string) {
  const name = deviceName.trim().replace(/[^a-zA-Z0-9_=+.-]/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 15);
  return `${name || "sirinvpn"}.conf`;
}
