import { expect, it } from "vitest";
import { backupFileName } from "./ExportBackupDialog";

it("keeps non-Latin server names in the suggested backup file name", () => {
  expect(backupFileName("Ev sunucusu")).toBe("Ev-sunucusu.sirinvpn-backup");
  expect(backupFileName("家里的服务器")).toBe("家里的服务器.sirinvpn-backup");
  expect(backupFileName("خادم المنزل")).toBe("خادم-المنزل.sirinvpn-backup");
  expect(backupFileName(" ../.. ")).toBe("sirinvpn-device.sirinvpn-backup");
});
