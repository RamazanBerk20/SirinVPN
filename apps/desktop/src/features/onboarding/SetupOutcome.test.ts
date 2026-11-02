import { expect, it } from "vitest";
import { describeInstallFailure } from "./SetupOutcome";

it("reads the failed phase and whether the server was changed from installer errors", () => {
  expect(describeInstallFailure("Couldn’t install SirinVPN. server transaction failed during connection: refused")).toEqual({ stage: "connect", change: "unchanged" });
  expect(describeInstallFailure("server transaction failed during artifact upload: broken pipe")).toEqual({ stage: "upload", change: "unchanged" });
  expect(describeInstallFailure("server transaction failed during owner enrollment: exit 1")).toEqual({ stage: "configure", change: "rolledBack" });
  expect(describeInstallFailure("the server is incompatible: Debian 11")).toEqual({ stage: "check", change: "unchanged" });
  expect(describeInstallFailure("Server setup was interrupted.")).toEqual({ stage: null, change: "unknown" });
});
