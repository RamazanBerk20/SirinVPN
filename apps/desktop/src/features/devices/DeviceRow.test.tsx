import { cleanup } from "@testing-library/react";
import { Desktop, Devices, DeviceMobile } from "@phosphor-icons/react";
import { afterEach, expect, it } from "vitest";
import { deviceIcon } from "./DeviceRow";

afterEach(cleanup);

it("keeps the reported platform's icon whatever the device is called", () => {
  expect(deviceIcon({ name: "Renamed device", platform: "android" }, false)).toBe(DeviceMobile);
  expect(deviceIcon({ name: "My phone", platform: "windows" }, false)).toBe(Desktop);
  expect(deviceIcon({ name: "Kitchen", platform: "linux" }, true)).toBe(Desktop);
});

it("guesses from the name only when the platform is unknown", () => {
  expect(deviceIcon({ name: "Android phone" }, false)).toBe(DeviceMobile);
  expect(deviceIcon({ name: "Work laptop", platform: "macos" }, false)).toBe(Desktop);
  expect(deviceIcon({ name: "Renamed device" }, false)).toBe(Devices);
  expect(deviceIcon({ name: "Renamed device" }, true)).toBe(Desktop);
});
