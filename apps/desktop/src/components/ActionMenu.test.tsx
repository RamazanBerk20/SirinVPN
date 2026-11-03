import { expect, it, vi } from "vitest";
import { sheetGroups } from "./ActionMenu";

const run = vi.fn();

it("ends a menu with its loose destructive action, after any titled group", () => {
  const groups = sheetGroups([
    { label: "Details", run }, { label: "Revoke", danger: true, run }, { label: "Rename", run },
    { group: "Advanced", label: "Device pairs", run },
  ]);
  expect(groups.map((group) => [group.label, group.items.map((item) => item.label)])).toEqual([
    ["", ["Details", "Rename"]], ["Advanced", ["Device pairs"]], ["", ["Revoke"]],
  ]);
  // Without a titled group, the destructive action simply ends the one list.
  expect(sheetGroups([{ label: "Revoke", danger: true, run }, { label: "Rename", run }]).map((group) => group.items.map((item) => item.label)))
    .toEqual([["Rename", "Revoke"]]);
});
