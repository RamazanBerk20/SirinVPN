import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { ActionMenu } from "./ActionMenu";
import { DialogContent } from "./DialogContent";

const platform = vi.hoisted(() => ({ dpad: false }));
vi.mock("../platform", () => ({ isAndroid: true, get dpadOnly() { return platform.dpad; } }));
afterEach(() => { cleanup(); platform.dpad = false; });

function Row() {
  const [open, setOpen] = useState(false);
  return <>
    <ActionMenu label="Actions for Phone" title="Phone" actions={[
      { label: "Rename", disabled: true, run: vi.fn() },
      { label: "Details", run: () => setOpen(true) },
    ]} />
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal><DialogContent heading="Phone details" aria-describedby={undefined}>Facts</DialogContent></Dialog.Portal>
    </Dialog.Root>
  </>;
}

it("returns focus to the sheet's trigger when a dialog its item opened closes", async () => {
  render(<Row />);
  const trigger = screen.getByRole("button", { name: "Actions for Phone" });
  fireEvent.click(trigger);
  fireEvent.click(screen.getByRole("button", { name: "Details" }));
  const dialog = await screen.findByRole("dialog", { name: "Phone details" });
  fireEvent.keyDown(dialog, { key: "Escape" });
  await waitFor(() => expect(document.activeElement).toBe(trigger));
});

it("starts the D-pad on the first available item, not the sheet's title", async () => {
  platform.dpad = true;
  render(<Row />);
  fireEvent.click(screen.getByRole("button", { name: "Actions for Phone" }));
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "Details" })));
});
