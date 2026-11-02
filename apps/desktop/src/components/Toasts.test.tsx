import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { notify, ToastRegion } from "./Toasts";
import { InlineError } from "./ui";

afterEach(() => vi.useRealTimers());

it("shows success briefly, keeps errors until dismissed and drops repeats", () => {
  vi.useFakeTimers();
  render(<ToastRegion />);
  act(() => { notify("Pair removed"); notify("Pair removed"); notify("Couldn't remove the pair.", "error"); });
  expect(screen.getAllByText("Pair removed")).toHaveLength(1);
  act(() => { vi.advanceTimersByTime(5000); });
  expect(screen.queryByText("Pair removed")).toBeNull();
  expect(screen.getByText("Couldn't remove the pair.")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
  expect(screen.queryByText("Couldn't remove the pair.")).toBeNull();
});

it("offers a retry inside the error", () => {
  const retry = vi.fn();
  render(<InlineError message="Couldn't load devices." onRetry={retry} />);
  fireEvent.click(screen.getByRole("button", { name: "Try again" }));
  expect(retry).toHaveBeenCalledOnce();
});
