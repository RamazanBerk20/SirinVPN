import { DotsThree, DotsThreeVertical } from "@phosphor-icons/react";
import { Fragment, useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "./DialogContent";
import { dpadOnly, isAndroid } from "../platform";
export interface MenuAction {
  label: string;
  group?: string;
  run: () => void;
  disabled?: boolean;
  reason?: string;
  danger?: boolean;
}

/**
 * Groups keep their first-seen order; destructive actions move to the end of their group, and
 * ungrouped destructive ones to the end of the whole menu, after any titled group.
 */
export function sheetGroups(actions: MenuAction[]): { key: string; label: string; items: MenuAction[] }[] {
  const groups = new Map<string, MenuAction[]>();
  for (const action of actions) groups.set(action.group ?? "", [...(groups.get(action.group ?? "") ?? []), action]);
  // Ungrouped actions come first, so they never read as part of a titled group.
  const ordered = [...groups].sort(([a], [b]) => Number(Boolean(a)) - Number(Boolean(b)))
    .map(([label, items]) => ({ key: label, label, items: [...items.filter(item => !item.danger), ...items.filter(item => item.danger)] }));
  const loose = ordered[0]?.label === "" && ordered.length > 1 ? ordered[0].items.filter(item => item.danger) : [];
  if (!loose.length) return ordered;
  return [{ ...ordered[0], items: ordered[0].items.filter(item => !item.danger) }, ...ordered.slice(1), { key: "\u0000danger", label: "", items: loose }]
    .filter(group => group.items.length > 0);
}

export function ActionMenu({
  label,
  title,
  actions,
  onOpenChange,
  trigger,
}: {
  /** Accessible name of the trigger, e.g. “Actions for Android phone”. */
  label: string;
  /** Sheet title on Android; defaults to the label. */
  title?: string;
  actions: MenuAction[];
  onOpenChange?: (open: boolean) => void;
  /** A visible button in place of the ⋯ icon, for a menu that is a page's main action; its text is its name. */
  trigger?: { content: ReactNode; className: string; disabled?: boolean };
}) {
  const [open, setOpen] = useState(false);
  const [placement, setPlacement] = useState({ above: false, height: 400 });
  const root = useRef<HTMLDivElement>(null);
  const triggerButton = useRef<HTMLButtonElement>(null);
  // A sheet item's action waits until the sheet has returned focus to its trigger.
  const pending = useRef<(() => void) | null>(null);
  const id = useId();
  // A layout effect applies the owner's update in the same commit, so content it
  // made inert never outlives the menu.
  useLayoutEffect(() => {
    onOpenChange?.(open);
    return () => onOpenChange?.(false);
  }, [open, onOpenChange]);
  const close = (focus = true) => {
    setOpen(false);
    if (focus) triggerButton.current?.focus();
  };
  useLayoutEffect(() => {
    if (isAndroid || !open || !root.current) return;
    const anchor = root.current.getBoundingClientRect();
    const navHeight =
      document.querySelector(".bottom-navigation")?.getBoundingClientRect()
        .height ?? 0;
    const workspace = root.current
      .closest(".workspace")
      ?.getBoundingClientRect();
    const topEdge = Math.max(0, workspace?.top ?? 0);
    const bottomEdge = Math.min(
      window.innerHeight - navHeight,
      workspace?.bottom ?? window.innerHeight,
    );
    const below = bottomEdge - anchor.bottom - 16;
    const above = anchor.top - topEdge - 16;
    const contentHeight =
      root.current.querySelector('[role="menu"]')?.scrollHeight ?? 400;
    const flip = below < contentHeight && above > below;
    setPlacement({ above: flip, height: Math.max(44, flip ? above : below) });
  }, [open]);
  useEffect(() => {
    if (isAndroid || !open) return;
    const outside = (e: PointerEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", outside);
    const resize = () => {
      setOpen(false);
      triggerButton.current?.focus({ preventScroll: true });
    };
    window.addEventListener("resize", resize);
    root.current
      ?.querySelector<HTMLButtonElement>('[role="menuitem"]:not(:disabled)')
      ?.focus({ preventScroll: true });
    return () => {
      document.removeEventListener("pointerdown", outside);
      window.removeEventListener("resize", resize);
    };
  }, [open]);
  if (isAndroid) return <Dialog.Root open={open} onOpenChange={setOpen}>
    <Dialog.Trigger asChild>{trigger
      ? <button ref={triggerButton} className={trigger.className} disabled={trigger.disabled}>{trigger.content}</button>
      : <button ref={triggerButton} className="icon-button overflow-button" aria-label={label}><DotsThreeVertical size={24} weight="bold" /></button>}</Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
      <DialogContent className="dialog-content mobile-action-sheet" heading={title ?? label} aria-describedby={undefined}
        onOpenAutoFocus={(event) => {
          // TV spatial navigation can't leave a focused title when the sheet scrolls, so the D-pad starts on an item.
          if (!dpadOnly) return;
          event.preventDefault();
          (event.target as HTMLElement).querySelector<HTMLButtonElement>(".mobile-sheet-action:not(:disabled)")?.focus();
        }}
        onCloseAutoFocus={(event) => {
          // A dialog the action opens then returns focus to the trigger, not to the item that unmounted.
          event.preventDefault();
          triggerButton.current?.focus();
          const run = pending.current;
          pending.current = null;
          run?.();
        }}>
        {sheetGroups(actions).map(({ key, label: group, items }, index) => <Fragment key={key}>
          {group && <h3 className="sheet-group-label">{group}</h3>}
          {/* An untitled group after a titled one (a trailing Revoke) still needs a visible break from it. */}
          {!group && index > 0 && <hr className="sheet-group-separator" />}
          {items.map(action => <button key={action.label} className={`mobile-sheet-action ${action.danger ? "danger-text" : ""}`} disabled={action.disabled} onClick={() => { pending.current = action.run; setOpen(false); }}>
            <span>{action.label}</span>{action.reason && <small>{action.reason}</small>}
          </button>)}
        </Fragment>)}
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
  return (
    <div
      className="action-menu"
      ref={root}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) setOpen(false);
      }}
    >
      <button
        ref={triggerButton}
        className={trigger?.className ?? "icon-button"}
        disabled={trigger?.disabled}
        aria-label={trigger ? undefined : label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        onClick={() => setOpen(!open)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setOpen(true);
          }
        }}
      >
        {trigger ? trigger.content : <DotsThree size={25} weight="bold" />}
      </button>
      {open && (
        <div
          className="action-menu-backdrop"
          aria-hidden="true"
          onPointerDown={(event) => {
            event.preventDefault();
            close();
          }}
        />
      )}
      {open && (
        <div
          id={id}
          role="menu"
          aria-label={label}
          className="action-menu-panel"
          style={{
            top: placement.above ? "auto" : "calc(100% + 5px)",
            bottom: placement.above ? "calc(100% + 5px)" : "auto",
            maxHeight: placement.height,
            overflowY: "auto",
          }}
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              e.preventDefault();
              e.stopPropagation();
              close();
              return;
            }
            const items = Array.from(
              e.currentTarget.querySelectorAll<HTMLButtonElement>(
                '[role="menuitem"]:not(:disabled)',
              ),
            );
            const i = items.indexOf(
              document.activeElement as HTMLButtonElement,
            );
            const next =
              e.key === "ArrowDown"
                ? (i + 1) % items.length
                : e.key === "ArrowUp"
                  ? (i - 1 + items.length) % items.length
                  : e.key === "Home"
                    ? 0
                    : e.key === "End"
                      ? items.length - 1
                      : null;
            if (next !== null) {
              e.preventDefault();
              items[next]?.focus();
            }
          }}
        >
          {/* One heading per group, as on Android, instead of a scope caption on every item. */}
          {sheetGroups(actions).map(({ key, label: group, items }, groupIndex) => <div role="group" aria-label={group || undefined} key={key}>
            {group && <p className="menu-group-label" aria-hidden="true">{group}</p>}
            {items.map((action, index) => (
              <button
                role="menuitem"
                key={action.label}
                className={action.danger ? "danger-text" : ""}
                disabled={action.disabled}
                aria-label={action.label}
                // The name stays the action; why it is unavailable is read as its description.
                aria-describedby={action.reason ? `${id}-${groupIndex}-${index}-reason` : undefined}
                onClick={() => {
                  if (action.disabled) return;
                  close();
                  action.run();
                }}
              >
                <span>{action.label}</span>
                {action.reason && <small id={`${id}-${groupIndex}-${index}-reason`}>{action.reason}</small>}
              </button>
            ))}
          </div>)}
        </div>
      )}
    </div>
  );
}
