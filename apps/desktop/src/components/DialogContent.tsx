import * as Dialog from "@radix-ui/react-dialog";
import { ArrowLeft, X } from "@phosphor-icons/react";
import { isAndroid } from "../platform";
import { useRef, type ComponentProps, type ReactNode } from "react";

type DialogContentProps = ComponentProps<typeof Dialog.Content> & {
  heading?: ReactNode;
  description?: ReactNode;
  footer?: ReactNode;
  closeDisabled?: boolean;
  closeLabel?: string;
};

/** Restore focus for dialogs opened from state, as well as Radix triggers. */
export function DialogContent({ heading, description, footer, closeDisabled = false, closeLabel = "Close", children, ...props }: DialogContentProps) {
  const returnFocus = useRef<HTMLElement | null>(null);
  const title = useRef<HTMLHeadingElement | null>(null);
  const framed = heading !== undefined;
  return (
    <Dialog.Content
      {...props}
      className={`${props.className ?? "dialog-content"}${framed ? " dialog-layout" : ""}`}
      onEscapeKeyDown={(event) => {
        if (closeDisabled) event.preventDefault();
        props.onEscapeKeyDown?.(event);
      }}
      onInteractOutside={(event) => {
        // Window controls must not discard an open form or transaction review.
        if (closeDisabled || (event.target instanceof Element &&
          event.target.closest(".desktop-titlebar, .window-resize-edge")))
          event.preventDefault();
        props.onInteractOutside?.(event);
      }}
      onOpenAutoFocus={(event) => {
        returnFocus.current =
          document.activeElement instanceof HTMLElement
            ? document.activeElement
            : null;
        props.onOpenAutoFocus?.(event);
        // Long forms begin at their context, rather than scrolling to an input.
        if (framed && !event.defaultPrevented) {
          event.preventDefault();
          title.current?.focus({ preventScroll: true });
        }
      }}
      onCloseAutoFocus={(event) => {
        props.onCloseAutoFocus?.(event);
        if (!event.defaultPrevented && returnFocus.current?.isConnected) {
          event.preventDefault();
          returnFocus.current.focus();
        }
      }}
    >
      {framed ? <>
        <header className="dialog-header">
          <div>
            <Dialog.Title ref={title} tabIndex={-1}>{heading}</Dialog.Title>
            {description && <Dialog.Description>{description}</Dialog.Description>}
          </div>
          <Dialog.Close asChild>
            <button type="button" className="dialog-close" aria-label={closeLabel} disabled={closeDisabled}
              title={closeDisabled ? "Wait for the current operation to finish" : "Close"}>
              {isAndroid ? <ArrowLeft size={22} /> : <X size={20} />}
            </button>
          </Dialog.Close>
        </header>
        <div className="dialog-body">{children}</div>
        {(footer || closeDisabled) && <footer className="dialog-footer">{footer ?? <p role="status">The operation is running. Closing is available when it finishes.</p>}</footer>}
      </> : children}
    </Dialog.Content>
  );
}
