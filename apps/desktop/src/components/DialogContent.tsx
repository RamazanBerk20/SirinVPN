import { t } from "../i18n";
import * as Dialog from "@radix-ui/react-dialog";
import { ArrowLeft, X } from "@phosphor-icons/react";
import { isAndroid } from "../platform";
import { useRef, type ComponentProps, type ReactNode } from "react";

type DialogContentProps = ComponentProps<typeof Dialog.Content> & {
  heading?: ReactNode;
  description?: ReactNode;
  footer?: ReactNode;
  /** One line beside the actions: why the primary action is unavailable, or what is running. */
  footerNote?: ReactNode;
  closeDisabled?: boolean;
  closeLabel?: string;
};

/** Restore focus for dialogs opened from state, as well as Radix triggers. */
export function DialogContent({ heading, description, footer, footerNote, closeDisabled = false, closeLabel = t("common.action.close"), children, ...props }: DialogContentProps) {
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
              title={closeDisabled ? t("app.dialog.waitToClose") : closeLabel}>
              {isAndroid && !props.className?.includes("mobile-action-sheet") ? <ArrowLeft size={22} /> : <X size={20} />}
            </button>
          </Dialog.Close>
        </header>
        <div className="dialog-body">{children}</div>
        {/* A running task says so once, in the body next to its spinner; the footer never repeats it. */}
        {(footer || footerNote) && <footer className="dialog-footer">
          {footerNote && <p className="dialog-footer-note" role="status">{footerNote}</p>}
          {footer}
        </footer>}
      </> : children}
    </Dialog.Content>
  );
}

/** Returns to the previous step of a dialog. On Android the app bar's arrow closes the dialog, so this names the step. */
export function DialogBack({ onClick, disabled }: { onClick: () => void; disabled?: boolean }) {
  return <button type="button" className="secondary-button dialog-back" disabled={disabled} onClick={onClick}>
    <ArrowLeft size={16} />{isAndroid ? t("vps.common.previousStep") : t("common.action.back")}
  </button>;
}
