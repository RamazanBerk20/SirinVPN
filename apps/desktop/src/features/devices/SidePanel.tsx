import * as Dialog from "@radix-ui/react-dialog";
import type { ReactNode } from "react";
import { DialogContent } from "../../components/DialogContent";
import { t } from "../../i18n";

/** The one open panel on the Devices page: a sheet at the inline end on the desktop, full screen on a phone. */
export function SidePanel({ heading, description, onClose, busy = false, footer, testId, children }: {
  heading: ReactNode; description?: ReactNode; onClose: () => void; busy?: boolean; footer?: ReactNode; testId: string; children: ReactNode;
}) {
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <Dialog.Portal>
      <Dialog.Overlay className="dialog-overlay" />
      <DialogContent className="dialog-content devices-panel" data-testid={testId} heading={heading} description={description}
        closeDisabled={busy} closeLabel={t("common.action.close")} footer={footer}>
        {children}
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}

/** A titled part of a panel. */
export function PanelSection({ title, children, danger = false }: { title: string; children: ReactNode; danger?: boolean }) {
  return <section className={`panel-section${danger ? " danger-zone" : ""}`}>
    <h3>{title}</h3>
    {children}
  </section>;
}
