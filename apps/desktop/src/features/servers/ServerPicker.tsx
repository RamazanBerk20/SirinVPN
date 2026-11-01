import { CaretUpDown, Check, Database, Plus, Star } from "@phosphor-icons/react";
import * as Dialog from "@radix-ui/react-dialog";
import { useState } from "react";
import { DialogContent } from "../../components/DialogContent";
import { ListRow } from "../../components/ListRow";
import { t } from "../../i18n";
import { confirmNavigation } from "../../lib/navigationGuard";
import type { LocalTunnelStatus, ServerProfile } from "../../types";
import { describeConnection } from "../connection/connectionState";

// ServerWorkspace remounts per server, so the sheet cannot return focus to the old trigger.
let focusNextTrigger = false;

/** Android Home: the current server opens a sheet to switch servers without leaving Home. */
export function ServerPicker({ servers, selected, local, onSelect, onAdd, onManage }: {
  servers: ServerProfile[];
  selected: ServerProfile;
  local: LocalTunnelStatus;
  onSelect: (id: string) => void;
  onAdd: () => void;
  onManage: () => void;
}) {
  const [open, setOpen] = useState(false);
  const close = (then: () => void) => { setOpen(false); then(); };
  return <Dialog.Root open={open} onOpenChange={setOpen}>
    <div className="mobile-choice-list home-server">
      <Dialog.Trigger asChild>
        <button type="button" className="mobile-list-row" ref={button => { if (button && focusNextTrigger) { focusNextTrigger = false; button.focus(); } }} aria-label={t("servers.picker.trigger", { name: selected.name })}>
          <span className={`mobile-row-icon ${describeConnection(local, selected.id, null).connected ? "online" : ""}`}><Database size={22} /></span>
          <span><small className="mobile-row-eyebrow">{t("servers.picker.eyebrow")}</small><strong>{selected.name}</strong></span>
          <CaretUpDown size={20} />
        </button>
      </Dialog.Trigger>
    </div>
    <Dialog.Portal>
      <Dialog.Overlay className="dialog-overlay" />
      <DialogContent className="dialog-content mobile-action-sheet" heading={t("servers.picker.title")} aria-describedby={undefined}>
        <div className="sheet-list" role="list">
          {servers.map(server => {
            const state = describeConnection(local, server.id, null);
            const current = server.id === selected.id;
            return <div role="listitem" key={server.id}>
              <ListRow
                icon={<Database size={22} />}
                title={<>{server.favorite && <Star size={14} weight="fill" aria-label={t("servers.favorite")} />}{server.name}</>}
                subtitle={state.status}
                trailing={current ? <Check size={20} className="row-check" /> : null}
                current={current}
                onClick={() => close(() => { if (!current && confirmNavigation()) { focusNextTrigger = true; onSelect(server.id); } })}
              />
            </div>;
          })}
        </div>
        <div className="sheet-actions">
          <button type="button" className="secondary-button" onClick={() => close(onAdd)}><Plus size={18} /> {t("servers.add")}</button>
          <button type="button" className="text-button" onClick={() => close(onManage)}>{t("servers.picker.manage")}</button>
        </div>
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}
