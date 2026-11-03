import { Check, Database, Plus, Star } from "@phosphor-icons/react";
import { useState } from "react";
import { api } from "../../api";
import { ActionMenu } from "../../components/ActionMenu";
import { CopyValue } from "../../components/CopyValue";
import { notify } from "../../components/Toasts";
import { InlineError } from "../../components/ui";
import { describeConnection } from "../connection/connectionState";
import type { LocalTunnelStatus, ServerProfile } from "../../types";
import { errorMessage } from "../../lib/errors";
import { isAndroid } from "../../platform";
import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { t } from "../../i18n";

/** Search appears once a collection is long enough to need it. */
export const SEARCH_THRESHOLD = 6;
function roleLabel(server: ServerProfile): string {
  return t(server.role === "owner" ? "common.role.owner" : server.administrator ? "common.role.admin" : "common.role.member");
}

export function ServerCollection({
  servers,
  selectedId,
  local,
  onOpen,
  onInspect,
  onAdd,
  onChanged,
}: {
  servers: ServerProfile[];
  selectedId?: string;
  local: LocalTunnelStatus;
  onOpen: (id: string) => void;
  onInspect: (id: string) => void;
  onAdd: () => void;
  onChanged: () => Promise<void>;
}) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState("");
  const [renaming, setRenaming] = useState<ServerProfile | null>(null);
  const [draftName, setDraftName] = useState("");
  const filtered = servers.filter((server) => `${server.name} ${server.endpoint.host}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()));
  const edit = async (server: ServerProfile, favorite?: boolean, newName?: string) => {
    if (favorite === undefined && newName === undefined) { setRenaming(server); setDraftName(server.name); return; }
    const name = favorite === undefined ? newName?.trim() : null;
    if (favorite === undefined && (!name || name === server.name)) return;
    setBusy(true);
    setError(null);
    try {
      await api.updateServerPresentation(
        server.id,
        name ?? null,
        favorite ?? null,
      );
      await onChanged();
      setRenaming(null);
      notify(favorite === undefined ? t("servers.renamed", { name: name! }) : t(favorite ? "servers.favorited" : "servers.unfavorited", { name: server.name }));
    } catch (e) {
      setError(errorMessage(e, t("common.error.localSave")));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="servers-page">
      <header className="workspace-header">
        <div>
          <h1>{t("app.nav.servers")}</h1>
          <p>{t("servers.count", { count: servers.length })}</p>
          {/* The desktop sidebar is the switcher; this page only manages. */}
          {!isAndroid && <p>{t("servers.manageHint")}</p>}
        </div>
        <button className="primary-button" onClick={onAdd}>
          <Plus size={18} /> {t("servers.add")}
        </button>
      </header>
      {error && <InlineError message={error} />}
      {(servers.length >= SEARCH_THRESHOLD || query) && <label className="field"><span>{t("servers.search.label")}</span><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("servers.search.placeholder")} /></label>}
      {!filtered.length && <p role="status">{t("servers.search.empty")}</p>}
      <div className="server-collection">
        {filtered.map((server) => {
          const state = describeConnection(local, server.id, null);
          return (
            <article
              key={server.id}
              className="collection-row"
              data-selected={selectedId === server.id}
            >
              {isAndroid ? <button className="mobile-server-open" onClick={() => onOpen(server.id)} aria-label={t("servers.open", { name: server.name })} aria-current={selectedId === server.id || undefined}>
                <span className={`mobile-row-icon ${state.connected ? "online" : ""}`}><Database size={22} /></span>
                <span><strong>{server.name}</strong><small>{server.favorite && <><Star size={13} weight="fill" className="favorite-star" aria-label={t("servers.favorite")} />{" "}</>}{t("common.separator.pair", { first: roleLabel(server), second: state.status })}</small></span>
                {selectedId === server.id && <Check size={20} className="row-check" />}
              </button> : <><span
                className={`server-card-icon ${state.connected ? "online" : ""}`}
              >
                <Database size={25} />
              </span>
              <div className="collection-copy">
                <h2>
                  {server.favorite && (
                    <Star size={17} weight="fill" aria-label={t("servers.favorite")} />
                  )}
                  {server.name}
                </h2>
                <span>
                  {t("common.separator.pair", { first: roleLabel(server), second: state.status })}
                </span>
                <div className="collection-address">
                  <span>{t("home.details.serverAddress")}</span>
                  <CopyValue
                    value={`${server.endpoint.host}:${server.endpoint.wireguard_port}`}
                    label={t("servers.addressOf", { name: server.name })}
                  />
                </div>
              </div></>}
              <ActionMenu
                label={t("servers.actions.label", { name: server.name })}
                title={server.name}
                actions={[
                  {
                    label: t("servers.actions.rename"),
                    disabled: busy,
                    run: () => void edit(server),
                  },
                  {
                    label: t(server.favorite ? "servers.actions.unfavorite" : "servers.actions.favorite"),
                    disabled: busy,
                    run: () => void edit(server, !server.favorite),
                  },
                  {
                    label: t("servers.actions.maintain"),
                    run: () => onInspect(server.id),
                  },
                ]}
              />
            </article>
          );
        })}
      </div>
      <Dialog.Root open={Boolean(renaming)} onOpenChange={open => { if (!open && !busy) setRenaming(null); }}>
        <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><DialogContent heading={t("servers.rename.title")} description={t("servers.rename.description")} closeDisabled={busy}>
          <form onSubmit={event => { event.preventDefault(); if (renaming) void edit(renaming, undefined, draftName); }}>
            <label className="field"><span>{t("servers.rename.label")}</span><input value={draftName} maxLength={128} onChange={event => setDraftName(event.target.value)} /></label>
            {error && <InlineError message={error} />}
            <button className="primary-button" disabled={busy || !draftName.trim()}>{busy ? t("common.state.saving") : t("servers.rename.save")}</button>
          </form>
        </DialogContent></Dialog.Portal>
      </Dialog.Root>
    </section>
  );
}
