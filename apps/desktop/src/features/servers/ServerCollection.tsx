import { Check, Database, Plus, Star } from "@phosphor-icons/react";
import { useState } from "react";
import { api } from "../../api";
import { ActionMenu } from "../../components/ActionMenu";
import { CopyValue } from "../../components/CopyValue";
import { InlineError } from "../../components/ui";
import { describeConnection } from "../connection/connectionState";
import type { LocalTunnelStatus, ServerProfile } from "../../types";
import { errorMessage } from "../../lib/errors";
import { isAndroid } from "../../platform";
import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { t } from "../../i18n";

/** Search appears once a collection is long enough to need it. */
const SEARCH_THRESHOLD = 6;
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
    if (isAndroid && favorite === undefined && newName === undefined) { setRenaming(server); setDraftName(server.name); return; }
    const name =
      favorite === undefined
        ? (newName ?? window.prompt(t("servers.rename.prompt"), server.name))?.trim()
        : null;
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
                <span><strong>{server.favorite && <Star size={14} weight="fill" aria-label={t("servers.favorite")} />}{server.name}</strong><small>{t("common.separator.pair", { first: roleLabel(server), second: state.status })}</small></span>
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
                  {selectedId === server.id
                    ? t("common.separator.triple", { first: roleLabel(server), second: state.status, third: t("servers.selected") })
                    : t("common.separator.pair", { first: roleLabel(server), second: state.status })}
                </span>
                <div className="collection-address">
                  <span>{t("home.details.serverAddress")}</span>
                  <CopyValue
                    value={`${server.endpoint.host}:${server.endpoint.wireguard_port}`}
                    label={t("servers.addressOf", { name: server.name })}
                  />
                </div>
              </div>
              <button
                className="secondary-button"
                onClick={() => onOpen(server.id)}
              >
                {t("common.action.open")}
              </button></>}
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
