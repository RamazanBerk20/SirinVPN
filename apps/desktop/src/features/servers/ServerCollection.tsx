import { CaretRight, Database, Plus, Star } from "@phosphor-icons/react";
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
        ? (newName ?? window.prompt("Name on this device", server.name))?.trim()
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
      setError(errorMessage(e, "The local server details could not be saved."));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="servers-page">
      <header className="workspace-header">
        <div>
          <h1>Servers</h1>
          <p>{isAndroid ? `${servers.length} saved on this phone` : "Choose a server to open its connection controls."}</p>
        </div>
        <button className="primary-button" onClick={onAdd}>
          <Plus size={18} /> Add server
        </button>
      </header>
      {error && <InlineError message={error} />}
      <label className="field"><span>Search servers</span><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Name or VPN address" /></label>
      {!filtered.length && <p role="status">No servers match your search.</p>}
      <div className="server-collection">
        {filtered.map((server) => {
          const state = describeConnection(local, server.id, null);
          return (
            <article
              key={server.id}
              className="collection-row"
              data-selected={selectedId === server.id}
            >
              {isAndroid ? <button className="mobile-server-open" onClick={() => onOpen(server.id)} aria-label={`Open ${server.name}`}>
                <span className={`mobile-row-icon ${state.connected ? "online" : ""}`}><Database size={24} /></span>
                <span><strong>{server.favorite && <Star size={15} weight="fill" />} {server.name}</strong><small>{server.role === "owner" ? "Owner" : server.administrator ? "Admin" : "Member"} · {state.status}</small></span><CaretRight size={18} />
              </button> : <><span
                className={`server-card-icon ${state.connected ? "online" : ""}`}
              >
                <Database size={25} />
              </span>
              <div className="collection-copy">
                <h2>
                  {server.favorite && (
                    <Star size={17} weight="fill" aria-label="Favorite" />
                  )}
                  {server.name}
                </h2>
                <span>
                  {server.role === "owner"
                    ? "Owner"
                    : server.administrator
                      ? "Admin"
                      : "Member"}{" "}
                  · {state.status}
                  {selectedId === server.id ? " · Selected" : ""}
                </span>
                <div className="collection-address">
                  <span>VPN endpoint</span>
                  <CopyValue
                    value={`${server.endpoint.host}:${server.endpoint.wireguard_port}`}
                    label={`${server.name} endpoint`}
                  />
                </div>
              </div>
              <button
                className="secondary-button"
                onClick={() => onOpen(server.id)}
              >
                Open
              </button></>}
              <ActionMenu
                label={`Actions for ${server.name}`}
                actions={[
                  {
                    label: "Rename locally",
                    disabled: busy,
                    run: () => void edit(server),
                  },
                  {
                    label: server.favorite ? "Remove favorite" : "Add favorite",
                    disabled: busy,
                    run: () => void edit(server, !server.favorite),
                  },
                  {
                    label: "Inspect & maintain",
                    run: () => onInspect(server.id),
                  },
                ]}
              />
            </article>
          );
        })}
      </div>
      <Dialog.Root open={Boolean(renaming)} onOpenChange={open => { if (!open && !busy) setRenaming(null); }}>
        <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><DialogContent heading="Rename server" description="This name is only saved on this phone." closeDisabled={busy}>
          <form onSubmit={event => { event.preventDefault(); if (renaming) void edit(renaming, undefined, draftName); }}>
            <label className="field"><span>Server name</span><input value={draftName} maxLength={128} onChange={event => setDraftName(event.target.value)} /></label>
            {error && <InlineError message={error} />}
            <button className="primary-button" disabled={busy || !draftName.trim()}>{busy ? "Saving…" : "Save name"}</button>
          </form>
        </DialogContent></Dialog.Portal>
      </Dialog.Root>
    </section>
  );
}
