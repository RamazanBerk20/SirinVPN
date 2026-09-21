import { ArrowClockwise, LockKey, Plus } from "@phosphor-icons/react";
import { InlineError } from "../../components/ui";
import { useAccessController, type AccessProps } from "./useAccessController";
import { DeviceList } from "./DeviceList";
import { ActiveInvitations } from "./ActiveInvitations";
import { InvitationDialog } from "./InvitationDialog";
import { MemberPolicyDialog } from "./MemberPolicyDialog";
import { useState } from "react";
import type { MemberSummary } from "../../types";
export function AccessPanel(
  props: AccessProps & { onNetwork?: () => void; onOpenHome?: () => void },
) {
  const { profile, connected, accessLevel, onNetwork } = props;
  const [policyTarget, setPolicyTarget] = useState<MemberSummary | null>(null);
  const {
    snapshot,
    verified,
    updatedAt,
    loading,
    loadError,
    error,
    inviteOpen,
    inviteTarget,
    accessBusy,
    peerBusy,
    scopedInvitationsAvailable,
    recipientNamesAvailable,
    memberLifecycleAvailable,
    memberBusy,
    changeMemberSuspension,
    revokeMemberDevices,
    query,
    setQuery,
    owner,
    refresh,
    rename,
    revoke,
    updatePeerCommunication,
    cancel,
    updateAccess,
    transferOwnership,
    openInvitation,
    changeInvitationOpen,
  } = useAccessController(props);

  const issuer = snapshot?.members.find((member) => member.devices.some((device) => device.id === profile.device_id))
    ?? (accessLevel === "member" ? snapshot?.members[0] : undefined);
  return (
    <section className="access-section">
      <div className="section-heading">
        <div>
          <h2>Current access</h2>
          <p>
            Invite a person, or use a device’s action menu to add another device
            for its member.
          </p>
        </div>
        <div className="access-heading-actions">
          <button
            className="icon-button"
            disabled={!connected || loading}
            aria-label="Refresh devices"
            onClick={() => void refresh()}
          >
            <ArrowClockwise size={17} />
          </button>
          <button
            className="primary-button"
            disabled={!verified || (accessLevel === "member" && !issuer?.policy?.invite_members)}
            onClick={() => openInvitation(null)}
          >
            <Plus size={16} weight="bold" /> Invite member
          </button>
        </div>
      </div>
      {!connected ? (
        <div className="access-empty">
          <LockKey size={20} /> Connect to view and change authorized devices.
          {props.onOpenHome && (
            <button className="secondary-button" onClick={props.onOpenHome}>
              Open Home
            </button>
          )}
        </div>
      ) : loading && !snapshot && !loadError ? (
        <div className="access-empty">
          <ArrowClockwise className="spin" size={20} /> Reading current
          authorization
        </div>
      ) : (
        <>
          {loadError ? <InlineError message={loadError} /> : null}
          {snapshot && !verified && <p className="settings-note" role="status">
            Showing saved devices{updatedAt ? ` from ${new Date(updatedAt).toLocaleTimeString()}` : ""}.{" "}
            {loading ? "Refreshing current access…" : "Current access is unavailable. Device changes are disabled."}
          </p>}
          {error ? <InlineError message={error} /> : null}
          {memberLifecycleAvailable === false && (
            <p className="settings-note">
              Update VPS software to enable member suspension and revoking all
              member devices.
            </p>
          )}
          {snapshot && (
            <label className="device-search">
              <span>Search devices</span>
              <input
                type="search"
                placeholder="Search by name or tunnel address…"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </label>
          )}
          {snapshot ? (
            <fieldset className="access-dashboard" disabled={!verified} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
              <div
                className="access-summary"
                aria-label="Current authorization summary"
              >
                <span>
                  <strong>{snapshot.members.length}</strong>{" "}
                  {snapshot.members.length === 1 ? "member" : "members"}
                </span>
                <span>
                  <strong>
                    {snapshot.members.reduce(
                      (count, member) => count + member.devices.length,
                      0,
                    )}
                  </strong>{" "}
                  {snapshot.members.reduce(
                    (n, m) => n + m.devices.length,
                    0,
                  ) === 1
                    ? "device"
                    : "devices"}
                </span>
                <span>
                  <strong>{snapshot.active_invitations.length}</strong>{" "}
                  {snapshot.active_invitations.length === 1
                    ? "invitation"
                    : "invitations"}
                </span>
              </div>
              <DeviceList
                snapshot={snapshot}
                accessLevel={accessLevel}
                currentDeviceId={profile.device_id}
                platform={props.platform}
                query={query}
                accessBusy={accessBusy}
                peerBusy={peerBusy}
                memberLifecycleAvailable={memberLifecycleAvailable}
                memberBusy={memberBusy}
                onMemberSuspension={changeMemberSuspension}
                onRevokeMemberDevices={revokeMemberDevices}
                onInvite={openInvitation}
                onAccess={updateAccess}
                onTransfer={transferOwnership}
                onRename={rename}
                onRevoke={revoke}
                onPeer={updatePeerCommunication}
                onNetwork={onNetwork}
                onPolicy={scopedInvitationsAvailable ? setPolicyTarget : undefined}
              />
              <ActiveInvitations
                snapshot={snapshot}
                accessLevel={accessLevel}
                onCancel={cancel}
              />
            </fieldset>
          ) : null}
        </>
      )}
      <InvitationDialog
        key={`${profile.id}:${inviteOpen}:${inviteTarget?.id ?? "new"}`}
        profile={profile}
        open={inviteOpen}
        target={inviteTarget}
        canCreateAdmin={owner}
        scopedAvailable={scopedInvitationsAvailable}
        recipientNamesAvailable={verified ? recipientNamesAvailable : null}
        configurationError={loadError}
        onRefreshConfiguration={refresh}
        issuer={issuer}
        delegated={accessLevel === "member"}
        onOpenChange={changeInvitationOpen}
        onCreated={refresh}
      />
      {policyTarget && <MemberPolicyDialog key={policyTarget.id} serverId={profile.id} member={policyTarget} onClose={() => setPolicyTarget(null)} onSaved={refresh} />}
    </section>
  );
}
