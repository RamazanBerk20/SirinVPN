import { ArrowClockwise, LockKey, Plus } from "@phosphor-icons/react";
import { InlineError } from "../../components/ui";
import { useAccessController, type AccessProps } from "./useAccessController";
import { DeviceList } from "./DeviceList";
import { ActiveInvitations } from "./ActiveInvitations";
import { InvitationDialog } from "./InvitationDialog";
import { MemberPolicyDialog } from "./MemberPolicyDialog";
import { WireGuardDeviceDialog } from "./WireGuardDeviceDialog";
import { SubnetRoutesDialog } from "./SubnetRoutesDialog";
import { DevicePairsDialog } from "./DevicePairsDialog";
import { canManagePeerCommunication } from "../../access";
import { isAndroid } from "../../platform";
import { useState, type ReactNode } from "react";
import type { DeviceSummary, MemberSummary } from "../../types";
import { formatDateTime, t } from "../../i18n";
import { Rich } from "../../i18n/Rich";

const strong = { strong: (content: ReactNode) => <strong>{content}</strong> };
export function AccessPanel(
  props: AccessProps & { onNetwork?: () => void; onOpenHome?: () => void },
) {
  const { profile, connected, accessLevel, onNetwork } = props;
  const [policyTarget, setPolicyTarget] = useState<MemberSummary | null>(null);
  const [wireguardTarget, setWireguardTarget] = useState<MemberSummary | "new" | null>(null);
  const [routesTarget, setRoutesTarget] = useState<DeviceSummary | null>(null);
  const [pairsTarget, setPairsTarget] = useState<DeviceSummary | null>(null);
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
    wireguardDevicesAvailable,
    subnetRoutesAvailable,
    devicePairsAvailable,
    recipientNamesAvailable,
    memberLifecycleAvailable,
    memberBusy,
    changeMemberSuspension,
    revokeMemberDevices,
    query,
    setQuery,
    owner,
    refresh,
    refreshAfterChange,
    rename,
    revoke,
    updatePeerCommunication,
    cancel,
    updateAccess,
    transferOwnership,
    openInvitation,
    changeInvitationOpen,
  } = useAccessController(props);

  const savedAt = updatedAt ? formatDateTime(new Date(updatedAt), { timeStyle: "short" }) : null;
  const deviceCount = snapshot?.members.reduce((count, member) => count + member.devices.length, 0) ?? 0;
  const issuer = snapshot?.members.find((member) => member.devices.some((device) => device.id === profile.device_id))
    ?? (accessLevel === "member" ? snapshot?.members[0] : undefined);
  // The Android runtime has no command for exporting WireGuard configurations yet.
  const wireguardAvailable = wireguardDevicesAvailable && !isAndroid;
  return (
    <section className="access-section">
      <div className="section-heading">
        <div>
          <h2>{t("devices.panel.title")}</h2>
        </div>
        <div className="access-heading-actions">
          <button
            className="icon-button"
            disabled={!connected || loading}
            aria-label={t("devices.panel.refresh")}
            onClick={() => void refresh()}
          >
            <ArrowClockwise size={17} />
          </button>
          <button
            className="primary-button"
            disabled={!verified || (accessLevel === "member" && !issuer?.policy?.invite_members)}
            onClick={() => openInvitation(null)}
          >
            <Plus size={16} weight="bold" /> {t("devices.panel.invite")}
          </button>
          {wireguardAvailable && <button
            className="secondary-button"
            disabled={!verified || (accessLevel === "member" && !issuer?.policy?.invite_members)}
            onClick={() => setWireguardTarget("new")}
          >
            <Plus size={16} weight="bold" /> {t("devices.panel.addWireguard")}
          </button>}
        </div>
      </div>
      {!connected ? (
        <div className="access-empty">
          <LockKey size={20} /> {t("devices.panel.connectFirst")}
          {props.onOpenHome && (
            <button className="secondary-button" onClick={props.onOpenHome}>
              {t("devices.panel.openHome")}
            </button>
          )}
        </div>
      ) : loading && !snapshot && !loadError ? (
        <div className="access-empty">
          <ArrowClockwise className="spin" size={20} /> {t("devices.panel.loading")}
        </div>
      ) : (
        <>
          {loadError ? <InlineError message={loadError} /> : null}
          {snapshot && !verified && <p className="settings-note" role="status">
            {loading
              ? savedAt ? t("devices.panel.savedRefreshingAt", { time: savedAt }) : t("devices.panel.savedRefreshing")
              : savedAt ? t("devices.panel.savedStaleAt", { time: savedAt }) : t("devices.panel.savedStale")}
          </p>}
          {error ? <InlineError message={error} /> : null}
          {memberLifecycleAvailable === false && (
            <p className="settings-note">
              {t("devices.panel.lifecycleUnsupported")}
            </p>
          )}
          {snapshot && (
            <label className="device-search">
              <span>{t("devices.panel.search")}</span>
              <input
                type="search"
                placeholder={t("devices.panel.searchPlaceholder")}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </label>
          )}
          {snapshot ? (
            <fieldset className="access-dashboard" disabled={!verified} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
              <div
                className="access-summary"
                aria-label={t("devices.panel.summary.label")}
              >
                <span>
                  <Rich id="devices.panel.summary.members" params={{ count: snapshot.members.length }} tags={strong} />
                </span>
                <span>
                  <Rich id="devices.panel.summary.devices" params={{ count: deviceCount }} tags={strong} />
                </span>
                <span>
                  <Rich id="devices.panel.summary.invitations" params={{ count: snapshot.active_invitations.length }} tags={strong} />
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
                onWireGuard={wireguardAvailable ? setWireguardTarget : undefined}
                onSubnetRoutes={subnetRoutesAvailable ? setRoutesTarget : undefined}
                onPairs={devicePairsAvailable ? setPairsTarget : undefined}
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
        onCreated={refreshAfterChange}
      />
      {wireguardTarget && <WireGuardDeviceDialog
        key={`${profile.id}:${wireguardTarget === "new" ? "new" : wireguardTarget.id}`}
        serverId={profile.id}
        target={wireguardTarget === "new" ? null : wireguardTarget}
        delegatedPolicy={accessLevel === "member" ? issuer?.policy : undefined}
        onClose={() => setWireguardTarget(null)}
        onCreated={refreshAfterChange}
      />}
      {routesTarget && <SubnetRoutesDialog key={routesTarget.id} serverId={profile.id} device={routesTarget} onClose={() => setRoutesTarget(null)} onSaved={refreshAfterChange} />}
      {pairsTarget && snapshot && <DevicePairsDialog key={pairsTarget.id} serverId={profile.id} device={pairsTarget} snapshot={snapshot}
        candidates={snapshot.members.filter((member) => canManagePeerCommunication(accessLevel, member)).flatMap((member) => member.devices).filter((device) => device.id !== pairsTarget.id)}
        onClose={() => setPairsTarget(null)} onSaved={refreshAfterChange} />}
      {policyTarget && <MemberPolicyDialog key={policyTarget.id} serverId={profile.id} member={policyTarget} onClose={() => setPolicyTarget(null)} onSaved={refreshAfterChange} />}
    </section>
  );
}
