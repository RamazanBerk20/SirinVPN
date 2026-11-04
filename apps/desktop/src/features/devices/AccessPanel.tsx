import { ArrowClockwise, DeviceMobile, LockKey, MagnifyingGlass, Plus, X } from "@phosphor-icons/react";
import { InlineError } from "../../components/ui";
import { useAccessController, type AccessProps } from "./useAccessController";
import { DeviceList } from "./DeviceList";
import { ActiveInvitations } from "./ActiveInvitations";
import { InvitationDialog } from "./InvitationDialog";
import { MemberPolicyDialog } from "./MemberPolicyDialog";
import { WireGuardDeviceDialog } from "./WireGuardDeviceDialog";
import { SubnetRoutesDialog } from "./SubnetRoutesDialog";
import { DevicePairsDialog } from "./DevicePairsDialog";
import { RenameDeviceDialog } from "./RenameDeviceDialog";
import { addDeviceState } from "./memberLifecycleActions";
import { ActionMenu, type MenuAction } from "../../components/ActionMenu";
import { canManagePeerCommunication, memberAccessLevel } from "../../access";
import { isAndroid } from "../../platform";
import { useState } from "react";
import type { DeviceSummary, MemberSummary } from "../../types";
import { formatDateTime, t } from "../../i18n";

/** Search pays off once the list no longer fits at a glance. */
const SEARCH_FROM = 4;

export function AccessPanel(
  props: AccessProps & { onNetwork?: () => void; onOpenHome?: () => void; onConnect?: () => void },
) {
  const { profile, connected, onNetwork } = props;
  const [policyTarget, setPolicyTarget] = useState<MemberSummary | null>(null);
  const [wireguardTarget, setWireguardTarget] = useState<MemberSummary | "new" | null>(null);
  const [routesTarget, setRoutesTarget] = useState<DeviceSummary | null>(null);
  const [pairsTarget, setPairsTarget] = useState<DeviceSummary | null>(null);
  const [renameTarget, setRenameTarget] = useState<{ id: string; name: string } | null>(null);
  const controller = useAccessController(props);
  const { snapshot, verified, updatedAt, loading, loadError, query, setQuery, refresh, refreshAfterChange } = controller;

  const self = snapshot?.members.find((member) => member.devices.some((device) => device.id === profile.device_id));
  // Right after an ownership transfer the verified list knows this device's new role before the server status does.
  const accessLevel = verified && self ? memberAccessLevel(self) : props.accessLevel;
  const issuer = self ?? (accessLevel === "member" ? snapshot?.members[0] : undefined);
  // Hide what this role can never use rather than showing it disabled.
  const canInvite = accessLevel !== "member" || Boolean(issuer?.policy?.invite_members);
  const savedAt = updatedAt ? formatDateTime(new Date(updatedAt), { timeStyle: "short" }) : null;
  const deviceCount = snapshot?.members.reduce((count, member) => count + member.devices.length, 0) ?? 0;
  // The Android runtime has no command for exporting WireGuard configurations yet.
  const wireguardAvailable = controller.wireguardDevicesAvailable && !isAndroid;
  const searching = query.trim() !== "";
  const lonely = snapshot && !searching && snapshot.members.length === 1 && deviceCount <= 1;
  // The page's one add action: this member's next device, a new member, or (Advanced) a WireGuard configuration.
  const own = self && addDeviceState(self, { accessLevel, memberBusy: controller.memberBusy });
  const invite: MenuAction | null = canInvite ? { label: t("devices.panel.invite"), run: () => controller.openInvitation(null) } : null;
  const addActions: MenuAction[] = [
    ...(self && own?.allowed ? [{ label: t("devices.panel.addMine"), disabled: own.disabled, reason: own.reason, run: () => controller.openInvitation(self) }] : []),
    ...(invite ? [invite] : []),
    ...(wireguardAvailable && canInvite ? [{ group: t("devices.menu.group.advanced"), label: t("devices.panel.addWireguard"), run: () => setWireguardTarget("new") }] : []),
  ];
  // A single choice is a plain button named for what it does: an invitation isn't "Add device".
  const direct = addActions.length === 1 && !addActions[0].disabled ? addActions[0] : null;
  const addLabel = <><Plus size={16} weight="bold" /> {t(direct && direct === invite ? "devices.panel.invite" : "devices.panel.add")}</>;
  return (
    <section className="access-section devices-page">
      <div className="devices-heading">
        <h2>{t("devices.panel.title")}</h2>
        <div className="devices-heading-actions">
          <button className="icon-button" disabled={!connected || loading} aria-label={t(loading ? "devices.panel.refreshing" : "devices.panel.refresh")}
            title={t(loading ? "devices.panel.refreshing" : "devices.panel.refresh")} onClick={() => void refresh()}>
            <ArrowClockwise size={17} className={loading && snapshot ? "spin" : undefined} />
          </button>
          {direct
            ? <button className="primary-button" disabled={!verified} onClick={direct.run}>{addLabel}</button>
            : addActions.length > 0 && <ActionMenu label={t("devices.panel.add")} actions={addActions}
              trigger={{ content: addLabel, className: "primary-button", disabled: !verified }} />}
        </div>
      </div>
      {!connected ? (
        <div className="devices-notice">
          <LockKey size={20} aria-hidden="true" /> <p>{t("devices.panel.connectFirst")}</p>
          {props.onConnect ? <button className="primary-button" onClick={props.onConnect}>{t("devices.panel.connect")}</button>
            : props.onOpenHome && <button className="secondary-button" onClick={props.onOpenHome}>{t("devices.panel.openHome")}</button>}
        </div>
      ) : loading && !snapshot && !loadError ? (
        <div className="devices-notice" role="status">
          <ArrowClockwise className="spin" size={20} aria-hidden="true" /> <p>{t("devices.panel.loading")}</p>
        </div>
      ) : (
        <>
          {loadError && <InlineError message={loadError} onRetry={() => void refresh()} retryDisabled={loading}
            retryLabel={loading ? t("devices.panel.refreshing") : undefined} />}
          {snapshot && !verified && <p className="settings-note" role="status">
            {loading
              ? savedAt ? t("devices.panel.savedRefreshingAt", { time: savedAt }) : t("devices.panel.savedRefreshing")
              : savedAt ? t("devices.panel.savedStaleAt", { time: savedAt }) : t("devices.panel.savedStale")}
          </p>}
          {controller.memberLifecycleAvailable === false && accessLevel !== "member" && (
            <p className="settings-note">{t("devices.panel.lifecycleUnsupported")}</p>
          )}
          {snapshot && (
            <div className="devices-toolbar">
              {(deviceCount >= SEARCH_FROM || searching) && (
                <label className="devices-search">
                  <MagnifyingGlass size={17} aria-hidden="true" />
                  <span className="sr-only">{t("devices.panel.search")}</span>
                  <input type="search" placeholder={t("devices.panel.searchPlaceholder")} value={query} onChange={(event) => setQuery(event.target.value)} />
                  {searching && <button type="button" className="icon-button" aria-label={t("devices.panel.clearSearch")} onClick={() => setQuery("")}><X size={16} /></button>}
                </label>
              )}
              <p className="devices-summary" aria-label={t("devices.panel.summary.label")}>
                {t("devices.panel.summary.members", { count: snapshot.members.length })}
                {" · "}
                {t("devices.panel.summary.devices", { count: deviceCount })}
                {snapshot.active_invitations.length > 0 && <>{" · "}{t("devices.panel.summary.invitations", { count: snapshot.active_invitations.length })}</>}
              </p>
            </div>
          )}
          {snapshot ? (
            <fieldset className="devices-content" disabled={!verified}>
              <DeviceList
                snapshot={snapshot}
                accessLevel={accessLevel}
                currentDeviceId={profile.device_id}
                platform={props.platform}
                query={query}
                onClearSearch={() => setQuery("")}
                accessBusy={controller.accessBusy}
                peerBusy={controller.peerBusy}
                memberLifecycleAvailable={controller.memberLifecycleAvailable}
                memberBusy={controller.memberBusy}
                onMemberSuspension={controller.changeMemberSuspension}
                onRevokeMemberDevices={controller.revokeMemberDevices}
                onInvite={controller.openInvitation}
                onAccess={controller.updateAccess}
                onTransfer={controller.transferOwnership}
                onRename={(id, name) => setRenameTarget({ id, name })}
                onRevoke={controller.revoke}
                onPeer={controller.updatePeerCommunication}
                onNetwork={onNetwork}
                onPolicy={controller.scopedInvitationsAvailable ? setPolicyTarget : undefined}
                onWireGuard={wireguardAvailable ? setWireguardTarget : undefined}
                onSubnetRoutes={controller.subnetRoutesAvailable ? setRoutesTarget : undefined}
                onPairs={controller.devicePairsAvailable ? setPairsTarget : undefined}
              />
              {lonely && self && (
                <div className="devices-next-step">
                  <DeviceMobile size={24} aria-hidden="true" />
                  <div>
                    <strong>{t("devices.panel.aloneTitle")}</strong>
                    <p>{t(own?.allowed ? canInvite ? "devices.panel.aloneBody" : "devices.panel.aloneBodyOwn"
                      : canInvite ? "devices.panel.aloneBodyInvite" : "devices.panel.aloneBodyNone")}</p>
                  </div>
                </div>
              )}
              <ActiveInvitations snapshot={snapshot} accessLevel={accessLevel} onCancel={controller.cancel} />
            </fieldset>
          ) : null}
        </>
      )}
      <InvitationDialog
        key={`${profile.id}:${controller.inviteOpen}:${controller.inviteTarget?.id ?? "new"}`}
        profile={profile}
        open={controller.inviteOpen}
        target={controller.inviteTarget}
        self={Boolean(self && controller.inviteTarget?.id === self.id)}
        canCreateAdmin={accessLevel === "owner"}
        scopedAvailable={controller.scopedInvitationsAvailable}
        recipientNamesAvailable={verified ? controller.recipientNamesAvailable : null}
        configurationError={loadError}
        onRefreshConfiguration={refresh}
        issuer={issuer}
        delegated={accessLevel === "member"}
        onOpenChange={controller.changeInvitationOpen}
        onCreated={refreshAfterChange}
      />
      {renameTarget && <RenameDeviceDialog key={renameTarget.id} device={renameTarget} onRename={controller.renameDevice} onClose={() => setRenameTarget(null)} />}
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
