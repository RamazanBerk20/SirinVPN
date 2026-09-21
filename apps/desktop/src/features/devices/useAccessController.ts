import { confirmAction } from "../../lib/confirmAction";
import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { canManageMember } from "../../access";
import { api } from "../../api";
import type {
  MemberSummary,
  MembershipSnapshot,
  PortForwardProtocol,
  ServerProfile,
} from "../../types";
import { errorMessage } from "../../lib/errors";
import { useMemberLifecycle } from "./useMemberLifecycle";
import { cachedMembership, readMembership, retainMembership, withoutLiveActivity } from "./membershipCache";
export interface AccessProps {
  profile: Pick<ServerProfile, "id" | "name" | "device_id">;
  platform?: "desktop";
  connected: boolean;
  accessLevel: "owner" | "admin" | "member";
  onAccessChanged: () => Promise<void>;
}
export function useAccessController({
  profile,
  connected,
  accessLevel,
  onAccessChanged,
  platform = "desktop",
}: AccessProps) {
  const cacheKey = `${platform}:${profile.id}:${profile.device_id ?? ""}:${accessLevel}`;
  const retained = cachedMembership(cacheKey);
  const [stored, setStored] = useState<{ key: string; value: MembershipSnapshot | null }>({ key: cacheKey,
    value: connected && retained?.value ? withoutLiveActivity(retained.value) : null });
  const snapshot = stored.key === cacheKey ? stored.value : retained?.value ? withoutLiveActivity(retained.value) : null;
  const setSnapshot = (value: MembershipSnapshot | null | ((current: MembershipSnapshot | null) => MembershipSnapshot | null)) =>
    setStored(current => ({ key: cacheKey, value: typeof value === "function" ? value(current.key === cacheKey ? current.value : null) : value }));
  const [verifiedKey, setVerifiedKey] = useState<string | null>(null);
  const verified = connected && verifiedKey === cacheKey;
  const [updatedAt, setUpdatedAt] = useState<number | null>(retained?.at ?? null);
  const revision = useRef(0);
  const request = useRef(0);
  const actionScope = useRef(0);
  // A background read must not cancel an OS dialog that is still being reviewed.
  useEffect(() => () => { actionScope.current += 1; }, [profile.id, connected, accessLevel]);
  const updateSnapshot = (next: MembershipSnapshot) => {
    revision.current += 1;
    retainMembership(cacheKey, next);
    setUpdatedAt(Date.now());
    setVerifiedKey(cacheKey);
    setSnapshot(next);
    setMembershipFailure(null);
  };
  const [loading, setLoading] = useState(false);
  const [membershipFailure, setMembershipFailure] = useState<{ key: string; message: string } | null>(null);
  const [configurationFailure, setConfigurationFailure] = useState<{ key: string; message: string } | null>(null);
  const loadError = connected
    ? (membershipFailure?.key === cacheKey ? membershipFailure.message : null)
      ?? (configurationFailure?.key === cacheKey ? configurationFailure.message : null)
    : null;
  const [error, setError] = useState<string | null>(null);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteTarget, setInviteTarget] = useState<MemberSummary | null>(null);
  const [accessBusy, setAccessBusy] = useState<string | null>(null);
  const [peerBusy, setPeerBusy] = useState<string | null>(null);
  const [scopedInvitationsAvailable, setScopedInvitationsAvailable] = useState(false);
  const [invitationNaming, setInvitationNaming] = useState<{
    serverId: string;
    available: boolean;
  } | null>(null);
  const recipientNamesAvailable = connected && invitationNaming?.serverId === profile.id
    ? invitationNaming.available : null;
  const [memberLifecycleAvailable, setMemberLifecycleAvailable] = useState<
    boolean | null
  >(null);
  const { memberBusy, changeMemberSuspension, revokeMemberDevices } =
    useMemberLifecycle({
      serverId: profile.id,
      connected: verified,
      available: memberLifecycleAvailable,
      accessLevel,
      snapshot,
      onSnapshot: updateSnapshot,
      onError: setError,
    });
  const [portForwardingAvailable, setPortForwardingAvailable] = useState<
    boolean | null
  >(null);
  const [forwardProtocol, setForwardProtocol] =
    useState<PortForwardProtocol>("tcp");
  const [forwardPublicPort, setForwardPublicPort] = useState("");
  const [forwardDeviceId, setForwardDeviceId] = useState("");
  const [forwardDevicePort, setForwardDevicePort] = useState("");
  const [forwardBusy, setForwardBusy] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const owner = accessLevel === "owner";

  const refresh = useCallback(async () => {
    const generation = ++request.current;
    const startedRevision = revision.current;
    if (!connected) {
      setLoading(false);
      setVerifiedKey(null);
      setSnapshot(null);
      setMembershipFailure(null);
      setConfigurationFailure(null);
      setPortForwardingAvailable(null);
      setMemberLifecycleAvailable(null);
      setScopedInvitationsAvailable(false);
      setInvitationNaming(null);
      return;
    }
    setLoading(true);
    // Keep each failure until that same read succeeds. Clearing on retry makes
    // persistent failures flash and lets one successful read hide the other.
    const capabilities = api.serverConfiguration(profile.id).then(configuration => {
      if (generation !== request.current) return;
      setScopedInvitationsAvailable(Boolean(configuration.reusable_invitations_enabled));
      setInvitationNaming({ serverId: profile.id, available: Boolean(configuration.recipient_names_enabled) });
      setPortForwardingAvailable(Boolean(configuration.port_forwarding_enabled));
      setMemberLifecycleAvailable(Boolean(configuration.member_lifecycle_enabled));
      setConfigurationFailure(null);
    }, reason => {
      if (generation !== request.current) return;
      setMemberLifecycleAvailable(null); setPortForwardingAvailable(null);
      setScopedInvitationsAvailable(false); setInvitationNaming(null);
      setConfigurationFailure({ key: cacheKey, message: errorMessage(reason, "Server capabilities could not be refreshed.") });
    });
    const membership = readMembership(cacheKey, () => api.membership(profile.id)).then(nextSnapshot => {
      if (generation !== request.current || startedRevision !== revision.current) return;
      setSnapshot(nextSnapshot);
      setVerifiedKey(cacheKey);
      setUpdatedAt(Date.now());
      setMembershipFailure(null);
    }, reason => {
      if (generation !== request.current || startedRevision !== revision.current) return;
      setVerifiedKey(null);
      setSnapshot(current => current && withoutLiveActivity(current));
      setMembershipFailure({ key: cacheKey, message: errorMessage(reason, "Current access could not be read from the VPS.") });
    }).finally(() => {
      if (generation === request.current) setLoading(false);
    });
    await Promise.all([membership, capabilities]);
  }, [connected, profile.id, cacheKey]);

  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    const poll = async () => {
      if (!document.hidden) await refresh();
      if (active && connected)
        timer = window.setTimeout(() => void poll(), 10_000);
    };
    void poll();
    return () => {
      active = false;
      ++request.current;
      window.clearTimeout(timer);
    };
  }, [connected, refresh]);

  const rename = async (deviceId: string, currentName: string) => {
    if (!verified) return;
    const name = window.prompt("Device name", currentName)?.trim();
    if (!name || name === currentName) return;
    setError(null);
    try {
      updateSnapshot(await api.renameDevice(profile.id, deviceId, name));
    } catch (reason) {
      setError(errorMessage(reason, "The device could not be renamed."));
    }
  };

  const confirmCurrentAction = async (message: string) => {
    if (!verified) return false;
    const generation = actionScope.current;
    return await confirmAction(message) && generation === actionScope.current;
  };

  const revoke = async (deviceId: string, deviceName: string) => {
    if (
      !await confirmCurrentAction(
        `Revoke ${deviceName}? Its VPN and management access will stop immediately.`,
      )
    )
      return;
    setError(null);
    try {
      updateSnapshot(await api.revokeDevice(profile.id, deviceId));
    } catch (reason) {
      setError(errorMessage(reason, "The device could not be revoked."));
    }
  };

  const updatePeerCommunication = async (
    deviceId: string,
    deviceName: string,
    currentlyEnabled: boolean,
  ) => {
    const enabled = !currentlyEnabled;
    const prompt = enabled
      ? `Allow ${deviceName} to communicate directly with other explicitly allowed VPN devices? Both devices must have peer access enabled.`
      : `Return ${deviceName} to internet-only isolation? Existing direct connections to other VPN devices will stop.`;
    if (!await confirmCurrentAction(prompt)) return;
    setPeerBusy(deviceId);
    setError(null);
    try {
      updateSnapshot(
        await api.updateDevicePeerCommunication(profile.id, deviceId, enabled),
      );
    } catch (reason) {
      setError(
        errorMessage(reason, "Peer communication could not be changed."),
      );
    } finally {
      setPeerBusy(null);
    }
  };

  const createPortForward = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!snapshot || !portForwardingAvailable) return;
    const targets = snapshot.members.flatMap((member) =>
      !member.suspended && (canManageMember(accessLevel, member) || (accessLevel === "member" && member.policy?.manage_own_port_forwards))
        ? member.devices.map((device) => ({ member, device }))
        : [],
    );
    const deviceId = targets.some(({ device }) => device.id === forwardDeviceId)
      ? forwardDeviceId
      : targets[0]?.device.id || "";
    const target = targets.find(({ device }) => device.id === deviceId);
    const publicPort = Number(forwardPublicPort);
    const devicePort = Number(forwardDevicePort);
    if (
      !target ||
      !Number.isInteger(publicPort) ||
      publicPort < 1024 ||
      publicPort > 65535 ||
      !Number.isInteger(devicePort) ||
      devicePort < 1 ||
      devicePort > 65535
    ) {
      setError(
        "Choose a device, a public port from 1024 to 65535, and a device port from 1 to 65535.",
      );
      return;
    }
    const confirmed = await confirmCurrentAction(
      `Expose public ${forwardProtocol.toUpperCase()} port ${publicPort} on this VPS and forward it to ${target.member.name} / ${target.device.name} on port ${devicePort}? Anyone on the internet can attempt to reach that service.`,
    );
    if (!confirmed) return;
    setForwardBusy("create");
    setError(null);
    try {
      updateSnapshot(
        await api.createPortForward(
          profile.id,
          forwardProtocol,
          publicPort,
          deviceId,
          devicePort,
        ),
      );
      setForwardPublicPort("");
      setForwardDevicePort("");
    } catch (reason) {
      setError(errorMessage(reason, "The public port could not be forwarded."));
    } finally {
      setForwardBusy(null);
    }
  };

  const removePortForward = async (
    protocol: PortForwardProtocol,
    publicPort: number,
  ) => {
    if (
      !await confirmCurrentAction(
        `Close public ${protocol.toUpperCase()} port ${publicPort} immediately?`,
      )
    )
      return;
    const key = `${protocol}:${publicPort}`;
    setForwardBusy(key);
    setError(null);
    try {
      updateSnapshot(
        await api.removePortForward(profile.id, protocol, publicPort),
      );
    } catch (reason) {
      setError(errorMessage(reason, "The public port could not be closed."));
    } finally {
      setForwardBusy(null);
    }
  };

  const cancel = async (invitationId: string) => {
    if (!verified) return;
    setError(null);
    try {
      await api.cancelInvitation(profile.id, invitationId);
      await refresh();
    } catch (reason) {
      setError(errorMessage(reason, "The invitation could not be cancelled."));
    }
  };

  const updateAccess = async (member: MemberSummary) => {
    const administrator = !Boolean(member.administrator);
    const prompt = administrator
      ? `Make ${member.name} an Admin? Admins can invite Members and manage ordinary Member devices.`
      : `Remove Admin access from ${member.name}? Their VPN devices will remain authorized.`;
    if (!await confirmCurrentAction(prompt)) return;
    setAccessBusy(member.id);
    setError(null);
    try {
      updateSnapshot(
        await api.updateMemberAccess(profile.id, member.id, administrator),
      );
    } catch (reason) {
      setError(
        errorMessage(reason, "The member access level could not be changed."),
      );
    } finally {
      setAccessBusy(null);
    }
  };

  const transferOwnership = async (member: MemberSummary) => {
    const destination = member.devices[0];
    if (!destination) return;
    const fingerprint = destination.identity_fingerprint
      ? destination.identity_fingerprint
      : destination.id;
    const confirmed = await confirmCurrentAction(
      `Transfer ownership to ${member.name} through ${destination.name} (identity ${fingerprint})? ${member.name}'s devices will become Owner devices. This device will become an Admin and only the new Owner can transfer ownership again.`,
    );
    if (!confirmed) return;
    setAccessBusy(member.id);
    setError(null);
    try {
      updateSnapshot(await api.transferOwnership(profile.id, destination.id));
      await onAccessChanged();
    } catch (reason) {
      setError(errorMessage(reason, "Ownership could not be transferred."));
    } finally {
      setAccessBusy(null);
    }
  };

  const openInvitation = (target: MemberSummary | null) => {
    if (!verified || target?.suspended) return;
    setInviteTarget(target);
    setInviteOpen(true);
  };

  const changeInvitationOpen = (open: boolean) => {
    setInviteOpen(open);
    if (!open) setInviteTarget(null);
  };

  return {
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
    portForwardingAvailable,
    forwardProtocol,
    setForwardProtocol: (value: PortForwardProtocol) => { setForwardProtocol(value); setError(null); },
    forwardPublicPort,
    setForwardPublicPort: (value: string) => { setForwardPublicPort(value); setError(null); },
    forwardDeviceId,
    setForwardDeviceId,
    forwardDevicePort,
    setForwardDevicePort,
    forwardBusy,
    query,
    setQuery,
    owner,
    refresh,
    rename,
    revoke,
    updatePeerCommunication,
    createPortForward,
    removePortForward,
    cancel,
    updateAccess,
    transferOwnership,
    openInvitation,
    changeInvitationOpen,
  };
}
