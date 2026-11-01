import { confirmAction } from "../../lib/confirmAction";
import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { canManagePortForwards } from "../../access";
import { api } from "../../api";
import type {
  MemberSummary,
  MembershipSnapshot,
  PortForwardProtocol,
  ServerProfile,
} from "../../types";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
import type { Confirmation } from "../../lib/confirmAction";
import { useMemberLifecycle } from "./useMemberLifecycle";
import { cachedMembership, invalidateMembership, readMembership, retainMembership, withoutLiveActivity } from "./membershipCache";
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
  // A failure may belong under the public port field. Server messages are matched by
  // content; failures raised here are flagged where they happen.
  const [failure, setFailure] = useState<{ message: string; publicPort: boolean } | null>(null);
  const error = failure?.message ?? null;
  const publicPortError = failure?.publicPort ? failure.message : null;
  const setError = (message: string | null, publicPort = false) =>
    setFailure(message === null ? null : { message, publicPort });
  const setPortError = (reason: unknown, fallback: string) => {
    const server = errorMessage(reason, "");
    setError(server || fallback, !server || /reserved|public.*port/i.test(server));
  };
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteTarget, setInviteTarget] = useState<MemberSummary | null>(null);
  const [accessBusy, setAccessBusy] = useState<string | null>(null);
  const [peerBusy, setPeerBusy] = useState<string | null>(null);
  const [scopedInvitationsAvailable, setScopedInvitationsAvailable] = useState(false);
  const [wireguardDevicesAvailable, setWireguardDevicesAvailable] = useState(false);
  const [subnetRoutesAvailable, setSubnetRoutesAvailable] = useState(false);
  const [devicePairsAvailable, setDevicePairsAvailable] = useState(false);
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
      setWireguardDevicesAvailable(false);
      setSubnetRoutesAvailable(false);
      setDevicePairsAvailable(false);
      setInvitationNaming(null);
      return;
    }
    setLoading(true);
    // Keep each failure until that same read succeeds. Clearing on retry makes
    // persistent failures flash and lets one successful read hide the other.
    const capabilities = api.serverConfiguration(profile.id).then(configuration => {
      if (generation !== request.current) return;
      setScopedInvitationsAvailable(Boolean(configuration.reusable_invitations_enabled));
      setWireguardDevicesAvailable(Boolean(configuration.wireguard_devices_enabled));
      setSubnetRoutesAvailable(Boolean(configuration.subnet_routes_enabled));
      setDevicePairsAvailable(Boolean(configuration.device_pairs_enabled));
      setInvitationNaming({ serverId: profile.id, available: Boolean(configuration.recipient_names_enabled) });
      setPortForwardingAvailable(Boolean(configuration.port_forwarding_enabled));
      setMemberLifecycleAvailable(Boolean(configuration.member_lifecycle_enabled));
      setConfigurationFailure(null);
    }, reason => {
      if (generation !== request.current) return;
      setMemberLifecycleAvailable(null); setPortForwardingAvailable(null);
      setScopedInvitationsAvailable(false); setWireguardDevicesAvailable(false); setSubnetRoutesAvailable(false); setDevicePairsAvailable(false); setInvitationNaming(null);
      setConfigurationFailure({ key: cacheKey, message: errorMessage(reason, t("devices.error.features")) });
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
      setMembershipFailure({ key: cacheKey, message: errorMessage(reason, t("devices.error.load")) });
    }).finally(() => {
      if (generation === request.current) setLoading(false);
    });
    await Promise.all([membership, capabilities]);
  }, [connected, profile.id, cacheKey]);

  const refreshAfterChange = useCallback(() => {
    invalidateMembership(cacheKey);
    return refresh();
  }, [cacheKey, refresh]);

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
    const name = window.prompt(t("devices.rename.prompt"), currentName)?.trim();
    if (!name || name === currentName) return;
    setError(null);
    try {
      updateSnapshot(await api.renameDevice(profile.id, deviceId, name));
    } catch (reason) {
      setError(errorMessage(reason, t("devices.error.rename")));
    }
  };

  const confirmCurrentAction = async (confirmation: Confirmation) => {
    if (!verified) return false;
    const generation = actionScope.current;
    return await confirmAction(confirmation) && generation === actionScope.current;
  };

  const revoke = async (deviceId: string, deviceName: string) => {
    if (
      !await confirmCurrentAction({
        title: t("devices.confirm.revoke.title", { name: deviceName }),
        message: t("devices.confirm.revoke.message"),
        confirm: t("devices.confirm.revoke.action"),
      })
    )
      return;
    setError(null);
    try {
      updateSnapshot(await api.revokeDevice(profile.id, deviceId));
    } catch (reason) {
      setError(errorMessage(reason, t("devices.error.revoke")));
    }
  };

  const updatePeerCommunication = async (
    deviceId: string,
    deviceName: string,
    currentlyEnabled: boolean,
  ) => {
    const enabled = !currentlyEnabled;
    const confirmation = enabled
      ? {
          title: t("devices.confirm.allowMutual.title", { name: deviceName }),
          message: t("devices.confirm.allowMutual.message"),
          confirm: t("devices.confirm.allowMutual.action"),
        }
      : {
          title: t("devices.confirm.isolate.title", { name: deviceName }),
          message: t("devices.confirm.isolate.message"),
          confirm: t("devices.confirm.isolate.action"),
        };
    if (!await confirmCurrentAction(confirmation)) return;
    setPeerBusy(deviceId);
    setError(null);
    try {
      updateSnapshot(
        await api.updateDevicePeerCommunication(profile.id, deviceId, enabled),
      );
    } catch (reason) {
      setError(errorMessage(reason, t("devices.error.mutualAccess")));
    } finally {
      setPeerBusy(null);
    }
  };

  const createPortForward = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!snapshot || !portForwardingAvailable) return;
    const targets = snapshot.members.flatMap((member) =>
      !member.suspended && canManagePortForwards(accessLevel, member)
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
      setError(t("devices.error.portsInvalid"), true);
      return;
    }
    const confirmed = await confirmCurrentAction({
      title: t("devices.confirm.openPort.title", { publicPort }),
      message: t("devices.confirm.openPort.message", {
        protocol: forwardProtocol.toUpperCase(),
        publicPort,
        member: target.member.name,
        device: target.device.name,
        devicePort,
      }),
      confirm: t("devices.confirm.openPort.action"),
    });
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
      setPortError(reason, t("devices.error.openPort"));
    } finally {
      setForwardBusy(null);
    }
  };

  const removePortForward = async (
    protocol: PortForwardProtocol,
    publicPort: number,
  ) => {
    if (
      !await confirmCurrentAction({
        title: t("devices.confirm.closePort.title", { protocol: protocol.toUpperCase(), publicPort }),
        message: t("devices.confirm.closePort.message"),
        confirm: t("devices.confirm.closePort.action"),
      })
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
      setPortError(reason, t("devices.error.closePort"));
    } finally {
      setForwardBusy(null);
    }
  };

  const cancel = async (invitationId: string) => {
    if (!verified) return;
    setError(null);
    try {
      await api.cancelInvitation(profile.id, invitationId);
      await refreshAfterChange();
    } catch (reason) {
      setError(errorMessage(reason, t("devices.error.cancelInvitation")));
    }
  };

  const updateAccess = async (member: MemberSummary) => {
    const administrator = !Boolean(member.administrator);
    const confirmation = administrator
      ? {
          title: t("devices.confirm.makeAdmin.title", { name: member.name }),
          message: t("devices.confirm.makeAdmin.message"),
          confirm: t("devices.confirm.makeAdmin.action"),
        }
      : {
          title: t("devices.confirm.removeAdmin.title", { name: member.name }),
          message: t("devices.confirm.removeAdmin.message"),
          confirm: t("devices.confirm.removeAdmin.action"),
        };
    if (!await confirmCurrentAction(confirmation)) return;
    setAccessBusy(member.id);
    setError(null);
    try {
      updateSnapshot(
        await api.updateMemberAccess(profile.id, member.id, administrator),
      );
    } catch (reason) {
      setError(errorMessage(reason, t("devices.error.role")));
    } finally {
      setAccessBusy(null);
    }
  };

  const transferOwnership = async (member: MemberSummary) => {
    // A WireGuard-only device cannot manage the server, so it can never become the Owner's.
    const destination = member.devices.find((device) => !device.wireguard_only);
    if (!destination) return;
    const fingerprint = destination.identity_fingerprint
      ? destination.identity_fingerprint
      : destination.id;
    const confirmed = await confirmCurrentAction({
      title: t("devices.confirm.transfer.title", { name: member.name }),
      message: t("devices.confirm.transfer.message", { device: destination.name, fingerprint }),
      confirm: t("devices.confirm.transfer.action"),
    });
    if (!confirmed) return;
    setAccessBusy(member.id);
    setError(null);
    try {
      updateSnapshot(await api.transferOwnership(profile.id, destination.id));
      await onAccessChanged();
    } catch (reason) {
      setError(errorMessage(reason, t("devices.error.transfer")));
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
    publicPortError,
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
    refreshAfterChange,
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
