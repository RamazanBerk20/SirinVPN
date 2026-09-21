import { confirmAction } from "../../lib/confirmAction";
import { useEffect, useRef, useState } from "react";
import { canManageMember } from "../../access";
import { api } from "../../api";
import { errorMessage } from "../../lib/errors";
import type { MemberSummary, MembershipSnapshot } from "../../types";

type Options = {
  serverId: string;
  connected: boolean;
  available: boolean | null;
  accessLevel: "owner" | "admin" | "member";
  snapshot: MembershipSnapshot | null;
  onSnapshot: (snapshot: MembershipSnapshot) => void;
  onError: (message: string | null) => void;
};

export function useMemberLifecycle(options: Options) {
  const latest = useRef(options);
  latest.current = options;
  const generation = useRef(0);
  const pending = useRef(false);
  const [memberBusy, setMemberBusy] = useState<string | null>(null);

  useEffect(() => {
    ++generation.current;
    pending.current = false;
    setMemberBusy(null);
    return () => {
      ++generation.current;
      pending.current = false;
    };
  }, [options.serverId, options.connected]);

  const perform = async (requested: MemberSummary, revoke: boolean) => {
    const current = latest.current;
    if (!current.connected || !current.available || pending.current) return;
    const member = current.snapshot?.members.find(
      (entry) => entry.id === requested.id,
    );
    if (
      !member ||
      member.role === "owner" ||
      !canManageMember(current.accessLevel, member)
    )
      return;
    const suspended = !Boolean(member.suspended);
    const count = member.devices.length;
    const prompt = revoke
      ? `Revoke all ${count} devices for ${member.name}? This permanently removes their VPN and management access, port forwards and pending device invitations. They will need a new invitation to return.`
      : suspended
        ? `Suspend ${member.name} and all ${count} of their devices? VPN, management, peer access and port forwards will stop. Their identities and settings are kept for reactivation; pending device invitations and key rotations are cancelled.`
        : `Reactivate ${member.name}? The same devices will regain VPN and management access, including their saved peer-access settings and port forwards. Cancelled invitations are not restored.`;
    const at = generation.current;
    const serverId = current.serverId;
    const isCurrent = () =>
      at === generation.current &&
      latest.current.serverId === serverId &&
      latest.current.connected;
    pending.current = true;
    setMemberBusy(member.id);
    current.onError(null);
    try {
      if (!await confirmAction(prompt) || !isCurrent()) return;
      const snapshot = revoke
        ? await api.revokeMemberDevices(serverId, member.id, true)
        : await api.updateMemberSuspension(serverId, member.id, suspended);
      if (isCurrent()) latest.current.onSnapshot(snapshot);
    } catch (reason) {
      if (isCurrent())
        latest.current.onError(
          errorMessage(
            reason,
            revoke
              ? "The member's devices could not be revoked. Refresh access to check their current state."
              : "Member access could not be changed. Refresh access to check its current state.",
          ),
        );
    } finally {
      if (isCurrent()) {
        pending.current = false;
        setMemberBusy(null);
      }
    }
  };

  return {
    memberBusy,
    changeMemberSuspension: (member: MemberSummary) => perform(member, false),
    revokeMemberDevices: (member: MemberSummary) => perform(member, true),
  };
}
