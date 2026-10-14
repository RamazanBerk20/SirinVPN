import { confirmAction } from "../../lib/confirmAction";
import { useEffect, useRef, useState } from "react";
import { canManageMember } from "../../access";
import { api } from "../../api";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
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
    const name = member.name;
    const confirmation = revoke
      ? {
          title: t("devices.confirm.revokeAll.title", { name }),
          message: t("devices.confirm.revokeAll.message", { count }),
          confirm: t("devices.confirm.revokeAll.action"),
        }
      : suspended
        ? {
            title: t("devices.confirm.suspend.title", { name }),
            message: t("devices.confirm.suspend.message", { count }),
            confirm: t("devices.confirm.suspend.action"),
          }
        : {
            title: t("devices.confirm.reactivate.title", { name }),
            message: t("devices.confirm.reactivate.message"),
            confirm: t("devices.confirm.reactivate.action"),
          };
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
      if (!await confirmAction(confirmation) || !isCurrent()) return;
      const snapshot = revoke
        ? await api.revokeMemberDevices(serverId, member.id, true)
        : await api.updateMemberSuspension(serverId, member.id, suspended);
      if (isCurrent()) latest.current.onSnapshot(snapshot);
    } catch (reason) {
      if (isCurrent())
        latest.current.onError(
          errorMessage(reason, t(revoke ? "devices.error.revokeAll" : "devices.error.suspension")),
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
