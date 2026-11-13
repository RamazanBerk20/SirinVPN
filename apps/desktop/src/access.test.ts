import { describe, expect, it } from "vitest";
import {
  canActOnOwn,
  canAddDeviceFor,
  canCancelJoinCode,
  canManagePerson,
  canRotateDeviceKeys,
  personRole,
  roleLabel,
  resolveAccess,
} from "./access";
import { t } from "./i18n";
import type { ActiveInvitationSummary, MemberSummary } from "./types";

const owner: MemberSummary = {
  id: "owner",
  name: "Owner",
  role: "owner",
  devices: [],
};
const admin: MemberSummary = {
  id: "admin",
  name: "Alice",
  role: "member",
  administrator: true,
  devices: [],
};
const member: MemberSummary = {
  id: "member",
  name: "Bob",
  role: "member",
  devices: [],
};

function invitation(overrides: Partial<ActiveInvitationSummary> = {}): ActiveInvitationSummary {
  return {
    id: "invitation",
    member_name: "Bob",
    device_name: "Laptop",
    expires_at_unix: 1_000,
    ...overrides,
  };
}

describe("live management access", () => {
  it("uses authenticated status instead of a stale local Admin flag", () => {
    expect(resolveAccess({ role: "member", administrator: false }, {
      caller_role: "member",
      caller_administrator: true,
    }, true)).toEqual({ level: "admin", canManage: true });

    expect(resolveAccess({ role: "member", administrator: true }, {
      caller_role: "member",
      caller_administrator: false,
    }, true)).toEqual({ level: "member", canManage: false });
  });

  it("does not trust an offline cached Admin flag", () => {
    expect(resolveAccess({ role: "member", administrator: true }, null, false)).toEqual({
      level: "admin",
      canManage: false,
    });
    expect(resolveAccess({ role: "owner" }, null, false)).toEqual({
      level: "owner",
      canManage: true,
    });
  });
});

describe("device key rotation gate", () => {
  it("requires a live tunnel for a new rotation but permits disconnected recovery", () => {
    expect(canRotateDeviceKeys(true, false, false)).toBe(true);
    expect(canRotateDeviceKeys(false, false, false)).toBe(false);
    expect(canRotateDeviceKeys(false, true, false)).toBe(true);
    expect(canRotateDeviceKeys(true, true, true)).toBe(false);
  });
});

describe("roles", () => {
  it("names the three roles without inventing a third wire role", () => {
    expect([owner, admin, member].map(personRole)).toEqual(["owner", "admin", "member"]);
    expect(roleLabel("owner")).toBe(t("common.role.owner"));
    expect(roleLabel("admin")).toBe(t("common.role.admin"));
    expect(roleLabel("member")).toBe(t("common.role.member"));
  });

  it("lets Admins manage only Members", () => {
    expect(canManagePerson("owner", owner)).toBe(true);
    expect(canManagePerson("owner", admin)).toBe(true);
    expect(canManagePerson("admin", member)).toBe(true);
    expect(canManagePerson("admin", admin)).toBe(false);
    expect(canManagePerson("admin", owner)).toBe(false);
    expect(canManagePerson("member", member)).toBe(false);
  });

  it("lets a person act on their own devices when their permissions allow it, Admins included", () => {
    const allowedAdmin = { ...admin, policy: { device_limit: null, expires_at_unix: null, weekly_access: [], invite_members: false,
      add_own_devices: true, manage_own_peer_communication: false, manage_own_port_forwards: false } };
    expect(canActOnOwn("admin", allowedAdmin, admin.id, "add_own_devices")).toBe(true);
    expect(canActOnOwn("admin", admin, admin.id, "add_own_devices")).toBe(false);
    expect(canActOnOwn("admin", allowedAdmin, "someone else", "add_own_devices")).toBe(false);
    expect(canActOnOwn("admin", allowedAdmin, admin.id, "manage_own_port_forwards")).toBe(false);
  });

  it("fails closed when an Admin cannot resolve a join code's person", () => {
    const people = [owner, admin, member];
    expect(canCancelJoinCode("admin", invitation(), people, admin.id)).toBe(true);
    expect(canCancelJoinCode("admin", invitation({ administrator: true }), people, admin.id)).toBe(false);
    expect(canCancelJoinCode("admin", invitation({ target_member_id: member.id }), people, admin.id)).toBe(true);
    expect(canCancelJoinCode("admin", invitation({ target_member_id: admin.id, administrator: true }), people, admin.id)).toBe(true);
    expect(canCancelJoinCode("admin", invitation({ target_member_id: admin.id }), people, "other")).toBe(false);
    expect(canCancelJoinCode("admin", invitation({ target_member_id: owner.id }), people, admin.id)).toBe(false);
    expect(canCancelJoinCode("admin", invitation({ target_member_id: "missing" }), people, admin.id)).toBe(false);
    expect(canCancelJoinCode("owner", invitation({ administrator: true }), people, owner.id)).toBe(true);
  });
});

describe("adding devices", () => {
  it("lets an Admin add their own device without a grant only where the server allows it", () => {
    expect(canAddDeviceFor("admin", admin, admin.id, false)).toBe(false);
    expect(canAddDeviceFor("admin", { ...admin, policy: { add_own_devices: true } as MemberSummary["policy"] }, admin.id, false)).toBe(true);
    expect(canAddDeviceFor("admin", admin, admin.id, true)).toBe(true);
    expect(canAddDeviceFor("admin", owner, admin.id, true)).toBe(false);
    expect(canAddDeviceFor("member", member, member.id, true)).toBe(false);
    expect(canAddDeviceFor("admin", member, admin.id, false)).toBe(true);
  });
});
