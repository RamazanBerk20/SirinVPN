import { describe, expect, it } from "vitest";
import {
  canCancelInvitation,
  canManageMember,
  canRotateDeviceKeys,
  memberAccessLabel,
  resolveAccess,
} from "./access";
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

describe("management target boundaries", () => {
  it("labels compatibility roles without inventing a third wire role", () => {
    expect(memberAccessLabel(owner)).toBe("Owner");
    expect(memberAccessLabel(admin)).toBe("Admin");
    expect(memberAccessLabel(member)).toBe("Member");
  });

  it("lets Admins manage only ordinary Members", () => {
    expect(canManageMember("owner", owner)).toBe(true);
    expect(canManageMember("owner", admin)).toBe(true);
    expect(canManageMember("admin", member)).toBe(true);
    expect(canManageMember("admin", admin)).toBe(false);
    expect(canManageMember("admin", owner)).toBe(false);
  });

  it("fails closed when an Admin cannot resolve an invitation target", () => {
    expect(canCancelInvitation("admin", invitation(), [owner, admin, member])).toBe(true);
    expect(canCancelInvitation("admin", invitation({ administrator: true }), [owner, admin, member])).toBe(false);
    expect(canCancelInvitation("admin", invitation({ target_member_id: member.id }), [owner, admin, member])).toBe(true);
    expect(canCancelInvitation("admin", invitation({ target_member_id: admin.id }), [owner, admin, member])).toBe(false);
    expect(canCancelInvitation("admin", invitation({ target_member_id: owner.id }), [owner, admin, member])).toBe(false);
    expect(canCancelInvitation("admin", invitation({ target_member_id: "missing" }), [owner, admin, member])).toBe(false);
    expect(canCancelInvitation("owner", invitation({ administrator: true }), [owner, admin, member])).toBe(true);
  });
});
