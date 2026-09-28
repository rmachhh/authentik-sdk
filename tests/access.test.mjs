import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  defineAccessPolicy,
  extractGroups,
  isMemberOfAppGroup,
} from "../src/access.js";

describe("extractGroups", () => {
  it("reads the groups claim authentik sends", () => {
    assert.deepEqual(extractGroups({ groups: ["a", "b"] }), ["a", "b"]);
  });

  it("accepts a singular group claim from other providers", () => {
    assert.deepEqual(extractGroups({ group: "myapp-access" }), ["myapp-access"]);
  });

  it("accepts a single string in the plural claim", () => {
    assert.deepEqual(extractGroups({ groups: "myapp-access" }), ["myapp-access"]);
  });

  it("de-duplicates, trims and drops non-strings", () => {
    assert.deepEqual(
      extractGroups({ groups: [" a ", "a", "", "  ", null, 42, "b"] }),
      ["a", "b"],
    );
  });

  it("returns an empty list rather than throwing on odd input", () => {
    assert.deepEqual(extractGroups(undefined), []);
    assert.deepEqual(extractGroups(null), []);
    assert.deepEqual(extractGroups("nope"), []);
    assert.deepEqual(extractGroups({}), []);
    assert.deepEqual(extractGroups({ groups: null }), []);
  });
});

describe("isMemberOfAppGroup", () => {
  it("allows a member of the app's group", () => {
    assert.equal(isMemberOfAppGroup(["myapp-access", "hr-access"], "myapp-access"), true);
  });

  it("denies someone who is only in another app's group", () => {
    assert.equal(isMemberOfAppGroup(["hr-access"], "myapp-access"), false);
  });

  it("allows membership of any one of several configured groups", () => {
    assert.equal(isMemberOfAppGroup(["b"], ["a", "b"]), true);
    assert.equal(isMemberOfAppGroup(["c"], ["a", "b"]), false);
  });

  it("tolerates missing or empty group lists", () => {
    assert.equal(isMemberOfAppGroup([], "myapp-access"), false);
    assert.equal(isMemberOfAppGroup(undefined, "myapp-access"), false);
  });

  it("fails closed when the application has not configured a group", () => {
    // An unconfigured guard must never let everyone in.
    assert.equal(isMemberOfAppGroup(["anything"], undefined), false);
    assert.equal(isMemberOfAppGroup(["anything"], ""), false);
    assert.equal(isMemberOfAppGroup(["anything"], []), false);
  });
});

describe("defineAccessPolicy", () => {
  it("requires the group that guards the application", () => {
    assert.throws(() => defineAccessPolicy({}), /requires appGroup/);
    assert.throws(() => defineAccessPolicy({ appGroup: "" }), /requires appGroup/);
    assert.throws(() => defineAccessPolicy({ appGroup: [] }), /requires appGroup/);
  });

  it("grants access from group membership alone, with no role mapping", () => {
    const policy = defineAccessPolicy({ appGroup: "myapp-access" });

    assert.deepEqual(policy.check({ groups: ["myapp-access"] }), {
      allowed: true,
      groups: ["myapp-access"],
      roles: [],
    });
    assert.deepEqual(policy.check({ groups: ["hr-access"] }), {
      allowed: false,
      groups: ["hr-access"],
      roles: [],
    });
  });

  it("reports the groups it saw even when access is denied", () => {
    // Useful for a denial log without leaking the token.
    const policy = defineAccessPolicy({ appGroup: "myapp-access" });
    assert.deepEqual(policy.check({ groups: ["hr-access", "finance-access"] }).groups,
      ["hr-access", "finance-access"]);
  });

  it("applies optional role mapping only when access was granted", () => {
    const policy = defineAccessPolicy({
      appGroup: "myapp-access",
      mapRoles: (groups) => (groups.includes("myapp-admins") ? ["admin"] : ["user"]),
    });

    assert.deepEqual(policy.check({ groups: ["myapp-access", "myapp-admins"] }).roles,
      ["admin"]);
    assert.deepEqual(policy.check({ groups: ["myapp-access"] }).roles, ["user"]);
    // Denied: no roles are computed at all.
    assert.deepEqual(policy.check({ groups: ["hr-access", "myapp-admins"] }).roles, []);
  });

  it("returns no roles when mapping was not configured", () => {
    const policy = defineAccessPolicy({ appGroup: "myapp-access" });
    assert.deepEqual(policy.rolesFrom(["myapp-access"]), []);
  });

  it("maps roles from either claims or a prepared group list", () => {
    const policy = defineAccessPolicy({
      appGroup: "myapp-access",
      mapRoles: (groups) => groups.filter((g) => g.endsWith("-admins")),
    });

    assert.deepEqual(policy.rolesFrom({ groups: ["myapp-admins"] }), ["myapp-admins"]);
    assert.deepEqual(policy.rolesFrom(["myapp-admins"]), ["myapp-admins"]);
  });

  it("exposes the configured group and the raw group list", () => {
    const policy = defineAccessPolicy({ appGroup: "myapp-access" });
    assert.equal(policy.appGroup, "myapp-access");
    assert.deepEqual(policy.groupsFrom({ groups: ["a", "b"] }), ["a", "b"]);
  });
});
