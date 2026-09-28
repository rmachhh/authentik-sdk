import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createRoleMapper, pickPrimaryRole } from "../src/roles.js";

const ROLES = ["user", "scheduler", "admin"];
const MAP = {
  "myapp-access": "user",
  "myapp-admins": "admin",
  "hr-access": "user",
};

describe("createRoleMapper", () => {
  it("maps a known group to a role that exists", () => {
    const rolesFrom = createRoleMapper({ map: MAP, roles: ROLES });
    assert.deepEqual(rolesFrom(["myapp-admins"]), ["admin"]);
  });

  it("ignores groups that are not in the map", () => {
    const rolesFrom = createRoleMapper({ map: MAP, roles: ROLES });
    assert.deepEqual(rolesFrom(["authentik Admins", "some-other-team"]), []);
  });

  it("ignores a mapped group naming a role this app does not have", () => {
    // Mapping drift must not grant a role that does not exist.
    const rolesFrom = createRoleMapper({
      map: { "myapp-access": "superuser" },
      roles: ROLES,
    });
    assert.deepEqual(rolesFrom(["myapp-access"]), []);
  });

  it("returns roles in the application's order, not the claim's order", () => {
    const rolesFrom = createRoleMapper({ map: MAP, roles: ROLES });
    const forwards = rolesFrom(["myapp-admins", "myapp-access"]);
    const backwards = rolesFrom(["myapp-access", "myapp-admins"]);
    assert.deepEqual(forwards, backwards);
    assert.deepEqual(forwards, ["user", "admin"]);
  });

  it("does not duplicate a role granted by two groups", () => {
    const rolesFrom = createRoleMapper({ map: MAP, roles: ROLES });
    assert.deepEqual(rolesFrom(["myapp-access", "hr-access"]), ["user"]);
  });

  it("returns nothing when requireAppGroup is not held", () => {
    const rolesFrom = createRoleMapper({
      map: MAP,
      roles: ROLES,
      requireAppGroup: "myapp-access",
    });

    // In another app's group, and even in an admin group — still no roles,
    // because they are not in this application's entry group.
    assert.deepEqual(rolesFrom(["hr-access"]), []);
    assert.deepEqual(rolesFrom(["hr-access", "myapp-admins"]), []);
  });

  it("maps normally when requireAppGroup is held", () => {
    const rolesFrom = createRoleMapper({
      map: MAP,
      roles: ROLES,
      requireAppGroup: "myapp-access",
    });
    assert.deepEqual(rolesFrom(["myapp-access", "myapp-admins"]), ["user", "admin"]);
  });

  it("accepts several required groups", () => {
    const rolesFrom = createRoleMapper({
      map: { ...MAP, "myapp-contractors": "user" },
      roles: ROLES,
      requireAppGroup: ["myapp-access", "myapp-contractors"],
    });
    // Holding either entry group is enough to be mapped.
    assert.deepEqual(rolesFrom(["myapp-contractors"]), ["user"]);
    assert.deepEqual(rolesFrom(["hr-access"]), []);
  });

  it("handles empty and malformed input", () => {
    const rolesFrom = createRoleMapper({ map: MAP, roles: ROLES });
    assert.deepEqual(rolesFrom([]), []);
    assert.deepEqual(rolesFrom(undefined), []);
    assert.deepEqual(rolesFrom([null, 42, ""]), []);
  });

  it("defaults to no mappings and no roles", () => {
    const rolesFrom = createRoleMapper();
    assert.deepEqual(rolesFrom(["anything"]), []);
  });
});

describe("pickPrimaryRole", () => {
  it("returns null when nothing matched", () => {
    assert.equal(pickPrimaryRole([], ROLES), null);
    assert.equal(pickPrimaryRole(undefined, ROLES), null);
  });

  it("returns the single match", () => {
    assert.equal(pickPrimaryRole(["admin"], ROLES), "admin");
  });

  it("prefers the role furthest along the application's own order", () => {
    // admin is last in ROLES, so it is treated as the most privileged.
    assert.equal(pickPrimaryRole(["user", "admin"], ROLES), "admin");
    assert.equal(pickPrimaryRole(["admin", "user"], ROLES), "admin");
    assert.equal(pickPrimaryRole(["user", "scheduler"], ROLES), "scheduler");
  });
});
