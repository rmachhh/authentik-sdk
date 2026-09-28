import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { defineAccessPolicy } from "../src/access.js";
import { accessConfigFromEnv, connectionConfigFromEnv, ENV_KEYS } from "../src/config.js";
import { createRoleMapper } from "../src/roles.js";

// Tests pass an env object explicitly rather than mutating process.env, so they
// cannot interfere with each other or with the machine running them.

describe("accessConfigFromEnv", () => {
  it("reads the group and role", () => {
    const config = accessConfigFromEnv({
      AUTHENTIK_APP_GROUP: "sis-access",
      AUTHENTIK_APP_ROLE: "superadmin",
    });

    assert.deepEqual(config, { appGroup: "sis-access", appRole: "superadmin" });
  });

  it("omits keys that are unset, including blank ones", () => {
    // A blank value must not overwrite a caller's default with an empty string.
    assert.deepEqual(accessConfigFromEnv({}), {});
    assert.deepEqual(accessConfigFromEnv({ AUTHENTIK_APP_GROUP: "" }), {});
    assert.deepEqual(accessConfigFromEnv({ AUTHENTIK_APP_GROUP: "   " }), {});
    assert.deepEqual(accessConfigFromEnv(undefined), {});
  });

  it("trims surrounding whitespace", () => {
    assert.deepEqual(
      accessConfigFromEnv({ AUTHENTIK_APP_GROUP: "  sis-access  " }).appGroup,
      "sis-access",
    );
  });
});

describe("connectionConfigFromEnv", () => {
  it("reads the connection settings", () => {
    const config = connectionConfigFromEnv({
      AUTHENTIK_ISSUER: "https://id.example.com/application/o/app/",
      AUTHENTIK_CLIENT_ID: "app",
      AUTHENTIK_CLIENT_SECRET: "secret",
      AUTHENTIK_REDIRECT_URI: "https://app.example.com/cb",
    });

    assert.equal(config.issuer, "https://id.example.com/application/o/app/");
    assert.equal(config.clientId, "app");
    assert.equal(config.clientSecret, "secret");
    assert.equal(config.redirectUri, "https://app.example.com/cb");
  });

  it("lets explicit overrides win", () => {
    const config = connectionConfigFromEnv(
      { AUTHENTIK_CLIENT_ID: "from-env" },
      { clientId: "explicit" },
    );

    assert.equal(config.clientId, "explicit");
  });

  it("exposes the key names it reads", () => {
    assert.equal(ENV_KEYS.appGroup, "AUTHENTIK_APP_GROUP");
    assert.equal(ENV_KEYS.appRole, "AUTHENTIK_APP_ROLE");
  });
});

describe("defineAccessPolicy with the environment", () => {
  it("takes the group from the environment when not passed", () => {
    const policy = defineAccessPolicy({ env: { AUTHENTIK_APP_GROUP: "sis-access" } });

    assert.equal(policy.appGroup, "sis-access");
    assert.equal(policy.check({ groups: ["sis-access"] }).allowed, true);
    assert.equal(policy.check({ groups: ["other"] }).allowed, false);
  });

  it("lets an explicit group win over the environment", () => {
    const policy = defineAccessPolicy({
      appGroup: "explicit",
      env: { AUTHENTIK_APP_GROUP: "from-env" },
    });

    assert.equal(policy.appGroup, "explicit");
  });

  it("reports the configured role when access is allowed", () => {
    const policy = defineAccessPolicy({
      env: { AUTHENTIK_APP_GROUP: "sis-access", AUTHENTIK_APP_ROLE: "superadmin" },
    });

    assert.deepEqual(policy.check({ groups: ["sis-access"] }).roles, ["superadmin"]);
    // No access, no role.
    assert.deepEqual(policy.check({ groups: ["other"] }).roles, []);
  });

  it("still refuses to build without a group anywhere", () => {
    assert.throws(
      () => defineAccessPolicy({ env: {} }),
      /requires appGroup/,
      "an unconfigured guard must not silently allow everyone",
    );
  });

  it("names the environment variable in the error, so the fix is obvious", () => {
    assert.throws(() => defineAccessPolicy({ env: {} }), /AUTHENTIK_APP_GROUP/);
  });
});

describe("createRoleMapper with a single role", () => {
  const env = { AUTHENTIK_APP_GROUP: "sis-access", AUTHENTIK_APP_ROLE: "superadmin" };
  const roles = ["superadmin", "teacher", "guest"];

  it("grants the role to a member of the app group", () => {
    const rolesFrom = createRoleMapper({ roles, env });
    assert.deepEqual(rolesFrom(["sis-access"]), ["superadmin"]);
  });

  it("does not grant the role to someone outside the group", () => {
    // The group is still the gate. Granting on the role alone would hand a role
    // to a user who was never admitted.
    const rolesFrom = createRoleMapper({ roles, env });
    assert.deepEqual(rolesFrom(["hr-access"]), []);
    assert.deepEqual(rolesFrom([]), []);
  });

  it("does not grant a role this application does not have", () => {
    const rolesFrom = createRoleMapper({ roles: ["teacher"], env });
    assert.deepEqual(rolesFrom(["sis-access"]), []);
  });

  it("prefers an explicit gate over the configured group", () => {
    const rolesFrom = createRoleMapper({ roles, env, requireAppGroup: "explicit-gate" });
    assert.deepEqual(rolesFrom(["explicit-gate"]), ["superadmin"]);
    assert.deepEqual(rolesFrom(["sis-access"]), []);
  });

  it("still maps groups when no single role is configured", () => {
    const rolesFrom = createRoleMapper({
      roles,
      map: { "sis-admins": "superadmin" },
      env: { AUTHENTIK_APP_GROUP: "sis-access" },
    });

    assert.deepEqual(rolesFrom(["sis-access", "sis-admins"]), ["superadmin"]);
  });
});
