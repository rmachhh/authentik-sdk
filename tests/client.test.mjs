import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createAuthentikClient } from "../src/client.js";
import { DEFAULT_SCOPES } from "../src/scopes.js";
import { createEphemeralStore } from "../src/stores.js";

const VALID = {
  issuer: "https://id.example.com/application/o/records/",
  clientId: "records",
  clientSecret: "secret",
  redirectUri: "https://records.example.com/auth/callback",
};

describe("createAuthentikClient", () => {
  it("requires every connection setting", () => {
    for (const missing of ["issuer", "clientId", "clientSecret", "redirectUri"]) {
      const options = { ...VALID, [missing]: undefined };
      assert.throws(
        () => createAuthentikClient(options),
        new RegExp(`requires ${missing}`),
        `expected a clear error when ${missing} is missing`,
      );
    }
  });

  it("defaults to the scopes needed for identity and groups", () => {
    const auth = createAuthentikClient(VALID);
    assert.equal(auth.scopes, DEFAULT_SCOPES);
    assert.equal(DEFAULT_SCOPES, "openid email profile");
  });

  it("accepts a custom scope string", () => {
    const auth = createAuthentikClient({ ...VALID, scopes: "openid email" });
    assert.equal(auth.scopes, "openid email");
  });

  it("exposes the configuration it was built with", () => {
    const auth = createAuthentikClient(VALID);
    assert.equal(auth.issuer, VALID.issuer);
    assert.equal(auth.clientId, "records");
    assert.equal(auth.redirectUri, VALID.redirectUri);
  });

  it("refuses a plain-HTTP issuer unless explicitly allowed", async () => {
    // Guards against a production deployment silently sending credentials in
    // the clear. The check happens before any network call.
    const auth = createAuthentikClient({
      ...VALID,
      issuer: "http://localhost:9000/application/o/records/",
    });

    await assert.rejects(
      () => auth.authorizationUrl("flow-1", createEphemeralStore()),
      /Refusing plain-HTTP issuer/,
    );
  });

  it("requires a flow id to key the stored state", async () => {
    const auth = createAuthentikClient(VALID);
    await assert.rejects(
      () => auth.authorizationUrl("", createEphemeralStore()),
      /requires a flowId/,
    );
  });

  it("requires a store that can persist the flow state", async () => {
    const auth = createAuthentikClient(VALID);
    await assert.rejects(() => auth.authorizationUrl("flow-1", {}), /saveFlowState/);
  });

  it("requires a readable, clearable store when completing a login", async () => {
    const auth = createAuthentikClient(VALID);
    await assert.rejects(
      () => auth.completeLogin("https://records.example.com/auth/callback?code=x", "flow-1", {}),
      /loadFlowState/,
    );
  });

  it("rejects a callback with no sign-in in progress", async () => {
    // The replay and forged-callback case: no server-side state, no login.
    const auth = createAuthentikClient(VALID);
    const store = createEphemeralStore();

    await assert.rejects(
      () => auth.completeLogin(
        "https://records.example.com/auth/callback?code=x&state=y",
        "flow-1",
        store,
      ),
      /No sign-in in progress/,
    );
  });
});
