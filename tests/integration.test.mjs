// Integration test against a running authentik.
//
// Skips unless credentials are supplied, so `npm test` works on a machine with
// no authentik running. To run it:
//
//   AUTHENTIK_CLIENT_SECRET=<secret> npm test
//
// Optionally override the issuer/client for a different application:
//   AUTHENTIK_ISSUER, AUTHENTIK_CLIENT_ID, AUTHENTIK_REDIRECT_URI

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createAuthentikClient } from "../src/client.js";
import { defineAccessPolicy } from "../src/access.js";

const SECRET = process.env.AUTHENTIK_CLIENT_SECRET;
const CLIENT_ID = process.env.AUTHENTIK_CLIENT_ID;

const CONFIG = {
  issuer: process.env.AUTHENTIK_ISSUER ?? "http://localhost:9000/application/o/example/",
  // No defaults for the client credentials: this repository is public, and a
  // client ID is half of a credential pair. Both must be supplied by the
  // environment if the integration tests are to run.
  clientId: CLIENT_ID,
  clientSecret: SECRET,
  redirectUri: process.env.AUTHENTIK_REDIRECT_URI
    ?? "http://localhost:4000/api/auth/authentik/callback",
  allowInsecure: true,
};

describe("against a live authentik", { skip: !SECRET || !CLIENT_ID }, () => {
  it("discovers the provider and builds a PKCE authorization URL", async () => {
    const auth = createAuthentikClient(CONFIG);

    let stored = null;
    const url = await auth.authorizationUrl("itest-1", {
      async saveFlowState(id, state) {
        assert.equal(id, "itest-1");
        stored = state;
      },
    });

    const parsed = new URL(url);
    // The URL must point at the provider's authorization endpoint, taken from
    // discovery rather than hard-coded.
    assert.match(parsed.pathname, /\/application\/o\/authorize\/?$/);

    assert.equal(parsed.searchParams.get("response_type"), "code");
    assert.equal(parsed.searchParams.get("client_id"), CONFIG.clientId);
    assert.equal(parsed.searchParams.get("redirect_uri"), CONFIG.redirectUri);
    assert.equal(parsed.searchParams.get("code_challenge_method"), "S256");
    assert.ok(parsed.searchParams.get("code_challenge"), "PKCE challenge missing");
    assert.ok(parsed.searchParams.get("state"), "state missing");
    assert.ok(parsed.searchParams.get("nonce"), "nonce missing");
    assert.match(parsed.searchParams.get("scope"), /openid/);

    // The three secrets that prove the callback belongs to this login must be
    // handed to the store, and must not appear in the URL.
    assert.ok(stored?.codeVerifier, "code verifier not persisted");
    assert.ok(stored?.state, "state not persisted");
    assert.ok(stored?.nonce, "nonce not persisted");
    assert.equal(parsed.searchParams.get("code_verifier"), null);
  });

  it("refuses to complete a login that was never started", async () => {
    const auth = createAuthentikClient(CONFIG);
    await assert.rejects(
      () => auth.completeLogin(
        `${CONFIG.redirectUri}?code=made-up&state=made-up`,
        "never-started",
        {
          async loadFlowState() { return null; },
          async clearFlowState() {},
        },
      ),
      /No sign-in in progress/,
    );
  });

  it("decides access from group membership alone", () => {
    const policy = defineAccessPolicy({ appGroup: "myapp-access" });
    assert.equal(policy.check({ groups: ["myapp-access"] }).allowed, true);
    assert.equal(policy.check({ groups: ["unrelated-group"] }).allowed, false);
  });
});
