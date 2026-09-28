import assert from "node:assert/strict";
import { after, describe, it } from "node:test";
import { createServer } from "node:http";

import { createAuthentikClient } from "../src/client.js";
import { DEFAULT_SCOPES } from "../src/scopes.js";
import { createEphemeralStore, createMemoryStore } from "../src/stores.js";

const VALID = {
  issuer: "https://id.example.com/application/o/records/",
  clientId: "records",
  clientSecret: "secret",
  redirectUri: "https://records.example.com/auth/callback",
};

// Serve a valid OIDC discovery document, so an instance is genuinely reachable
// rather than merely well-formed. Failover cannot be tested against a host that
// is meant to be unreachable.
function startProvider() {
  const server = createServer((req, res) => {
    if (req.url.includes(".well-known/openid-configuration")) {
      const base = `http://127.0.0.1:${server.address().port}/application/o/records`;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        issuer: base,
        authorization_endpoint: `${base}/authorize/`,
        token_endpoint: `${base}/token/`,
        jwks_uri: `${base}/jwks/`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
      }));
      return;
    }
    res.writeHead(404).end();
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, issuer: `http://127.0.0.1:${server.address().port}/application/o/records` }));
  });
}

// A port that was bound and then released: connecting to it is refused
// immediately, which is what an unreachable instance looks like.
async function deadPort() {
  const { server, issuer } = await startProvider();
  await new Promise((r) => server.close(r));
  return issuer;
}

const providers = [];
async function provider(label) {
  const p = await startProvider();
  providers.push(p.server);
  return { ...VALID, label, issuer: p.issuer, allowInsecure: true };
}

after(() => providers.forEach((s) => s.close()));

describe("createAuthentikClient", () => {
  it("requires every connection setting", () => {
    for (const missing of ["issuer", "clientId", "clientSecret", "redirectUri"]) {
      assert.throws(
        () => createAuthentikClient({ ...VALID, [missing]: undefined }),
        new RegExp(`requires ${missing}`),
        `expected a clear error when ${missing} is missing`,
      );
    }
  });

  it("requires at least one instance", () => {
    assert.throws(
      () => createAuthentikClient({ ...VALID, instances: [] }),
      /at least one instance/,
    );
  });

  it("reports which setting is missing on a later instance", () => {
    assert.throws(
      () => createAuthentikClient({ instances: [VALID, { ...VALID, clientSecret: undefined }] }),
      /instances\[1\]\.clientSecret/,
    );
  });

  it("defaults to the scopes needed for identity and groups", () => {
    const auth = createAuthentikClient(VALID);
    assert.equal(auth.scopes, DEFAULT_SCOPES);
    assert.equal(DEFAULT_SCOPES, "openid email profile");
  });

  it("exposes the configuration it was built with", () => {
    const auth = createAuthentikClient(VALID);
    assert.equal(auth.issuer, VALID.issuer);
    assert.equal(auth.clientId, "records");
    assert.equal(auth.redirectUri, VALID.redirectUri);
    assert.equal(auth.instances.length, 1);
  });

  it("accepts a single instance written as an array", () => {
    const auth = createAuthentikClient({ instances: [VALID] });
    assert.equal(auth.issuer, VALID.issuer);
  });

  it("refuses a plain-HTTP issuer unless explicitly allowed", async () => {
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
    await assert.rejects(() => auth.authorizationUrl("", createEphemeralStore()), /requires a flowId/);
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
    const auth = createAuthentikClient(VALID);
    await assert.rejects(
      () => auth.completeLogin(
        "https://records.example.com/auth/callback?code=x&state=y", "flow-1", createEphemeralStore()),
      /No sign-in in progress/,
    );
  });
});

describe("failover between instances", () => {
  it("falls back to a reachable instance when the first is down", async () => {
    const up = await provider("backup");
    const down = { ...VALID, label: "primary", issuer: await deadPort(), allowInsecure: true };
    const skipped = [];

    const auth = createAuthentikClient({
      instances: [down, up],
      onFailover: (error, instance) => skipped.push(instance.label),
    });

    const url = await auth.authorizationUrl("flow-1", createEphemeralStore());

    assert.deepEqual(skipped, ["primary"], "the down instance should be reported once");
    assert.equal(new URL(url).origin, new URL(up.issuer).origin);
    assert.equal(new URL(url).pathname, "/application/o/records/authorize/");
  });

  it("uses the first instance when it is healthy, without falling back", async () => {
    const first = await provider("first");
    const second = await provider("second");
    const skipped = [];

    const auth = createAuthentikClient({
      instances: [first, second],
      onFailover: (e, i) => skipped.push(i.label),
    });

    const url = await auth.authorizationUrl("flow-1", createEphemeralStore());

    assert.deepEqual(skipped, [], "no failover should happen");
    assert.equal(new URL(url).origin, new URL(first.issuer).origin);
  });

  it("records which instance issued the sign-in", async () => {
    // This is what makes failover safe: a code can only be exchanged by the
    // instance that issued it, so the callback must not fall back again.
    const up = await provider("backup");
    const down = { ...VALID, label: "primary", issuer: await deadPort(), allowInsecure: true };
    const auth = createAuthentikClient({ instances: [down, up] });

    const store = createMemoryStore({}, "flow");
    await auth.authorizationUrl("flow-1", store);
    const saved = await store.loadFlowState("flow-1");

    assert.equal(saved.instance, "backup");
    assert.ok(saved.codeVerifier && saved.state && saved.nonce);
  });

  it("reports every instance when none is reachable", async () => {
    const first = await deadPort();
    const second = await deadPort();
    const auth = createAuthentikClient({
      instances: [
        { ...VALID, label: "one", issuer: first, allowInsecure: true },
        { ...VALID, label: "two", issuer: second, allowInsecure: true },
      ],
    });

    await assert.rejects(
      () => auth.authorizationUrl("flow-1", createEphemeralStore()),
      (error) => {
        assert.match(error.message, /No authentik instance is reachable/);
        assert.match(error.message, /one/);
        assert.match(error.message, /two/);
        return true;
      },
    );
  });

  it("does not hide a configuration error behind failover", async () => {
    // A plain-HTTP issuer is a mistake, not an outage. Falling through would
    // turn a typo into a silent, confusing switch to the backup.
    const up = await provider("backup");
    const auth = createAuthentikClient({
      instances: [
        { ...VALID, label: "misconfigured", issuer: "http://id.example.com/application/o/x/" },
        up,
      ],
    });

    await assert.rejects(
      () => auth.authorizationUrl("flow-1", createEphemeralStore()),
      /Refusing plain-HTTP issuer/,
    );
  });
});
