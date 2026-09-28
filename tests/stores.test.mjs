import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createEphemeralStore,
  createMemoryStore,
  createSessionStore,
} from "../src/stores.js";

describe("createMemoryStore", () => {
  it("saves, loads and clears under the same key", async () => {
    const store = createMemoryStore(new Map(), "flow");
    assert.equal(await store.loadFlowState("s1"), null);

    await store.saveFlowState("s1", { codeVerifier: "v", state: "s", nonce: "n" });
    assert.deepEqual(await store.loadFlowState("s1"),
      { codeVerifier: "v", state: "s", nonce: "n" });

    await store.clearFlowState("s1");
    assert.equal(await store.loadFlowState("s1"), null);
  });

  it("keeps separate logins apart when given separate holders", async () => {
    const a = createMemoryStore(new Map(), "flow");
    const b = createMemoryStore(new Map(), "flow");
    await a.saveFlowState("x", { state: "from-a" });
    await b.saveFlowState("x", { state: "from-b" });
    assert.equal((await a.loadFlowState("x")).state, "from-a");
    assert.equal((await b.loadFlowState("x")).state, "from-b");
  });
});

describe("createSessionStore", () => {
  it("stores the flow state on the session and removes it on clear", async () => {
    const session = {};
    const store = createSessionStore(session);

    await store.saveFlowState("s1", { state: "abc" });
    assert.deepEqual(session.authentikFlow, { state: "abc" });
    assert.deepEqual(await store.loadFlowState("s1"), { state: "abc" });

    await store.clearFlowState("s1");
    assert.equal("authentikFlow" in session, false);
    assert.equal(await store.loadFlowState("s1"), null);
  });

  it("uses a custom key when given one", async () => {
    const session = {};
    const store = createSessionStore(session, "oidc");
    await store.saveFlowState("s1", { state: "abc" });
    assert.deepEqual(session.oidc, { state: "abc" });
  });

  it("refuses to be constructed without a session", () => {
    assert.throws(() => createSessionStore(undefined), /requires the request's session/);
  });
});

describe("createEphemeralStore", () => {
  it("behaves like a store while entries are alive", async () => {
    const store = createEphemeralStore(1000);
    await store.saveFlowState("s1", { state: "abc" });
    assert.equal(store.size(), 1);
    assert.deepEqual(await store.loadFlowState("s1"), { state: "abc", expiresAt: (await store.loadFlowState("s1")).expiresAt });
    await store.clearFlowState("s1");
    assert.equal(store.size(), 0);
  });

  it("expires an abandoned login instead of holding it forever", async () => {
    // A negative TTL makes the entry expire immediately, standing in for a
    // user who never came back from the provider.
    const store = createEphemeralStore(-1);
    await store.saveFlowState("s1", { state: "abc" });

    assert.equal(await store.loadFlowState("s1"), null);
    // The dead entry is dropped on read rather than accumulating.
    assert.equal(store.size(), 0);
  });

  it("returns null for an unknown flow id", async () => {
    const store = createEphemeralStore();
    assert.equal(await store.loadFlowState("never-seen"), null);
  });
});
