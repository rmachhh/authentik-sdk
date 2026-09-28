import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createAuthentikAdminClient, AuthentikImportError } from "../src/admin.js";

const USERS = [
  { email: "alex@example.com", name: "Alex" },
  { email: "sam@example.com", name: "Sam" },
];

/**
 * A scripted fetch: responses are matched by a substring of the URL, and every
 * call is recorded so a test can assert what was written.
 */
function fakeFetch(routes) {
  const calls = [];

  const impl = async (url, init = {}) => {
    const href = String(url);
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ method: init.method ?? "GET", url: href, body });

    const method = init.method ?? "GET";
    for (const [needle, route] of Object.entries(routes)) {
      // The key is "METHOD /path" so a broad path cannot swallow another
      // route's request, which is how the first version of this stub silently
      // intercepted the membership write.
      const [wantMethod, wantPath] = needle.includes(" ") ? needle.split(" ") : ["", needle];
      if (wantMethod && wantMethod !== method) continue;
      if (!href.includes(wantPath)) continue;
      const resolved = typeof route === "function" ? route({ url: href, method: init.method, body }) : route;
      return {
        status: resolved.status,
        text: async () => JSON.stringify(resolved.body ?? {}),
      };
    }

    return { status: 404, text: async () => JSON.stringify({ detail: `not scripted: ${href}` }) };
  };

  impl.calls = calls;
  return impl;
}

const VALID = { baseUrl: "https://id.example.com", token: "test-token", appGroup: "myapp-access" };

describe("createAuthentikAdminClient", () => {
  it("requires a base URL, a token and the group to add users to", () => {
    assert.throws(() => createAuthentikAdminClient({ ...VALID, baseUrl: "" }), /requires baseUrl/);
    assert.throws(() => createAuthentikAdminClient({ ...VALID, token: "" }), /API token/);
    assert.throws(() => createAuthentikAdminClient({ ...VALID, appGroup: "" }), /group to add users to/);
  });

  it("names the environment variable when the group is missing", () => {
    assert.throws(
      () => createAuthentikAdminClient({ baseUrl: "https://x", token: "t", env: {} }),
      /AUTHENTIK_APP_GROUP/,
    );
  });

  it("takes the group from the environment", () => {
    const client = createAuthentikAdminClient({
      baseUrl: "https://x",
      token: "t",
      env: { AUTHENTIK_APP_GROUP: "sis-access" },
      fetch: fakeFetch({}),
    });

    assert.equal(client.appGroup, "sis-access");
  });

  it("strips a trailing slash so paths do not double up", () => {
    const client = createAuthentikAdminClient({
      ...VALID,
      baseUrl: "https://id.example.com/",
      fetch: fakeFetch({}),
    });

    assert.equal(client.baseUrl, "https://id.example.com");
  });

  it("reports reachability", async () => {
    const client = createAuthentikAdminClient({
      ...VALID,
      fetch: fakeFetch({ "/api/v3/core/users/": { status: 200, body: { results: [] } } }),
    });

    assert.equal(await client.check(), true);
  });
});

describe("preview", () => {
  it("reports what would happen without writing anything", async () => {
    const fetchImpl = fakeFetch({
      "/api/v3/core/users/": { status: 200, body: { results: [] } },
    });
    const client = createAuthentikAdminClient({ ...VALID, fetch: fetchImpl });

    const result = await client.preview(USERS);

    assert.equal(result.summary.total, 2);
    assert.equal(result.summary.create, 2);
    assert.equal(result.users[0].action, "create");
    assert.equal(result.users[0].group, "myapp-access");

    // A preview must not write.
    assert.deepEqual(fetchImpl.calls.map((c) => c.method), ["GET", "GET"]);
  });

  it("marks an existing user as already present", async () => {
    const client = createAuthentikAdminClient({
      ...VALID,
      fetch: fakeFetch({ "/api/v3/core/users/": { status: 200, body: { results: [{ pk: 7 }] } } }),
    });

    const result = await client.preview([USERS[0]]);

    assert.equal(result.summary["already present"], 1);
    assert.equal(result.users[0].action, "add to group");
  });

  it("drops entries without a usable address and de-duplicates", async () => {
    const client = createAuthentikAdminClient({
      ...VALID,
      fetch: fakeFetch({ "/api/v3/core/users/": { status: 200, body: { results: [] } } }),
    });

    const result = await client.preview([
      { email: "alex@example.com" },
      { email: "alex@example.com" },
      { email: "" },
      { name: "no address" },
      { email: "not-an-address" },
    ]);

    assert.equal(result.summary.total, 1);
    assert.equal(result.users[0].email, "alex@example.com");
  });
});

describe("import", () => {
  function importFetch(existingMembers = []) {
    return fakeFetch({
      "GET /api/v3/core/groups/": {
        status: 200,
        body: { results: [{ pk: "grp-1", name: "myapp-access", users: existingMembers }] },
      },
      "/api/v3/core/users/": (call) => {
        if (call.method === "POST") {
          return { status: 201, body: { pk: 11, email: call.body.email } };
        }
        return { status: 200, body: { results: [] } };
      },
      "PATCH /api/v3/core/groups/grp-1/": { status: 200, body: { pk: "grp-1" } },
    });
  }

  it("creates a missing user and adds them to the group", async () => {
    const fetchImpl = importFetch();
    const client = createAuthentikAdminClient({ ...VALID, fetch: fetchImpl });

    const result = await client.import([USERS[0]]);

    assert.equal(result.summary.created, 1);
    assert.equal(result.summary["group additions"], 1);
    assert.equal(result.summary.failed, 0);
    assert.equal(result.results[0].status, "created");

    const patch = fetchImpl.calls.find((c) => c.method === "PATCH");
    assert.deepEqual(patch.body.users, [11], "the new user was not added");
  });

  it("keeps members already in the group", async () => {
    // The endpoint replaces the whole member list, so a naive write would drop
    // everyone already in the group.
    const fetchImpl = importFetch([3, 4]);
    const client = createAuthentikAdminClient({ ...VALID, fetch: fetchImpl });

    await client.import([USERS[0]]);

    const patch = fetchImpl.calls.find((c) => c.method === "PATCH");
    assert.deepEqual(patch.body.users, [3, 4, 11], "existing members were dropped");
  });

  it("does not write when the user is already a member", async () => {
    const fetchImpl = fakeFetch({
      "/api/v3/core/groups/": {
        status: 200,
        body: { results: [{ pk: "grp-1", name: "myapp-access", users: [11] }] },
      },
      "/api/v3/core/users/": { status: 200, body: { results: [{ pk: 11 }] } },
    });
    const client = createAuthentikAdminClient({ ...VALID, fetch: fetchImpl });

    const result = await client.import([USERS[0]]);

    assert.equal(result.summary["group additions"], 0);
    assert.equal(result.summary["already present"], 1);
    assert.equal(fetchImpl.calls.some((c) => c.method === "PATCH"), false, "a redundant write was made");
  });

  it("reports a failure per user rather than aborting the run", async () => {
    const fetchImpl = fakeFetch({
      "/api/v3/core/groups/": {
        status: 200,
        body: { results: [{ pk: "grp-1", name: "myapp-access", users: [] }] },
      },
      "/api/v3/core/users/": { status: 500, body: { detail: "boom" } },
    });
    const client = createAuthentikAdminClient({ ...VALID, fetch: fetchImpl });

    const result = await client.import(USERS);

    assert.equal(result.summary.failed, 2);
    assert.equal(result.results[0].status, "failed");
    assert.ok(result.results[0].error);
  });

  it("is repeatable: a second run changes nothing", async () => {
    const fetchImpl = importFetch();
    const client = createAuthentikAdminClient({ ...VALID, fetch: fetchImpl });

    await client.import([USERS[0]]);

    // The second run sees the user and the membership the first run created.
    const second = fakeFetch({
      "/api/v3/core/groups/": {
        status: 200,
        body: { results: [{ pk: "grp-1", name: "myapp-access", users: [11] }] },
      },
      "/api/v3/core/users/": { status: 200, body: { results: [{ pk: 11 }] } },
    });
    const result = await createAuthentikAdminClient({ ...VALID, fetch: second }).import([USERS[0]]);

    assert.equal(result.summary.created, 0);
    assert.equal(result.summary["group additions"], 0);
  });
});

describe("AuthentikImportError", () => {
  it("is a distinct type so callers can tell a per-user failure apart", () => {
    assert.ok(new AuthentikImportError("x") instanceof Error);
    assert.equal(new AuthentikImportError("x").name, "Error");
  });
});
