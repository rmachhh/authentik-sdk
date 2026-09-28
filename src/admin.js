// Import users into authentik.
//
// Deliberately one-directional and repeatable. The application stays the source
// of truth for who exists; this reconciles authentik with it rather than
// mirroring it back:
//
//   * a user absent from authentik is created
//   * a user already present is left alone but added to the group when missing
//   * membership is checked per group, so a re-run is cheap and safe
//
// It never deletes anyone. Removing a user from a shared identity provider
// affects every connected system, so that stays a deliberate act.
//
// No password is set. This establishes who exists, not how they sign in.
//
// Requires an API token belonging to a service account, which is a far more
// powerful credential than the sign-in client secret. It is supplied separately
// and never used on a sign-in path.

import { accessConfigFromEnv } from "./config.js";

const DEFAULT_TIMEOUT = 15000;

/** A failure worth reporting per user rather than aborting the whole run. */
export class AuthentikImportError extends Error {}

function isBlank(value) {
  return value === undefined || value === null || String(value).trim() === "";
}

/**
 * A username derived from the address.
 *
 * Readable for the common case — `ralph@rhet-corp.com` becomes `ralph` — and
 * unique when it has to be. A local part is not unique: `john@a.example` and
 * `john@b.example` both reduce to `john`, and two people at different schools
 * routinely share a first name. On a collision the domain is appended, so the
 * second address still gets a username rather than failing with "this field
 * must be unique".
 *
 * The suffix comes from the address, not a random value, so the same input
 * always produces the same username and a re-run does not create a second
 * account.
 */
function usernameFor(email) {
  const local = email.includes("@") ? email.slice(0, email.indexOf("@")) : email;
  return local.toLowerCase().replace(/[^a-z0-9._-]/g, "-");
}

/** A slug for a domain: alphanumeric only, so `@b.example` becomes `bexample`. */
function domainSlug(email) {
  const at = email.indexOf("@");
  if (at === -1) return "";

  return email.slice(at + 1).toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Usernames to try, in order of preference. */
function usernameAttempts(candidate) {
  const preferred = candidate.username;
  const domain = domainSlug(candidate.email);
  const qualified = domain === "" ? preferred : `${preferred}-${domain}`;

  return [...new Set([preferred, qualified, `${preferred}-${digest(candidate.email)}`])];
}

/** A short, stable digest. Crypto when available, a simple hash otherwise. */
function digest(value) {
  try {
    // eslint-disable-next-line no-undef
    const { createHash } = require("node:crypto");
    return createHash("sha256").update(value).digest("hex").slice(0, 8);
  } catch {
    let hash = 0;
    for (const char of value) {
      hash = (hash * 31 + char.charCodeAt(0)) % 0xffffffff;
    }
    return hash.toString(16).padStart(8, "0");
  }
}

/** Does authentik report the username, rather than something else, as taken? */
function usernameIsTaken(body) {
  const message = body?.username;
  if (!message) return false;
  const text = Array.isArray(message) ? message.join(" ") : String(message);

  return /unique|exists/i.test(text);
}

/**
 * Drop entries without a usable address, and de-duplicate.
 *
 * A duplicate would otherwise read as "already present" on the second pass,
 * which looks like a reconciliation when it is really a bad input.
 */
function normalise(users) {
  const seen = new Set();
  const out = [];

  for (const user of users ?? []) {
    const email = String(user?.email ?? "").trim();
    if (!email || !email.includes("@") || seen.has(email)) {
      continue;
    }
    seen.add(email);

    const name = String(user?.name ?? "").trim();
    const username = String(user?.username ?? "").trim();

    out.push({
      email,
      name: name || email,
      username: username || usernameFor(email),
    });
  }

  return out;
}

/** authentik reports field errors as {field: [messages]}. Surface the first. */
function summarise(body) {
  if (!body || typeof body !== "object") {
    return "";
  }
  for (const [field, messages] of Object.entries(body)) {
    if (Array.isArray(messages) && messages.length) {
      return `${field}: ${messages.join(" ")}`;
    }
    if (typeof messages === "string") {
      return `${field}: ${messages}`;
    }
  }
  return "";
}

/**
 * Create an admin client for importing users.
 *
 * @param {object} options
 * @param {string} options.baseUrl    authentik's root, e.g. https://id.example.com
 * @param {string} options.token      a service account's API token
 * @param {string} [options.appGroup] the group every imported user joins.
 *        Defaults to AUTHENTIK_APP_GROUP.
 * @param {number} [options.timeout]
 * @param {Function} [options.fetch]  injected for tests
 */
export function createAuthentikAdminClient(options = {}) {
  const baseUrl = String(options.baseUrl ?? "").replace(/\/+$/, "");
  const token = String(options.token ?? "");
  const appGroup = options.appGroup ?? accessConfigFromEnv(options.env).appGroup;
  const timeout = options.timeout ?? DEFAULT_TIMEOUT;
  const doFetch = options.fetch ?? globalThis.fetch;

  if (!baseUrl) {
    throw new Error("createAuthentikAdminClient requires baseUrl");
  }
  if (isBlank(token)) {
    throw new Error(
      "createAuthentikAdminClient requires an API token. The sign-in client secret is not enough.",
    );
  }
  if (isBlank(appGroup)) {
    throw new Error(
      "createAuthentikAdminClient requires the group to add users to. " +
      "Pass appGroup or set AUTHENTIK_APP_GROUP.",
    );
  }
  if (typeof doFetch !== "function") {
    throw new Error("No fetch implementation available. Pass options.fetch.");
  }

  async function request(method, path, { query, body } = {}) {
    const url = new URL(baseUrl + path);
    for (const [key, value] of Object.entries(query ?? {})) {
      url.searchParams.set(key, String(value));
    }

    const response = await doFetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout?.(timeout),
    });

    let parsed = null;
    const text = await response.text();
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }

    return { status: response.status, body: parsed };
  }

  async function findUserByEmail(email) {
    const { status, body } = await request("GET", "/api/v3/core/users/", {
      query: { email, page_size: 1 },
    });

    if (status !== 200) {
      throw new AuthentikImportError(`Could not search authentik for ${email}: HTTP ${status}`);
    }
    return body?.results?.[0] ?? null;
  }

  async function findOrCreateGroup(name) {
    const { status, body } = await request("GET", "/api/v3/core/groups/", {
      query: { name, page_size: 20 },
    });

    if (status !== 200) {
      throw new AuthentikImportError(`Could not look up group ${name}: HTTP ${status}`);
    }

    const found = (body?.results ?? []).find((group) => group.name === name);
    if (found) {
      return found;
    }

    const created = await request("POST", "/api/v3/core/groups/", {
      body: { name, is_superuser: false },
    });

    if (created.status !== 200 && created.status !== 201) {
      throw new AuthentikImportError(
        `Could not create group ${name}: HTTP ${created.status} ${summarise(created.body)}`,
      );
    }
    return created.body;
  }

  /**
   * Create the user, resolving a username that is already taken.
   *
   * authentik's usernames are globally unique, and a local part is not, so the
   * name is retried with the domain appended rather than reporting the second
   * John as a failure.
   */
  async function createUser(candidate) {
    let lastError = null;

    for (const username of usernameAttempts(candidate)) {
      const { status, body } = await request("POST", "/api/v3/core/users/", {
        body: {
          username,
          email: candidate.email,
          name: candidate.name,
          is_active: true,
          path: "users",
        },
      });

      if (status === 200 || status === 201) {
        if (!body?.pk) {
          throw new AuthentikImportError(
            `authentik accepted ${candidate.email} but returned no user`,
          );
        }
        return body;
      }

      lastError = `${status} ${summarise(body)}`;

      // Only a taken username is worth retrying. Anything else — a malformed
      // address, a permissions problem — will fail again.
      if (!usernameIsTaken(body)) break;
    }

    throw new AuthentikImportError(`Could not create ${candidate.email}: HTTP ${lastError}`);
  }

  /**
   * Add a user to a group when they are not already a member.
   *
   * The group payload's `users` field is a list of user primary keys, and this
   * endpoint replaces the whole list — so the current members are read and the
   * new one appended. Sending only the new member would remove everyone else.
   */
  async function addUserToGroup(group, user) {
    const members = (group.users ?? []).map(Number);
    const pk = Number(user.pk);

    if (!pk || !group.pk) {
      throw new AuthentikImportError("Cannot add a user to a group without both identifiers");
    }
    if (members.includes(pk)) {
      return false;
    }

    const { status, body } = await request("PATCH", `/api/v3/core/groups/${group.pk}/`, {
      body: { users: [...new Set([...members, pk])] },
    });

    if (status !== 200) {
      throw new AuthentikImportError(
        `Could not add user ${pk} to group ${group.pk}: HTTP ${status} ${summarise(body)}`,
      );
    }

    group.users = [...new Set([...members, pk])];
    return true;
  }

  return {
    baseUrl,
    appGroup,

    /** Is the API reachable and is the token accepted? */
    async check() {
      const { status } = await request("GET", "/api/v3/core/users/", {
        query: { page_size: 1 },
      });
      return status === 200;
    },

    /**
     * What the import would do, without doing it.
     *
     * Running this first is the point: an administrator sees exactly which
     * accounts would be created before anything is written.
     */
    async preview(users) {
      const rows = [];
      let toCreate = 0;

      for (const candidate of normalise(users)) {
        const existing = await findUserByEmail(candidate.email);
        if (existing === null) {
          toCreate += 1;
        }
        rows.push({
          email: candidate.email,
          name: candidate.name,
          group: appGroup,
          exists: existing !== null,
          action: existing === null ? "create" : "add to group",
        });
      }

      return {
        users: rows,
        summary: {
          total: rows.length,
          create: toCreate,
          "already present": rows.length - toCreate,
        },
      };
    },

    /**
     * Perform the import. Safe to run repeatedly.
     */
    async import(users) {
      const group = await findOrCreateGroup(appGroup);

      const results = [];
      let created = 0;
      let existing = 0;
      let added = 0;
      let failed = 0;

      for (const candidate of normalise(users)) {
        try {
          let user = await findUserByEmail(candidate.email);
          let wasCreated = false;

          if (user === null) {
            user = await createUser(candidate);
            wasCreated = true;
            created += 1;
          } else {
            existing += 1;
          }

          if (await addUserToGroup(group, user)) {
            added += 1;
          }

          results.push({
            email: candidate.email,
            name: candidate.name,
            status: wasCreated ? "created" : "existing",
            group: appGroup,
            error: null,
          });
        } catch (error) {
          failed += 1;
          results.push({
            email: candidate.email,
            name: candidate.name,
            status: "failed",
            group: appGroup,
            error: error.message,
          });
        }
      }

      return {
        results,
        summary: {
          total: results.length,
          created,
          "already present": existing,
          "group additions": added,
          failed,
        },
      };
    },
  };
}
