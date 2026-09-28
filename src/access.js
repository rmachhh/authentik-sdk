// The access decision: may this person use this application?
//
// One group per application is the whole model. If the app's group is in the
// user's group list, they may use it. Nothing else is required — no roles, no
// mapping table, no database.
//
import { accessConfigFromEnv } from "./config.js";

// Deliberately pure so it can be unit-tested and reused by any system written
// in JavaScript, without a framework, a database, or a session.
//
// Settings may be passed explicitly or supplied by the environment, so a
// deployment can configure the same way whatever the runtime. An explicit
// option always wins.

/**
 * Pull the group list out of OIDC claims, whatever shape the provider used.
 *
 * authentik reports every group a user belongs to and never filters by name.
 * Providers vary in how they deliver it, so accept the common shapes rather
 * than refusing a login over a formatting difference.
 *
 * @param {object} claims  verified ID token claims (or UserInfo)
 * @returns {string[]} group names, trimmed and de-duplicated
 */
export function extractGroups(claims) {
  if (!claims || typeof claims !== "object") {
    return [];
  }

  const raw = claims.groups ?? claims.group ?? [];
  const list = Array.isArray(raw) ? raw : [raw];

  const seen = new Set();
  for (const entry of list) {
    if (typeof entry !== "string") {
      continue;
    }
    const name = entry.trim();
    if (name) {
      seen.add(name);
    }
  }
  return [...seen];
}

/**
 * Does the user belong to the group that guards this application?
 *
 * @param {string[]} groups   from extractGroups()
 * @param {string|string[]} requiredGroup  the app's group, or several (any of)
 * @returns {boolean}
 */
export function isMemberOfAppGroup(groups, requiredGroup) {
  const required = (Array.isArray(requiredGroup) ? requiredGroup : [requiredGroup])
    .filter((name) => typeof name === "string" && name.trim())
    .map((name) => name.trim());

  if (required.length === 0) {
    // No group configured means the application has not declared who may use
    // it. Deny rather than quietly letting everyone in — an unconfigured guard
    // should fail closed.
    return false;
  }

  const present = new Set(groups ?? []);
  return required.some((name) => present.has(name));
}

/**
 * Build the access check for one application.
 *
 * @param {object} policy
 * @param {string|string[]} policy.appGroup  the group that grants access
 * @param {(claims: object) => object} [policy.mapRoles]
 *        optional: turn groups into this application's own roles
 * @returns {{ check: Function, groupsFrom: Function, rolesFrom: Function }}
 */
export function defineAccessPolicy({ appGroup, appRole, mapRoles, env } = {}) {
  // Fall back to the environment for anything not passed explicitly.
  const fromEnv = accessConfigFromEnv(env);
  appGroup = appGroup ?? fromEnv.appGroup;
  appRole = appRole ?? fromEnv.appRole;

  if (!appGroup || (Array.isArray(appGroup) && appGroup.length === 0)) {
    throw new Error(
      "defineAccessPolicy requires appGroup — the authentik group that grants access. "
      + "Pass it directly or set AUTHENTIK_APP_GROUP.",
    );
  }

  return {
    /** The group(s) this application is guarded by. */
    appGroup,

    /**
     * The application's own role, when it uses only one. Reported rather
     * than assigned: roles belong to the application, never to authentik.
     * Set with AUTHENTIK_APP_ROLE.
     */
    appRole: appRole ?? null,

    /** Groups named in the claims, unfiltered. */
    groupsFrom(claims) {
      return extractGroups(claims);
    },

    /**
     * Decide access from claims alone.
     * @returns {{ allowed: boolean, groups: string[], roles: string[] }}
     */
    check(claims) {
      const groups = extractGroups(claims);
      const allowed = isMemberOfAppGroup(groups, appGroup);
      const roles = typeof mapRoles === "function" && allowed
        ? (mapRoles(groups) ?? [])
        : (allowed && appRole ? [appRole] : []);
      return { allowed, groups, roles };
    },

    /** Optional role mapping, applied only when access was granted. */
    rolesFrom(claimsOrGroups) {
      if (typeof mapRoles !== "function") {
        return [];
      }
      const groups = Array.isArray(claimsOrGroups)
        ? claimsOrGroups
        : extractGroups(claimsOrGroups);
      return mapRoles(groups) ?? [];
    },
  };
}
