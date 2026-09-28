// Optional role mapping.
//
// Most applications only need "is this person in our group?" — use access.js and
// ignore this file. Reach for it when one group is not enough: when a system
// needs to tell administrators from ordinary users while both belong to the app.
//
// Kept pure and separate from access.js so a system that does not map roles
// carries none of this complexity, and so a system that does can test it
// without a database.

/**
 * Turn group names into this application's own role names.
 *
 * A group grants a role only when it is listed in the map *and* that role
 * exists in this application. Everything else is ignored — including groups
 * belonging to other systems and authentik's own internal groups — so the
 * identity provider can report every group without constraining naming.
 *
 * @param {object} options
 * @param {Record<string,string>} options.map    group name -> role name
 * @param {string[]} options.roles               roles that exist in this app
 * @param {boolean} [options.requireAppGroup]    only map when the user holds
 *        this group (or these groups); use when the map itself is not a
 *        sufficient access decision
 * @returns {(groups: string[]) => string[]} role names, in the app's own order
 */
export function createRoleMapper({ map = {}, roles = [], requireAppGroup } = {}) {
  const knownRoles = new Set(roles);
  const required = requireAppGroup === undefined
    ? null
    : (Array.isArray(requireAppGroup) ? requireAppGroup : [requireAppGroup]);

  return function rolesFromGroups(groups) {
    const list = Array.isArray(groups) ? groups : [];

    if (required && required.length > 0) {
      const present = new Set(list);
      const member = required.some((name) => present.has(name));
      if (!member) {
        // Not in the application's group at all: no roles, regardless of any
        // other group they happen to be in.
        return [];
      }
    }

    const granted = new Set();
    for (const group of list) {
      if (typeof group !== "string") {
        continue;
      }
      const role = map[group.trim()];
      if (role && knownRoles.has(role)) {
        granted.add(role);
      }
    }

    // Order by the application's own role list so precedence is explicit and
    // does not depend on the order groups arrived in.
    return roles.filter((role) => granted.has(role));
  };
}

/**
 * The single role to apply when an application allows exactly one role per user.
 * Precedence follows the application's own role list, so a later entry is
 * treated as more privileged.
 *
 * @returns {string|null} the highest-privilege matching role, or null
 */
export function pickPrimaryRole(matchedRoles, roles) {
  if (!matchedRoles || matchedRoles.length === 0) {
    return null;
  }
  const precedence = roles ?? matchedRoles;
  return [...matchedRoles].sort(
    (a, b) => precedence.indexOf(b) - precedence.indexOf(a),
  )[0];
}
