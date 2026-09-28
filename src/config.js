// Configuration from the environment.
//
// A Laravel application reads its settings from config; a Node application had
// to pass them to defineAccessPolicy by hand. This closes that gap, so the same
// deployment can be configured the same way whatever the runtime.
//
// Precedence: an explicit option always wins over the environment. A caller who
// passes appGroup means it, and silently overriding them with an environment
// variable would be surprising.

export const ENV_KEYS = {
  appGroup: "AUTHENTIK_APP_GROUP",
  appRole: "AUTHENTIK_APP_ROLE",
  issuer: "AUTHENTIK_ISSUER",
  clientId: "AUTHENTIK_CLIENT_ID",
  clientSecret: "AUTHENTIK_CLIENT_SECRET",
  redirectUri: "AUTHENTIK_REDIRECT_URI",
};

const isBlank = (value) => value === undefined || value === null || String(value).trim() === "";

/**
 * Read the access settings from the environment.
 *
 * @param {object} [env]  defaults to process.env, so tests can pass a plain object
 * @returns {{ appGroup?: string, appRole?: string }} only the keys that are set
 *          and non-empty, so an explicit default is never overwritten by a blank
 *          environment variable.
 */
export function accessConfigFromEnv(env = process.env) {
  const config = {};

  for (const [name, key] of [["appGroup", ENV_KEYS.appGroup], ["appRole", ENV_KEYS.appRole]]) {
    const value = env?.[key];
    if (!isBlank(value)) {
      config[name] = String(value).trim();
    }
  }

  return config;
}

/**
 * The connection settings for createAuthentikClient, from the environment.
 *
 * @param {object} [env]
 * @param {object} [overrides]  merged last, so explicit values win
 */
export function connectionConfigFromEnv(env = process.env, overrides = {}) {
  const config = {};

  for (const name of ["issuer", "clientId", "clientSecret", "redirectUri"]) {
    const value = env?.[ENV_KEYS[name]];
    if (!isBlank(value)) {
      config[name] = String(value).trim();
    }
  }

  return { ...config, ...overrides };
}
