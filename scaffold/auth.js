// authentik auth module — copy this file, change nothing but the paths.
//
// Generated shape matches SETUP.md step 4. Both exports are used by the two
// routes in step 5.

import {
  createSessionStore,
  defineAccessPolicy,
  loadAuthentikClient,
} from "authentik-sdk";

const { createAuthentikClient } = await loadAuthentikClient();

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    // Fail loudly at startup rather than at the first login attempt, so a
    // missing setting is found by whoever deploys rather than by a user.
    throw new Error(`${name} environment variable is required`);
  }
  return value;
}

const issuer = requireEnv("AUTHENTIK_ISSUER");

export const auth = createAuthentikClient({
  issuer,
  clientId: requireEnv("AUTHENTIK_CLIENT_ID"),
  clientSecret: requireEnv("AUTHENTIK_CLIENT_SECRET"),
  redirectUri: requireEnv("AUTHENTIK_REDIRECT_URI"),
  // Local authentik serves plain HTTP. Any real deployment is https://, and must
  // not be allowed to fall back.
  allowInsecure: issuer.startsWith("http://"),
});

// One group per application: this is the whole access rule.
export const access = defineAccessPolicy({ appGroup: requireEnv("APP_GROUP") });

/**
 * Start a sign-in. Returns the URL to redirect the browser to.
 *
 * @param {object} session  the request's server-side session
 * @param {string} flowId   ties this request to the callback
 */
export function signInUrl(session, flowId) {
  return auth.authorizationUrl(flowId, createSessionStore(session));
}

/**
 * Finish a sign-in.
 *
 * @returns {Promise<{allowed: boolean, groups: string[], claims: object}>}
 */
export async function completeSignIn(callbackUrl, session, flowId, store = null) {
  const sessionStore = store ?? createSessionStore(session);
  const claims = await auth.completeLogin(callbackUrl, flowId, sessionStore);
  const { allowed, groups } = access.check(claims);

  return { allowed, groups, claims };
}
