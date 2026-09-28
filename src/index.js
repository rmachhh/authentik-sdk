// authentik-sdk — single sign-on against authentik, with one group per app.
//
// The model, in one paragraph: every application has one authentik group. If
// the signed-in user is in that group, they may use the application. That is
// the whole access rule, and it needs no roles, no mapping table and no
// database. Role mapping is available when a system genuinely needs to
// distinguish levels of access, and can be ignored otherwise.
//
// Typical use:
//
//   import { createAuthentikClient, createSessionStore,
//            defineAccessPolicy } from "authentik-sdk";
//
//   const auth = createAuthentikClient({
//     issuer: process.env.AUTHENTIK_ISSUER,
//     clientId: process.env.AUTHENTIK_CLIENT_ID,
//     clientSecret: process.env.AUTHENTIK_CLIENT_SECRET,
//     redirectUri: process.env.AUTHENTIK_REDIRECT_URI,
//   });
//
//   const access = defineAccessPolicy({ appGroup: "myapp-access" });
//
//   // start
//   const url = await auth.authorizationUrl(session.id, createSessionStore(session));
//   res.redirect(url);
//
//   // callback
//   const claims = await auth.completeLogin(fullUrl, session.id, createSessionStore(session));
//   const { allowed, groups } = access.check(claims);
//   if (!allowed) return res.redirect("/login?error=no_app_access");

// Everything that does **not** need an OIDC library is exported here eagerly.
// `openid-client` is a peer dependency and is only used by the sign-in client,
// so importing it is deferred: an application that only needs the access
// decision does not have to install it.
export {
  defineAccessPolicy,
  extractGroups,
  isMemberOfAppGroup,
} from "./access.js";
export { createRoleMapper, pickPrimaryRole } from "./roles.js";
export {
  createEphemeralStore,
  createMemoryStore,
  createSessionStore,
} from "./stores.js";
export { DEFAULT_SCOPES } from "./scopes.js";
export {
  accessConfigFromEnv,
  connectionConfigFromEnv,
  ENV_KEYS,
} from "./config.js";

/**
 * Load the sign-in client.
 *
 * Deferred so `import "authentik-sdk"` never fails on a missing peer
 * dependency. Call this before creating a client:
 *
 *   import { loadAuthentikClient } from "authentik-sdk";
 *   const { createAuthentikClient } = await loadAuthentikClient();
 */
export async function loadAuthentikClient() {
  try {
    return await import("./client.js");
  } catch (error) {
    if (error?.code === "ERR_MODULE_NOT_FOUND" && /openid-client/.test(error.message)) {
      throw new Error(
        "The authentik sign-in client needs the 'openid-client' package. " +
        "Install it with: npm install openid-client",
      );
    }
    throw error;
  }
}
