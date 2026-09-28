// The OIDC half of the SDK: sign-in against authentik, in any framework.
//
// Storage-agnostic by design. A web framework has a session; a CLI or a test has
// something else. Rather than guess, the caller supplies two small functions
// that persist the transient flow state (PKCE verifier, state, nonce) between
// the redirect and the callback:
//
//   saveFlowState(id, state)   ->  persist, associated with this browser
//   loadFlowState(id)          ->  read it back
//   clearFlowState(id)         ->  remove it
//
// The `id` is whatever ties the two requests together — a session id, a cookie,
// an opaque key you set yourself.

import * as client from "openid-client";

import { DEFAULT_SCOPES } from "./scopes.js";

/**
 * Resolve the provider's configuration once and reuse it.
 *
 * Discovery is cached for the life of the process: the metadata at
 * /.well-known/openid-configuration does not change between requests, and
 * re-fetching it on every login would add a network round trip to the one
 * operation users notice.
 */
function createConfigCache({ issuer, clientId, clientSecret, allowInsecure }) {
  let cached;

  return async function getConfig() {
    if (!cached) {
      const url = new URL(issuer);
      // Fail before any network call: a misconfigured production issuer should
      // not be discovered over plain HTTP even once.
      if (url.protocol === "http:" && !allowInsecure) {
        throw new Error(
          `Refusing plain-HTTP issuer ${issuer}. Pass allowInsecure: true only for local development.`,
        );
      }
      const options = url.protocol === "http:"
        ? { execute: [client.allowInsecureRequests] }
        : undefined;
      cached = await client.discovery(url, clientId, clientSecret, undefined, options);
    }
    return cached;
  };
}

function requireOption(value, name) {
  if (!value || typeof value !== "string") {
    throw new Error(`createAuthentikClient requires ${name}`);
  }
  return value;
}

/**
 * Create a client bound to one authentik application.
 *
 * One application per system is the intended model: each gets its own client
 * credentials, so one leaked secret or one decommissioned system never affects
 * the others.
 *
 * @param {object} options
 * @param {string} options.issuer        e.g. https://id.example.com/application/o/records/
 * @param {string} options.clientId
 * @param {string} options.clientSecret
 * @param {string} options.redirectUri   must match authentik exactly
 * @param {string} [options.scopes]      defaults to "openid email profile"
 * @param {boolean} [options.allowInsecure]  permit an http:// issuer (local dev)
 * @param {string|string[]} [options.appGroup]  group that grants access
 * @param {(groups: string[]) => string[]} [options.mapRoles]  optional
 * @returns {object} the client
 */
export function createAuthentikClient(options = {}) {
  const issuer = requireOption(options.issuer, "issuer");
  const clientId = requireOption(options.clientId, "clientId");
  const clientSecret = requireOption(options.clientSecret, "clientSecret");
  const redirectUri = requireOption(options.redirectUri, "redirectUri");
  const scopes = options.scopes ?? DEFAULT_SCOPES;

  const getConfig = createConfigCache({
    issuer,
    clientId,
    clientSecret,
    allowInsecure: options.allowInsecure,
  });

  return {
    issuer,
    clientId,
    redirectUri,
    scopes,

    /**
     * Start a sign-in.
     *
     * @param {string} flowId  ties this request to the callback
     * @param {{ saveFlowState: Function }} store
     * @returns {Promise<string>} the URL to redirect the browser to
     */
    async authorizationUrl(flowId, store) {
      if (!flowId) {
        throw new Error("authorizationUrl requires a flowId to key the stored state");
      }
      if (!store?.saveFlowState) {
        throw new Error("authorizationUrl requires a store with saveFlowState()");
      }

      const config = await getConfig();
      const codeVerifier = client.randomPKCECodeVerifier();
      const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
      const state = client.randomState();
      const nonce = client.randomNonce();

      const url = client.buildAuthorizationUrl(config, {
        redirect_uri: redirectUri,
        scope: scopes,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state,
        nonce,
      });

      await store.saveFlowState(flowId, { codeVerifier, state, nonce });
      return url.href;
    },

    /**
     * Finish a sign-in.
     *
     * Validates state, nonce and PKCE, then returns the verified claims. The
     * flow state is cleared whatever happens, so a replayed callback finds
     * nothing and is rejected.
     *
     * @param {string} callbackUrl  the full URL the provider redirected to
     * @param {string} flowId
     * @param {{ loadFlowState: Function, clearFlowState: Function }} store
     * @returns {Promise<object>} verified claims
     */
    async completeLogin(callbackUrl, flowId, store) {
      if (!store?.loadFlowState || !store?.clearFlowState) {
        throw new Error(
          "completeLogin requires a store with loadFlowState() and clearFlowState()",
        );
      }

      const pending = await store.loadFlowState(flowId);
      if (!pending) {
        throw new Error(
          "No sign-in in progress for this session. It may have expired, or the callback did not come from this browser.",
        );
      }

      // Clear first: a login attempt is single-use, so a failure must not leave
      // reusable state behind.
      await store.clearFlowState(flowId);

      const config = await getConfig();
      const tokens = await client.authorizationCodeGrant(config, new URL(callbackUrl), {
        pkceCodeVerifier: pending.codeVerifier,
        expectedState: pending.state,
        expectedNonce: pending.nonce,
      });
      return tokens.claims();
    },
  };
}

