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
//
// Failover: pass several instances and the first reachable one is used. The
// instance that issued a sign-in is recorded with the flow state, because an
// authorization code can only be exchanged by the instance that issued it.
// Falling back to a second instance on the callback would fail the exchange.

import * as client from "openid-client";

import { DEFAULT_SCOPES } from "./scopes.js";

/**
 * Resolve a provider's configuration once and reuse it.
 *
 * Discovery is cached for the life of the process: the metadata at
 * /.well-known/openid-configuration does not change between requests, and
 * re-fetching it on every login would add a network round trip to the one
 * operation users notice.
 */
function createConfigCache(instance) {
  let cached;

  return async function getConfig() {
    if (!cached) {
      const url = new URL(instance.issuer);
      // Fail before any network call: a misconfigured production issuer should
      // not be discovered over plain HTTP even once.
      if (url.protocol === "http:" && !instance.allowInsecure) {
        throw new Error(
          `Refusing plain-HTTP issuer ${instance.issuer}. Pass allowInsecure: true only for local development.`,
        );
      }
      const options = url.protocol === "http:"
        ? { execute: [client.allowInsecureRequests] }
        : undefined;
      cached = await client.discovery(
        url, instance.clientId, instance.clientSecret, undefined, options,
      );
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
 * Accept either a single instance in the top-level options, or an `instances`
 * array. One instance is the common case and should not need an array.
 */
function normaliseInstances(options) {
  const isArrayForm = Array.isArray(options.instances);
  const raw = isArrayForm ? options.instances : [options];

  if (isArrayForm && raw.length === 0) {
    throw new Error("createAuthentikClient requires at least one instance");
  }
  if (!isArrayForm && !options.issuer) {
    // Keep the single-instance errors plain: `requires issuer` rather than
    // `requires instances[0].issuer`, which would be noise for the common case.
    throw new Error("createAuthentikClient requires issuer");
  }

  return raw.map((instance, index) => {
    const at = (name) => (isArrayForm ? `instances[${index}].${name}` : name);
    const label = instance.label ?? instance.issuer ?? `instance-${index}`;
    return {
      label,
      issuer: requireOption(instance.issuer, at("issuer")),
      clientId: requireOption(instance.clientId, at("clientId")),
      clientSecret: requireOption(instance.clientSecret, at("clientSecret")),
      redirectUri: requireOption(
        instance.redirectUri ?? options.redirectUri, at("redirectUri"),
      ),
      scopes: instance.scopes ?? options.scopes ?? DEFAULT_SCOPES,
      allowInsecure: instance.allowInsecure
        ?? options.allowInsecure
        ?? false,
    };
  });
}

function isUnreachable(error) {
  // A discovery failure means this instance could not be used for this attempt.
  // Anything else — a bad client secret, a malformed issuer — is a
  // configuration error and must not be hidden by silently trying the next
  // instance, or a typo would look like an outage.
  const message = String(error?.message ?? "");
  return /ECONNREFUSED|ENOTFOUND|ETIMEDOUT|EAI_AGAIN|fetch failed|socket hang up|network/i
    .test(message);
}

/**
 * Create a client bound to one authentik application.
 *
 * One application per system is the intended model: each gets its own client
 * credentials, so one leaked secret or one decommissioned system never affects
 * the others.
 *
 * @param {object} options
 * @param {string} [options.issuer]        single-instance form
 * @param {string} [options.clientId]
 * @param {string} [options.clientSecret]
 * @param {string} [options.redirectUri]   must match authentik exactly
 * @param {string} [options.scopes]        defaults to "openid email profile"
 * @param {boolean} [options.allowInsecure]  permit an http:// issuer (local dev)
 * @param {Array}  [options.instances]     several instances; the first reachable
 *        one is used. Each entry takes issuer/clientId/clientSecret and may
 *        override redirectUri, scopes and allowInsecure, plus an optional label.
 * @param {(error: Error, instance: object) => void} [options.onFailover]
 *        called when an instance is skipped, before trying the next
 * @returns {object} the client
 */
export function createAuthentikClient(options = {}) {
  const instances = normaliseInstances(options);
  const onFailover = options.onFailover;

  const caches = new Map(
    instances.map((instance) => [instance.label, createConfigCache(instance)]),
  );

  return {
    issuer: instances[0].issuer,
    clientId: instances[0].clientId,
    redirectUri: instances[0].redirectUri,
    scopes: instances[0].scopes,
    /** Every configured instance, in the order they will be tried. */
    instances: instances.map(({ label, issuer }) => ({ label, issuer })),

    /**
     * Start a sign-in, using the first reachable instance.
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

      let lastError;
      for (const instance of instances) {
        try {
          const config = await caches.get(instance.label)();

          const codeVerifier = client.randomPKCECodeVerifier();
          const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
          const state = client.randomState();
          const nonce = client.randomNonce();

          const url = client.buildAuthorizationUrl(config, {
            redirect_uri: instance.redirectUri,
            scope: instance.scopes,
            code_challenge: codeChallenge,
            code_challenge_method: "S256",
            state,
            nonce,
          });

          // The instance label is stored with the flow state so the callback
          // exchanges the code against the instance that issued it. Without
          // this, failing over between start and callback would break the
          // exchange.
          await store.saveFlowState(flowId, {
            codeVerifier, state, nonce, instance: instance.label,
          });
          return url.href;
        } catch (error) {
          lastError = error;
          if (!isUnreachable(error)) {
            throw error;
          }
          onFailover?.(error, instance);
        }
      }

      throw new Error(
        `No authentik instance is reachable. Tried: ${instances.map((i) => i.label).join(", ")}. `
        + `Last error: ${lastError?.message}`,
      );
    },

    /**
     * Finish a sign-in.
     *
     * Validates state, nonce and PKCE against the instance recorded when the
     * sign-in started, then returns the verified claims. The flow state is
     * cleared whatever happens, so a replayed callback finds nothing.
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

      // Complete against the instance that started the sign-in. A code is only
      // exchangeable by its issuer, so there is deliberately no failover here.
      const instance = instances.find((i) => i.label === pending.instance) ?? instances[0];
      const config = await caches.get(instance.label)();

      const tokens = await client.authorizationCodeGrant(config, new URL(callbackUrl), {
        pkceCodeVerifier: pending.codeVerifier,
        expectedState: pending.state,
        expectedNonce: pending.nonce,
      });
      return tokens.claims();
    },
  };
}

export { DEFAULT_SCOPES };
