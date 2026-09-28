// Flow-state stores.
//
// The client needs to remember three short-lived values (PKCE verifier, state,
// nonce) between the redirect and the callback. How you persist them is up to
// your framework; these cover the two common cases.
//
// Whatever you use, the values must be held **server-side** and never sent to
// the browser in a way JavaScript can read. They are what prove the callback
// belongs to a login this server started.

/**
 * A store backed by any Map-like object you already have: a session, a request
 * context, a cache. Values live in memory for the lifetime of that object.
 *
 * @param {object} [holder]  Map-like with get/set/delete, or a plain object
 * @param {string} [key]     property name to nest the state under
 */
export function createMemoryStore(holder = new Map(), key = "__authentikFlow") {
  const isMap = typeof holder.get === "function" && typeof holder.set === "function";

  const read = () => (isMap ? holder.get(key) : holder[key]);
  const write = (value) => {
    if (isMap) {
      holder.set(key, value);
    } else {
      holder[key] = value;
    }
  };
  const remove = () => {
    if (isMap) {
      holder.delete(key);
    } else {
      delete holder[key];
    }
  };

  return {
    async saveFlowState(_flowId, state) {
      write(state);
    },
    async loadFlowState(_flowId) {
      return read() ?? null;
    },
    async clearFlowState(_flowId) {
      remove();
    },
  };
}

/**
 * A store backed by a session object that is serialised per request, such as
 * Express's `req.session`. Survives across the redirect because the framework
 * persists it.
 *
 * @param {object} session  the request's session object
 * @param {string} [key]
 */
export function createSessionStore(session, key = "authentikFlow") {
  if (!session || typeof session !== "object") {
    throw new Error("createSessionStore requires the request's session object");
  }

  return {
    async saveFlowState(_flowId, state) {
      session[key] = state;
    },
    async loadFlowState(_flowId) {
      return session[key] ?? null;
    },
    async clearFlowState(_flowId) {
      delete session[key];
    },
  };
}

/**
 * A store with an explicit lifetime, for tests and short-lived process runs.
 * Entries expire so a long-running process cannot accumulate abandoned logins.
 *
 * @param {number} [ttlMs]  default 10 minutes, matching typical callback delays
 */
export function createEphemeralStore(ttlMs = 10 * 60 * 1000) {
  const entries = new Map();

  const alive = (entry) => entry && entry.expiresAt > Date.now();

  return {
    async saveFlowState(flowId, state) {
      entries.set(flowId, { ...state, expiresAt: Date.now() + ttlMs });
    },
    async loadFlowState(flowId) {
      const entry = entries.get(flowId);
      if (!alive(entry)) {
        entries.delete(flowId);
        return null;
      }
      return entry;
    },
    async clearFlowState(flowId) {
      entries.delete(flowId);
    },
    /** Test helper: how many attempts are outstanding. */
    size() {
      return entries.size;
    },
  };
}
