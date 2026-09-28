// Scopes live here rather than in client.js so importing them does not pull in
// the OIDC library, which is an optional peer dependency.

// `openid` is required. `email` gives the application the address it matches its
// own account on. `profile` includes group membership, which is the whole basis
// of the access decision — a custom groups scope is not needed.
export const DEFAULT_SCOPES = "openid email profile";
