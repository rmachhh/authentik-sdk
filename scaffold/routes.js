// authentik sign-in routes — copy this file and mount the router.
//
// Generated shape matches SETUP.md step 5. The SDK calls must stay exactly as
// written; the surrounding framework calls can change.

import express from "express";

import { completeSignIn, signInUrl } from "./auth.js";

export const authRouter = express.Router();

// Where to send the browser after sign-in completes or fails. Leave this on the
// application's own origin.
const AFTER_LOGIN = process.env.AFTER_LOGIN_PATH ?? "/";

authRouter.get("/auth/login", async (req, res) => {
  try {
    const url = await signInUrl(req.session, req.sessionID);
    res.redirect(url);
  } catch (error) {
    // A configuration mistake lands here — the issuer, the client credentials,
    // or a redirect URI the provider will reject. Log it: this is a bug on our
    // side, not a user error.
    console.error("[auth] cannot start sign-in:", error.message);
    res.redirect(`${AFTER_LOGIN}?error=sso_unavailable`);
  }
});

authRouter.get("/auth/callback", async (req, res) => {
  const callbackUrl = new URL(req.originalUrl, process.env.AUTHENTIK_REDIRECT_URI);

  let result;
  try {
    result = await completeSignIn(callbackUrl, req.session, req.sessionID);
  } catch (error) {
    // Covers an expired attempt, a replayed callback, a forged callback, and a
    // failed token exchange. All mean "start again", not "you are signed in".
    console.error("[auth] sign-in failed:", error.message);
    return res.redirect(`${AFTER_LOGIN}?error=sso_failed`);
  }

  if (!result.allowed) {
    // Log which groups were seen, never the token. This answers "why was I
    // denied?" without leaking a credential.
    console.warn(
      `[auth] denied ${result.claims.email}: groups=${result.groups.join(",") || "(none)"}`,
    );
    return res.redirect(`${AFTER_LOGIN}?error=no_app_access`);
  }

  // Which account this is, and what it may do, is the application's decision.
  // authentik supplied identity and group membership only.
  const user = await findUserByEmail(result.claims.email);

  if (!user) {
    // Deliberate policy: this application does not create accounts on the fly.
    // The alternative is to provision here, with an audit record. Ask first.
    console.warn(`[auth] no local account for ${result.claims.email}`);
    return res.redirect(`${AFTER_LOGIN}?error=no_account`);
  }

  req.session.userId = String(user.id);
  res.redirect(AFTER_LOGIN);
});

authRouter.get("/auth/logout", (req, res) => {
  req.session.destroy(() => res.redirect(AFTER_LOGIN));
});

// Replace with the project's own lookup. Kept here so this file runs as-is.
async function findUserByEmail(email) {
  return globalThis.__findUserByEmail ? globalThis.__findUserByEmail(email) : null;
}
