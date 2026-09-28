// Minimal, self-contained example: authentik sign-in with the SDK.
//
//   node examples/express-app.js     (after npm install express)
//
// It runs on http://localhost:4100 and implements exactly what an application
// must supply itself: a session, a user lookup, and its own roles. The SDK
// handles the OIDC protocol and the group check.
//
// To try it against a real authentik you must register this redirect URI on the
// provider:  http://localhost:4100/auth/callback

import express from "express";
import {
  createSessionStore,
  defineAccessPolicy,
  loadAuthentikClient,
} from "authentik-sdk";

const PORT = process.env.PORT ?? 4100;
const REDIRECT_URI = `http://localhost:${PORT}/auth/callback`;

// ---------------------------------------------------------------------------
// 1. Configure the client. One client per application: its own credentials, so
//    a leak here cannot be used against another system.
// ---------------------------------------------------------------------------
const { createAuthentikClient } = await loadAuthentikClient();

const auth = createAuthentikClient({
  issuer: process.env.AUTHENTIK_ISSUER,
  clientId: process.env.AUTHENTIK_CLIENT_ID,
  clientSecret: process.env.AUTHENTIK_CLIENT_SECRET,
  redirectUri: REDIRECT_URI,
  allowInsecure: (process.env.AUTHENTIK_ISSUER ?? "").startsWith("http://"),
});

// ---------------------------------------------------------------------------
// 2. Declare the group that grants access to THIS application.
//    Create one group per app in authentik. Nothing else is needed.
// ---------------------------------------------------------------------------
const access = defineAccessPolicy({
  appGroup: process.env.APP_GROUP ?? "myapp-access",
});

// ---------------------------------------------------------------------------
// 3. Application-owned data. The SDK never touches this.
// ---------------------------------------------------------------------------
// A real app uses its own session store. This is a development stand-in.
const sessions = new Map();

// Who exists here, and what they may do, is the application's decision — not
// authentik's. In a real app this is a database lookup and a roles table.
const USERS = {
  "alex@example.com": { id: 1, name: "Teacher", roles: ["user"] },
  "sam@example.com": { id: 2, name: "Coach", roles: ["user", "reviewer"] },
};

const app = express();

app.use((req, res, next) => {
  const id = req.headers.cookie?.match(/sid=([^;]+)/)?.[1];
  if (id && !sessions.has(id)) sessions.set(id, {});
  req.sid = id;
  req.session = id ? sessions.get(id) : {};
  next();
});

// ---------------------------------------------------------------------------
// 4. Start sign-in.
// ---------------------------------------------------------------------------
app.get("/auth/login", async (req, res) => {
  if (!req.sid) {
    req.sid = crypto.randomUUID();
    sessions.set(req.sid, {});
    res.setHeader("Set-Cookie", `sid=${req.sid}; HttpOnly; Path=/; SameSite=Lax`);
    req.session = sessions.get(req.sid);
  }

  try {
    const url = await auth.authorizationUrl(req.sid, createSessionStore(req.session));
    res.redirect(url);
  } catch (error) {
    // A configuration mistake (bad issuer, mismatched redirect URI) lands here.
    // Log it: this is a bug on our side, not a user error.
    console.error("[auth] cannot start sign-in:", error.message);
    res.redirect("/?error=sso_unavailable");
  }
});

// ---------------------------------------------------------------------------
// 5. Handle the callback. Three steps: verify, check access, map the user.
// ---------------------------------------------------------------------------
app.get("/auth/callback", async (req, res) => {
  const fullUrl = new URL(req.originalUrl, REDIRECT_URI);

  let claims;
  try {
    // Validates state, nonce and PKCE. Throws when there is no sign-in in
    // progress, which covers an expired attempt and a replayed or forged
    // callback.
    claims = await auth.completeLogin(fullUrl, req.sid, createSessionStore(req.session));
  } catch (error) {
    console.error("[auth] sign-in failed:", error.message);
    return res.redirect("/?error=sso_failed");
  }

  // May this person use this application at all?
  const { allowed, groups } = access.check(claims);
  if (!allowed) {
    console.warn(`[auth] denied ${claims.email}: groups=${groups.join(",") || "(none)"}`);
    return res.redirect("/?error=no_app_access");
  }

  // Which account is this, and what may they do HERE? Both are the
  // application's decision. authentik supplied only identity and groups.
  const user = USERS[claims.email];
  if (!user) {
    // Deliberate policy choice: this app does not create accounts on the fly.
    // The other option is to provision one here, with an audit record.
    console.warn(`[auth] no local account for ${claims.email}`);
    return res.redirect("/?error=no_account");
  }

  req.session.user = user;
  req.session.groups = groups;
  res.redirect("/");
});

// ---------------------------------------------------------------------------
// 6. Use the session.
// ---------------------------------------------------------------------------
app.get("/", (req, res) => {
  const user = req.session.user;

  if (!user) {
    return res.type("html").send(`
      <h1>Example app</h1>
      <p>Access requires the <code>${access.appGroup}</code> group.</p>
      <a href="/auth/login">Sign in with authentik</a>
    `);
  }

  res.type("html").send(`
    <h1>Signed in</h1>
    <p><strong>${user.name}</strong> (${user.roles.join(", ")})</p>
    <p>Groups from authentik: <code>${req.session.groups.join(", ")}</code></p>
    <p>Roles come from this application, not from authentik.</p>
    <a href="/auth/logout">Sign out</a>
  `);
});

app.get("/auth/logout", (req, res) => {
  sessions.delete(req.sid);
  res.setHeader("Set-Cookie", "sid=; HttpOnly; Path=/; Max-Age=0");
  res.redirect("/");
});

app.listen(PORT, () => {
  console.log(`example app on http://localhost:${PORT}`);
  console.log(`  issuer     : ${auth.issuer}`);
  console.log(`  app group  : ${access.appGroup}`);
  console.log(`  redirect   : ${REDIRECT_URI}`);
  console.log(`  register that redirect URI on the authentik provider.`);
});
