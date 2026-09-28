# Adding authentik sign-in

Exact steps. Follow them literally rather than inventing wiring — the order and
the details matter, and most integration failures come from skipping step 2 or 5.

Before starting, you need four values from authentik. If any are missing, stop
and ask rather than guessing:

| Value | Where it comes from |
|---|---|
| `AUTHENTIK_ISSUER` | The application's issuer URL, ending `/application/o/<slug>/` |
| `AUTHENTIK_CLIENT_ID` | The provider's client ID |
| `AUTHENTIK_CLIENT_SECRET` | The provider's client secret |
| `APP_GROUP` | The authentik group that grants access to this application |

---

## Step 1 — Install

```bash
npm install github:rmachhh/authentik-sdk
```

## Step 2 — Register the redirect URI in authentik

In the authentik admin interface: **Applications → Providers → your provider →
Redirect URIs**.

Add the exact callback URL for this environment, for example:

```
http://localhost:3000/auth/callback          # development
https://myapp.example.com/auth/callback      # production
```

It must match `AUTHENTIK_REDIRECT_URI` **character for character**. A mismatch is
the most common cause of a login that loops back to the login page.

## Step 3 — Add the environment variables

```dotenv
AUTHENTIK_ISSUER=https://id.example.com/application/o/myapp/
AUTHENTIK_CLIENT_ID=myapp
AUTHENTIK_CLIENT_SECRET=
AUTHENTIK_REDIRECT_URI=http://localhost:3000/auth/callback
APP_GROUP=myapp-access
```

Add `AUTHENTIK_CLIENT_SECRET` to `.gitignore`'d configuration only. Never commit
it, and never expose it to browser code.

## Step 4 — Create the auth module

Create `src/auth.js` (or the equivalent for the project's layout):

```js
import {
  createSessionStore,
  defineAccessPolicy,
  loadAuthentikClient,
} from "authentik-sdk";

const { createAuthentikClient } = await loadAuthentikClient();

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} environment variable is required`);
  return value;
}

const issuer = requireEnv("AUTHENTIK_ISSUER");

export const auth = createAuthentikClient({
  issuer,
  clientId: requireEnv("AUTHENTIK_CLIENT_ID"),
  clientSecret: requireEnv("AUTHENTIK_CLIENT_SECRET"),
  redirectUri: requireEnv("AUTHENTIK_REDIRECT_URI"),
  // Local authentik serves plain HTTP. Any real deployment is https://.
  allowInsecure: issuer.startsWith("http://"),
});

// The group that grants access to THIS application.
export const access = defineAccessPolicy({ appGroup: requireEnv("APP_GROUP") });
```

## Step 5 — Create the two routes

Adapt the framework calls; the SDK calls must stay as written.

```js
// Start sign-in.
app.get("/auth/login", async (req, res) => {
  try {
    const url = await auth.authorizationUrl(
      req.sessionID,
      createSessionStore(req.session),
    );
    res.redirect(url);
  } catch (error) {
    console.error("[auth] cannot start sign-in:", error.message);
    res.redirect("/?error=sso_unavailable");
  }
});

// Finish sign-in.
app.get("/auth/callback", async (req, res) => {
  let claims;
  try {
    claims = await auth.completeLogin(
      new URL(req.originalUrl, auth.redirectUri),
      req.sessionID,
      createSessionStore(req.session),
    );
  } catch (error) {
    console.error("[auth] sign-in failed:", error.message);
    return res.redirect("/?error=sso_failed");
  }

  // May this person use this application at all?
  const { allowed, groups } = access.check(claims);
  if (!allowed) {
    console.warn(`[auth] denied ${claims.email}: ${groups.join(",") || "(no groups)"}`);
    return res.redirect("/?error=no_app_access");
  }

  // The account is the application's data, not authentik's.
  const user = await findUserByEmail(claims.email);
  if (!user) return res.redirect("/?error=no_account");

  // Roles stay here. Do not set them from the groups claim.
  req.session.userId = user.id;
  res.redirect("/");
});
```

Add a link to `/auth/login` labelled "Sign in with authentik".

## Step 6 — Verify

Do these in order and fix each before moving on.

1. **The app starts** and the login page renders the authentik link.
2. **`/auth/login` redirects to authentik** — the URL should contain
   `response_type=code`, `code_challenge_method=S256`, and `state`.
3. **Sign in** with a user who is in the app's group. You should land back on the
   application, signed in.
4. **Denial works.** Remove the test user from the group in authentik, sign in
   again, and confirm the application refuses them.
5. **The redirect URI matches.** If sign-in loops, the value in
   `AUTHENTIK_REDIRECT_URI` and the provider's registered URI differ.

Report which of the six steps succeeded, and include any error message verbatim.

---

## Failure messages and what they mean

| Message | Cause | Fix |
|---|---|---|
| `No sign-in in progress for this session` | Session lost between redirect and callback, or a replayed callback | Check the session is persisted server-side and survives the redirect |
| `Refusing plain-HTTP issuer` | `http://` issuer outside development | Use `https://`, or set `allowInsecure` only for local work |
| `redirectUri ... does not match` | App and provider disagree on the callback URL | Make them identical |
| `Request has been denied` (from authentik) | The user is in no group bound to the application | Add a binding, or add the user to the group |
| `allowed: false` from the app | The user is not in `APP_GROUP` | Add them, or correct the group name |
| Login loops to the login page | Redirect URI mismatch, usually | See step 2 |

## Things not to do

- Do not set roles or permissions from the `groups` claim.
- Do not create an account when no local user matches; this package's policy is to
  refuse and let the administrator decide. If the project wants provisioning, ask
  first — it needs an audit trail.
- Do not log tokens, authorization codes, or client secrets.
- Do not make `APP_GROUP` optional or fall back to allowing everyone.
