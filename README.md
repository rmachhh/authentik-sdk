# authentik-sdk

Single sign-on against authentik, with **one group per application**.

## The model

Every application has one authentik group. If the signed-in user is in that
group, they may use the application. That is the whole access rule.

```
authentik                          Your application
─────────                          ────────────────
group: myapp-access    ──▶       "is myapp-access in the claims?"  ──▶  yes / no
```

No roles, no mapping table, no database required. authentik reports **every**
group a user belongs to, and the application decides whether its own group is
among them — so one group per app is enough to restrict access.

**Roles are not set from authentik.** authentik answers *may this person use the
application*, and nothing more. What they may do once inside belongs to the
application: keep roles in your own database, tables or config, and read groups
only as a yes/no gate. That way an identity-provider change can never grant
application privileges.

`createRoleMapper` exists for the minority of systems that have no role store of
their own and want to derive one from groups. **If your application already has
roles, ignore it** — use `defineAccessPolicy` and stop there.

## Install

The package lives in this repository at `packages/authentik-sdk`. Four ways to
get it into another application, simplest first.

### 1. Same repository (a workspace)

Already configured here. Another package in this repo just declares it:

```json
{ "dependencies": { "authentik-sdk": "*" } }
```

then `npm install` links it.

### 2. A tarball (works everywhere, no registry, no network)

```bash
# where the SDK lives
npm pack                       # produces authentik-sdk-0.1.0.tgz

# in the consuming application
npm install /path/to/authentik-sdk-0.1.0.tgz
```

Commit the `.tgz` to a shared `vendor/` folder if the applications do not share
a network. This is the most portable option and needs no credentials.

### 3. From the private Git repository

The repository is private, so the install needs a credential — an SSH key or a
token. Tarball installs above avoid that entirely.

```bash
npm install git+ssh://git@github.com/rmachhh/authentik-sdk.git
```

Do **not** use `git+https://` without a token on a private repository: it fails
with `404`, which reads like a missing package rather than an authentication
problem.

If you want an install straight from the subdirectory rather than the whole
repository, give the SDK its own repository. npm cannot install a package from a
subdirectory of a git repo.

### 4. A registry (best once three or more apps consume it)

Publish to GitHub Packages, which is free for private repositories:

```bash
# .npmrc in the SDK repository
@your-scope:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}

# publish
npm publish
```

Then each application:

```bash
npm install @your-scope/authentik-sdk
```

Versioning becomes explicit (`^0.2.0`), and updates are opt-in per application.

### Dependencies

`openid-client` is a real dependency, installed automatically. It is only used
by the sign-in flow, which loads lazily, so an application that only needs the
access decision still gets it installed but never loads it.

If the consuming project has pre-existing peer-dependency conflicts unrelated to
this package, npm may refuse the install:

```bash
npm install <package> --legacy-peer-deps
```

Many older Laravel-Mix projects need this regardless of this SDK.

### Verify the install

```js
import { defineAccessPolicy } from "authentik-sdk";

const policy = defineAccessPolicy({ appGroup: "your-app-access" });
console.log(policy.check({ groups: ["your-app-access"] })); // { allowed: true, ... }
```

Sign-in is a separate, deferred load:

```js
import { loadAuthentikClient } from "authentik-sdk";
const { createAuthentikClient } = await loadAuthentikClient();
```

## Quick start

```js
import {
  createAuthentikClient,
  createSessionStore,
  defineAccessPolicy,
} from "authentik-sdk";

const auth = createAuthentikClient({
  issuer: process.env.AUTHENTIK_ISSUER,        // https://id.example.com/application/o/records/
  clientId: process.env.AUTHENTIK_CLIENT_ID,   // records
  clientSecret: process.env.AUTHENTIK_CLIENT_SECRET,
  redirectUri: process.env.AUTHENTIK_REDIRECT_URI,
});

// One line: this application requires this group.
const access = defineAccessPolicy({ appGroup: "myapp-access" });
```

**Starting a sign-in**

```js
app.get("/auth/login", async (req, res) => {
  const store = createSessionStore(req.session);
  const url = await auth.authorizationUrl(req.session.id, store);
  res.redirect(url);
});
```

**Handling the callback**

```js
app.get("/auth/callback", async (req, res) => {
  const store = createSessionStore(req.session);
  const fullUrl = new URL(req.originalUrl, auth.redirectUri);

  let claims;
  try {
    claims = await auth.completeLogin(fullUrl, req.session.id, store);
  } catch (error) {
    // Covers: expired sign-in attempt, replayed callback, forged callback,
    // failed token exchange. All are "start again", not "you are logged in".
    return res.redirect("/login?error=sso_failed");
  }

  const { allowed, groups } = access.check(claims);
  if (!allowed) {
    return res.redirect("/login?error=no_app_access");
  }

  // Existing behaviour continues from here: match the user, start a session.
  req.session.userId = await findUserIdByEmail(claims.email);
  res.redirect("/");
});
```

## Implementing it in a new project

A complete, runnable example is in `examples/express-app.js` — it was verified
against a real authentik instance. Copy it and change four things.

### The four things you supply

| # | You provide | Why it cannot come from the SDK |
|---|---|---|
| 1 | **A session** | Every framework stores sessions differently |
| 2 | **A user lookup** | Who exists is your data |
| 3 | **Your roles** | What a person may do is your rule |
| 4 | **The app's group name** | One group per application, chosen by you |

### The integration, in full

```js
import { createSessionStore, defineAccessPolicy, loadAuthentikClient } from "authentik-sdk";

const { createAuthentikClient } = await loadAuthentikClient();

const auth = createAuthentikClient({
  issuer: process.env.AUTHENTIK_ISSUER,       // .../application/o/<slug>/
  clientId: process.env.AUTHENTIK_CLIENT_ID,
  clientSecret: process.env.AUTHENTIK_CLIENT_SECRET,
  redirectUri: "https://myapp.example.com/auth/callback",
});

const access = defineAccessPolicy({ appGroup: "myapp-access" });

// 1. start
app.get("/auth/login", async (req, res) => {
  const url = await auth.authorizationUrl(req.sessionID, createSessionStore(req.session));
  res.redirect(url);
});

// 2. finish
app.get("/auth/callback", async (req, res) => {
  let claims;
  try {
    claims = await auth.completeLogin(
      new URL(req.originalUrl, auth.redirectUri), req.sessionID, createSessionStore(req.session));
  } catch {
    return res.redirect("/?error=sso_failed");   // expired, replayed or forged
  }

  if (!access.check(claims).allowed) return res.redirect("/?error=no_app_access");

  const user = await findUserByEmail(claims.email);   // your database
  if (!user) return res.redirect("/?error=no_account");
  req.session.user = user;                            // your roles ride along
  res.redirect("/");
});
```

That is the whole integration. Two endpoints and one access check.

### What each call guarantees

| Call | Guarantee |
|---|---|
| `authorizationUrl()` | PKCE challenge generated; verifier, state and nonce persisted server-side |
| `completeLogin()` | State, nonce and PKCE validated; flow state cleared first, so it cannot be replayed |
| `access.check()` | Returns `{ allowed, groups }`; fails closed when no group is configured |

### Framework notes

- **Express** — `createSessionStore(req.session)`, flow id `req.sessionID`
- **Fastify** — `createSessionStore(req.session)`, flow id `req.session.sessionId`
- **Next.js / serverless** — pass a store backed by your session cookie; the flow
  state must survive between the redirect and the callback
- **No framework** — `createMemoryStore()` with your own cookie; the store only
  needs `saveFlowState`, `loadFlowState`, `clearFlowState`

### Checklist before it will work

1. An application and provider exist in authentik for this system
2. The redirect URI above is registered on the provider, **exactly**
3. The application is bound to a group — without a binding, every authenticated
   user can use it
4. `AUTHENTIK_REDIRECT_URI` in the app matches what you registered
5. The user has a local account, unless you choose to provision one

### Failure modes and what they look like

| Symptom | Cause |
|---|---|
| `No sign-in in progress for this session` | Session lost between redirect and callback, or a replayed callback |
| `Refusing plain-HTTP issuer` | `https://` in production; pass `allowInsecure` only for local dev |
| Login loops back to the login page | The redirect URI does not match the provider's registered value |
| `Request has been denied` (from authentik) | The user is not in any group bound to the application |
| Signed in, but `no_account` | Authenticated correctly, but no local account matches the email |

## API

### `createAuthentikClient(options)`

| Option | Required | Notes |
|---|---|---|
| `issuer` | yes | The application's issuer URL, ending `/application/o/<slug>/` |
| `clientId` | yes | From the authentik provider |
| `clientSecret` | yes | From the authentik provider. Server-side only. |
| `redirectUri` | yes | Must match authentik's registered URI exactly |
| `scopes` | no | Defaults to `openid email profile`, which already includes groups |
| `allowInsecure` | no | Required to use an `http://` issuer. Local development only. |

Returns:

| Method | Purpose |
|---|---|
| `authorizationUrl(flowId, store)` | Build the redirect URL and persist the PKCE verifier, state and nonce |
| `completeLogin(callbackUrl, flowId, store)` | Validate state, nonce and PKCE; return verified claims |

Both throw with a clear message rather than failing silently. A missing setting,
a missing store, an unstarted login and a plain-HTTP issuer in production are all
refused before anything else happens.

### `defineAccessPolicy({ appGroup, mapRoles? })`

| Option | Required | Notes |
|---|---|---|
| `appGroup` | yes | The group that grants access. A string, or several (any of). |
| `mapRoles` | no | `(groups) => string[]` — the application's own roles |

Returns:

| Member | Purpose |
|---|---|
| `check(claims)` | `{ allowed, groups, roles }` |
| `groupsFrom(claims)` | The group list, unfiltered |
| `rolesFrom(claims)` | Roles only, `[]` when mapping is not configured |
| `appGroup` | The configured group, for logging |

Throws at construction when `appGroup` is missing. An application that has not
declared its group **denies** everyone rather than accidentally allowing them.

### Stores

| Factory | Use |
|---|---|
| `createSessionStore(session)` | A serialised session, such as Express's `req.session` |
| `createMemoryStore(holder)` | Any Map-like object you already have |
| `createEphemeralStore(ttlMs)` | Tests and short-lived processes; entries expire |

A store is three methods: `saveFlowState`, `loadFlowState`, `clearFlowState`.
Anything matching that shape works — the SDK never assumes a framework.

### Helpers

```js
import { extractGroups, isMemberOfAppGroup } from "authentik-sdk";

extractGroups(claims);                            // ["myapp-access", "hr-access"]
isMemberOfAppGroup(groups, "myapp-access");     // true
```

`extractGroups` accepts `groups` or `group`, as a list or a single string,
de-duplicates, and never throws — providers vary in how they deliver the claim.

## Optional: role mapping (only if you have no role store)

Most applications keep roles in their own database. If yours does, skip this section entirely — the group check above is the whole integration.

Use this only when a system has no role store of its own and needs one derived from groups. It is application-side logic; authentik never assigns roles.

```js
import { createRoleMapper, pickPrimaryRole } from "authentik-sdk";

const rolesFromGroups = createRoleMapper({
  map: {
    "myapp-access": "user",
    "myapp-admins": "admin",
  },
  roles: ["user", "scheduler", "admin"],   // roles that exist in this app
});

rolesFromGroups(["myapp-access", "myapp-admins"]);  // ["user", "admin"]
pickPrimaryRole(["user", "admin"], roles);              // "admin"
```

Rules, all tested:

- A group grants a role only if it is in the map **and** the role exists in this
  application. Mapping drift grants nothing.
- Unknown groups are ignored — including other systems' groups and authentik's
  own internal groups.
- Roles are returned in the application's own order, so precedence never depends
  on the order the provider happened to send groups in.
- `requireAppGroup` makes the mapping conditional on holding the app's group.

## Setting up the authentik side

1. **Create one group per application**, for example `myapp-access`.
2. **Create an application and provider** for the system
   (Applications → Applications → Create with Provider, type OAuth2/OpenID).
3. **Register the redirect URI** — one per environment, exact, no wildcards.
4. **Request `openid email profile`.** The `profile` scope already includes group
   membership, so no custom scope mapping is needed.
5. **Bind the application to its group** so the right people can launch it.
   Without a binding, *every* authenticated user can.

## Moving an existing system onto it

Keep your current "match the user" logic and add one line:

```js
const { allowed } = access.check(claims);
if (!allowed) return res.redirect("/login?error=no_app_access");
```

Then set `appGroup` to the application's group. Nothing else in your
authentication needs to change — the SDK replaces only the redirect, the token
exchange and the access decision.

## Design notes

- **No framework dependency.** Session handling differs everywhere, so the SDK
  takes a store rather than assuming one.
- **Plain HTTP is refused by default.** A production deployment cannot silently
  send credentials unencrypted.
- **Discovery is cached per client.** The provider's metadata does not change
  between requests.
- **Flow state is single-use.** It is cleared before the token exchange, so a
  replayed callback finds nothing.
- **Secrets stay server-side.** The PKCE verifier, state and nonce are never
  placed in a URL.

## Tests

```bash
npm test                                  # unit tests only
AUTHENTIK_CLIENT_SECRET=<secret> npm test # adds live integration tests
```

The integration tests skip without credentials, so the suite runs anywhere. With
credentials they discover the real provider, build a PKCE authorization URL and
confirm a callback that was never started is refused.
