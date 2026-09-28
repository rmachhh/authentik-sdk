# Conventions for agents working in this repository

## What this package is

`authentik-sdk` adds authentik sign-in to Node applications and decides whether
the signed-in user may use an application. It does not manage roles, permissions
or users, and it must not start doing so.

## The rules this package encodes

These are load-bearing. A change that breaks one is a bug even if tests pass.

1. **One group per application.** Membership of the application's group is the
   entire access decision. Do not add a second gate.
2. **Never derive roles from the groups claim.** Roles belong to the consuming
   application. This is the reason the package exists in its current shape.
3. **Fail closed.** An application with no configured group denies everyone. A
   missing or malformed claim denies. Never let an unconfigured guard allow.
4. **Do not remove existing access on an unmatched claim.** A user whose groups
   match nothing keeps the roles they had. Stripping access when SSO is switched
   on would lock out every existing account.
5. **Flow state is single-use.** Clear it before the token exchange, so a replayed
   callback finds nothing.
6. **Refuse plain HTTP** unless `allowInsecure` is explicitly set, and only for
   local development.
7. **Configuration errors are not failed over.** Only network-shaped failures
   trigger trying the next instance. A typo must not look like an outage.
8. **Never log tokens, codes or client secrets.** Log outcomes and group names.
9. **The user import never deletes, never sets a password, and never mirrors
   roles.** Removing a user from a shared identity provider affects every
   connected system, so it stays a deliberate act. A role here does not become
   an authentik group.
10. **The import is repeatable.** An existing user is not recreated, and group
    membership is only written when missing. Never make it a one-shot that
    creates duplicates on a second run.
11. **The import needs a separate admin token.** It is a far more powerful
    credential than the sign-in client secret. Never reuse one for the other,
    and never put the admin token on a sign-in path.

## Layout

```
src/
  index.js       public exports; the OIDC client is loaded lazily from here
  access.js      the access decision (pure)
  roles.js       optional role mapping (pure)
  admin.js       user import; needs an API token, not the client secret
  config.js      environment configuration (group, role, connection)
  client.js      OIDC sign-in; imports openid-client
  stores.js      flow-state stores
  scopes.js      scope constants, kept separate so this import is dependency-free
tests/           one file per module, node:test
examples/        runnable examples
SETUP.md         the exact steps for integrating into another project
llms.txt         orientation for AI agents
```

**`src/admin.js` must not use the OIDC client.** The import is administered
with an API token, and mixing the two would mean a sign-in path could reach an
operation that creates users.

**`src/index.js` must not statically import `client.js`.** The sign-in client is
optional, and importing it eagerly would force every consumer to install
`openid-client`. `loadAuthentikClient()` exists for this reason.

## Testing

```bash
npm test                              # unit tests, no credentials or network
AUTHENTIK_CLIENT_SECRET=... npm test  # adds live tests against a running authentik
```

The admin tests need no credentials: `createAuthentikAdminClient` takes an
injected `fetch`, so the import is tested against a scripted transport.

- Unit tests must not require a network or credentials, and must skip cleanly
  when they do.
- A test that asserts a bug is fixed must fail without the fix. Verify by
  reverting the fix and watching it fail.
- Do not test against a hostname that is merely unresolvable when the test is
  about reaching a working server — spin up a local server instead.

## Changing the public API

- Adding an option is fine; changing or removing one is a breaking change and
  needs a major version.
- Keep the single-instance form working. `instances: [x]` and a top-level `issuer`
  must both work.
- Error messages are part of the API: an agent or a human will read them to decide
  what to do. Name the setting, and say what to do about it.

## Before committing

```bash
npm test
node examples/integration.js         # prints configuration and the access decision
```

Check that no real credential, client ID, email address or organisation name has
entered the package. It is published publicly.
