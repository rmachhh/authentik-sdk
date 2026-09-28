#!/usr/bin/env node
// Verify an authentik integration without signing in.
//
//   node scaffold/doctor.mjs
//
// Checks the things that actually go wrong — a missing setting, a mismatched
// redirect URI, an unreachable issuer, an app group that does not exist — and
// prints a specific fix for each. Run it before asking anyone to test in a
// browser.

import { createEphemeralStore, defineAccessPolicy, loadAuthentikClient } from "authentik-sdk";

const CHECKS = [];
let failed = 0;

function record(name, ok, detail, fix) {
  CHECKS.push({ name, ok, detail, fix });
  if (!ok) failed += 1;
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

async function main() {
  console.log("authentik integration check\n");

  // 1. Configuration
  let issuer, clientId, clientSecret, redirectUri, appGroup;
  try {
    issuer = requireEnv("AUTHENTIK_ISSUER");
    clientId = requireEnv("AUTHENTIK_CLIENT_ID");
    clientSecret = requireEnv("AUTHENTIK_CLIENT_SECRET");
    redirectUri = requireEnv("AUTHENTIK_REDIRECT_URI");
    appGroup = requireEnv("APP_GROUP");
    record("configuration", true, "all five variables are set");
  } catch (error) {
    record("configuration", false, error.message,
      "Set AUTHENTIK_ISSUER, AUTHENTIK_CLIENT_ID, AUTHENTIK_CLIENT_SECRET, " +
      "AUTHENTIK_REDIRECT_URI and APP_GROUP. See SETUP.md step 3.");
    return report();
  }

  // 2. Issuer shape
  const issuerOk = issuer.endsWith("/") && issuer.includes("/application/o/");
  record("issuer shape", issuerOk,
    issuerOk ? issuer : `${issuer} does not look like an application issuer`,
    "The issuer ends with /application/o/<slug>/ and keeps its trailing slash. " +
    "Copy it from authentik: Applications > Providers > your provider.");

  // 3. Redirect URI shape
  const redirectLooksRight = /^https?:\/\/.+\/.+/.test(redirectUri);
  record("redirect uri shape", redirectLooksRight,
    redirectLooksRight ? redirectUri : `${redirectUri} is not an absolute http(s) URL`,
    "AUTHENTIK_REDIRECT_URI must be the full callback URL, e.g. " +
    "https://myapp.example.com/auth/callback");

  // 4. HTTPS outside development
  const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1)/.test(issuer);
  const httpsOk = issuer.startsWith("https://") || isLocal;
  record("transport", httpsOk,
    httpsOk ? (isLocal ? "plain HTTP allowed for a local issuer" : "https") : "plain HTTP",
    "Use an https:// issuer. allowInsecure is only for a local authentik container.");

  // 5. Reachability + client credentials, in one step: discovery only succeeds
  //    if the issuer resolves and answers.
  let client;
  try {
    const { createAuthentikClient } = await loadAuthentikClient();
    client = createAuthentikClient({
      issuer, clientId, clientSecret, redirectUri,
      allowInsecure: issuer.startsWith("http://"),
    });

    const url = await client.authorizationUrl("doctor", createEphemeralStore());
    const parsed = new URL(url);

    record("discovery", true, `authorization endpoint ${parsed.origin}${parsed.pathname}`);
    record("pkce", parsed.searchParams.get("code_challenge_method") === "S256",
      parsed.searchParams.get("code_challenge_method") ?? "(missing)",
      "The SDK always sends S256. A different value means the URL was built elsewhere.");
    record("state and nonce",
      Boolean(parsed.searchParams.get("state")) && Boolean(parsed.searchParams.get("nonce")),
      `state=${parsed.searchParams.get("state") ? "present" : "MISSING"} ` +
      `nonce=${parsed.searchParams.get("nonce") ? "present" : "MISSING"}`,
      "Both are required and stored server-side. If either is missing, do not sign in.");
    record("verifier not exposed", !parsed.searchParams.get("code_verifier"),
      "the PKCE verifier is not in the authorization URL",
      "The verifier must never reach the browser in readable form.");

    if (parsed.searchParams.get("redirect_uri") !== redirectUri) {
      record("redirect uri registered", false,
        `the SDK sent ${parsed.searchParams.get("redirect_uri")}`,
        "This is the value authentik will check. Make sure the provider registers it exactly.");
    } else {
      record("redirect uri registered", true,
        "the URI is passed through unchanged; confirm it is registered on the provider " +
        "under Applications > Providers > Redirect URIs");
    }
  } catch (error) {
    record("discovery", false, error.message,
      "Check AUTHENTIK_ISSUER is reachable from this machine, and that the client " +
      "credentials belong to a provider on that instance.");
  }

  // 6. The access decision, against a fabricated claim set. This checks the
  //    guard is configured, not that any real user has access.
  if (appGroup) {
    const access = defineAccessPolicy({ appGroup });
    const allowed = access.check({ groups: [appGroup] }).allowed;
    const denied = access.check({ groups: ["some-other-group"] }).allowed === false;
    const closedWithoutGroup = defineAccessPolicy({ appGroup })
      .check({ groups: [] }).allowed === false;

    record("access guard", allowed && denied && closedWithoutGroup,
      `appGroup="${appGroup}" grants access, other groups and no groups are denied`,
      "If this fails the guard is misconfigured. hasAccessTo must fail closed.");
  }

  return report();
}

function report() {
  console.log("");
  for (const check of CHECKS) {
    console.log(`  ${check.ok ? "PASS" : "FAIL"}  ${check.name}: ${check.detail}`);
    if (!check.ok && check.fix) console.log(`        fix: ${check.fix}`);
  }

  console.log("");
  if (failed === 0) {
    console.log("All checks passed. Sign-in should work once the redirect URI is registered.");
    console.log("Next: sign in with a user in APP_GROUP, then remove them from the group and");
    console.log("confirm the application refuses them.");
    return 0;
  }

  console.log(`${failed} check(s) failed. Fix those before testing sign-in in a browser.`);
  return 1;
}

main().then((code) => { process.exitCode = code; }).catch((error) => {
  console.error("check could not run:", error.message);
  process.exitCode = 1;
});
