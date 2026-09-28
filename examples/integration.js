// Runnable integration example: sign in against authentik with the SDK, then
// decide access from the user's groups.
//
//   node examples/integration.js
//
// It reads the same environment variables the application uses, so it works
// against the same authentik instance without changing any configuration.
// Nothing here is persisted; it only proves the wiring and prints what happens.

import { config as loadEnv } from "dotenv";
import {
  createEphemeralStore,
  defineAccessPolicy,
  extractGroups,
  loadAuthentikClient,
} from "authentik-sdk";

const { createAuthentikClient } = await loadAuthentikClient();

loadEnv();

const REFUSED = "login refused: not signed in";

async function main() {
  const client = createAuthentikClient({
    issuer: process.env.AUTHENTIK_ISSUER,
    clientId: process.env.AUTHENTIK_CLIENT_ID,
    clientSecret: process.env.AUTHENTIK_CLIENT_SECRET,
    redirectUri: process.env.AUTHENTIK_REDIRECT_URI,
    // Local authentik runs over plain HTTP; production must not.
    allowInsecure: (process.env.AUTHENTIK_ISSUER ?? "").startsWith("http://"),
  });

  console.log("1. configuration");
  console.log("   issuer    :", client.issuer);
  console.log("   client    :", client.clientId);
  console.log("   scopes    :", client.scopes);
  console.log("   redirect  :", client.redirectUri);

  // The store holds PKCE verifier, state and nonce between the redirect and the
  // callback. A real app passes its session; this example uses memory.
  const store = createEphemeralStore();
  const url = await client.authorizationUrl("example-flow", store);

  console.log("\n2. the URL to redirect the browser to");
  console.log("  ", url.slice(0, 96) + "...");

  const parsed = new URL(url);
  console.log("   response_type :", parsed.searchParams.get("response_type"));
  console.log("   PKCE method   :", parsed.searchParams.get("code_challenge_method"));
  console.log("   state present :", Boolean(parsed.searchParams.get("state")));
  console.log("   nonce present :", Boolean(parsed.searchParams.get("nonce")));

  // A callback that was never started must be refused. This is the guard
  // against a forged or replayed callback.
  console.log("\n3. a callback with no login in progress");
  try {
    await client.completeLogin(
      `${client.redirectUri}?code=made-up&state=made-up`,
      "never-started",
      store,
    );
    console.log("   UNEXPECTED: it was accepted");
  } catch (error) {
    console.log("   refused, as it should be:", error.message.split(".")[0]);
  }

  // The access decision. Replace with the application's own group.
  const appGroup = process.env.APP_GROUP ?? "myapp-access";
  const policy = defineAccessPolicy({ appGroup });

  console.log(`\n4. access decision, appGroup="${appGroup}"`);
  for (const example of [
    { label: "in the group", groups: ["myapp-access", "some-other-team"] },
    { label: "only in another app's group", groups: ["hr-access"] },
    { label: "no groups at all", groups: [] },
  ]) {
    const { allowed } = policy.check({ groups: example.groups });
    console.log(`   ${example.label.padEnd(30)} -> ${allowed ? "ALLOWED" : "denied"}`);
  }

  console.log("\n5. what the application then sees");
  const claims = { sub: "abc123", email: "alex@example.com",
                   groups: ["myapp-access", "myapp-admins"] };
  console.log("   groups from claims :", extractGroups(claims));
  console.log("   allowed            :", policy.check(claims).allowed);
  console.log("   roles              : supplied by this application, not authentik");

  console.log("\nDone. Replace the store with your session and you are integrated.");
}

main().catch((error) => {
  console.error("example failed:", error.message);
  process.exitCode = 1;
});
