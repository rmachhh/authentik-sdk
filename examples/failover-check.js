import { config as loadEnv } from "dotenv";
import { createEphemeralStore, loadAuthentikClient } from "../src/index.js";

loadEnv({ path: "../../.env" });

const { createAuthentikClient } = await loadAuthentikClient();

const base = {
  issuer: process.env.AUTHENTIK_ISSUER,
  clientId: process.env.AUTHENTIK_CLIENT_ID,
  clientSecret: process.env.AUTHENTIK_CLIENT_SECRET,
  redirectUri: process.env.AUTHENTIK_REDIRECT_URI,
  allowInsecure: true,
};

const primary = { ...base, label: "primary" };
const down = { ...base, label: "backup-down", issuer: "http://127.0.0.1:59999/application/o/sis/" };

console.log("case 1: primary up, backup down");
const a = createAuthentikClient({
  instances: [primary, down],
  onFailover: (_e, i) => console.log("   skipped:", i.label),
});
const urlA = await a.authorizationUrl("f1", createEphemeralStore());
console.log("   used:", new URL(urlA).origin);

console.log("\ncase 2: primary down, backup up");
const b = createAuthentikClient({
  instances: [down, primary],
  onFailover: (_e, i) => console.log("   skipped:", i.label, "(unreachable)"),
});
const urlB = await b.authorizationUrl("f2", createEphemeralStore());
console.log("   used:", new URL(urlB).origin, new URL(urlB).pathname);

console.log("\ncase 3: both down");
const c = createAuthentikClient({
  instances: [
    { ...down, label: "one" },
    { ...down, label: "two", issuer: "http://127.0.0.1:59998/application/o/sis/" },
  ],
});
try {
  await c.authorizationUrl("f3", createEphemeralStore());
  console.log("   UNEXPECTED: succeeded");
} catch (error) {
  console.log("  ", error.message.slice(0, 120));
}
