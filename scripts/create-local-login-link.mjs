import { loadLocalDevEnv } from "./local-dev-env.mjs";

loadLocalDevEnv();

const baseUrl = process.env.CREDTRAIL_DEV_BASE_URL?.trim() || "http://127.0.0.1:8787";
const email = process.env.CREDTRAIL_DEV_ADMIN_EMAIL?.trim() || "admin@credtrail.local";
const tenantId = process.env.CREDTRAIL_DEV_TENANT_ID?.trim() || "tenant_123";
const nextPath =
  process.env.CREDTRAIL_DEV_NEXT_PATH?.trim() ||
  `/tenants/${encodeURIComponent(tenantId)}/admin`;

const response = await fetch(new URL("/v1/auth/magic-link/request", baseUrl), {
  method: "POST",
  headers: {
    "content-type": "application/json",
  },
  body: JSON.stringify({
    tenantId,
    email,
    nextPath,
  }),
});

const responseText = await response.text();
let payload;

try {
  payload = JSON.parse(responseText);
} catch {
  console.error(responseText);
  throw new Error(`Unable to create local login link. HTTP ${response.status}`);
}

if (!response.ok || typeof payload.magicLinkUrl !== "string") {
  console.error(JSON.stringify(payload, null, 2));
  throw new Error(`Unable to create local login link. HTTP ${response.status}`);
}

const localUrl = new URL(payload.magicLinkUrl);
const localBaseUrl = new URL(baseUrl);
localUrl.protocol = localBaseUrl.protocol;
localUrl.host = localBaseUrl.host;

console.log(localUrl.toString());
