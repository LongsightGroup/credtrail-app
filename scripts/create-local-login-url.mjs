import { loadLocalDevEnv } from "./local-dev-env.mjs";

loadLocalDevEnv();

const baseUrl = process.env.CREDTRAIL_DEV_BASE_URL?.trim() || "http://127.0.0.1:8787";
const email = process.env.CREDTRAIL_DEV_ADMIN_EMAIL?.trim() || "admin@credtrail.local";
const tenantId = process.env.CREDTRAIL_DEV_TENANT_ID?.trim() || "tenant_123";
const nextPath =
  process.env.CREDTRAIL_DEV_NEXT_PATH?.trim() ||
  `/tenants/${encodeURIComponent(tenantId)}/admin`;

const loginUrl = new URL("/v1/dev/auth/login-as", baseUrl);
loginUrl.searchParams.set("tenantId", tenantId);
loginUrl.searchParams.set("email", email);
loginUrl.searchParams.set("next", nextPath);

console.log(loginUrl.toString());
