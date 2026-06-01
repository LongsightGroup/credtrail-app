import { localDevDefaults } from "./local-dev-ready-block.mjs";

const ready = localDevDefaults();
const nextPath = process.env.CREDTRAIL_DEV_NEXT_PATH?.trim() || ready.adminPath;

const loginUrl = new URL("/v1/dev/auth/login-as", ready.baseUrl);
loginUrl.searchParams.set("tenantId", ready.tenantId);
loginUrl.searchParams.set("email", ready.adminEmail);
loginUrl.searchParams.set("next", nextPath);

console.log(loginUrl.toString());
