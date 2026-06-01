import { loadLocalDevEnv } from "./local-dev-env.mjs";
import {
  localDevDemoAdminEmail,
  localDevDemoRoutes,
  localDevDemoTenantId,
} from "./local-dev-demo-defaults.mjs";

export const localDevDefaults = () => {
  loadLocalDevEnv();

  const baseUrl = process.env.CREDTRAIL_DEV_BASE_URL?.trim() || "http://127.0.0.1:8787";
  const tenantId = process.env.CREDTRAIL_DEV_TENANT_ID?.trim() || localDevDemoTenantId;
  const adminEmail = process.env.CREDTRAIL_DEV_ADMIN_EMAIL?.trim() || localDevDemoAdminEmail;
  const demoRoutes = localDevDemoRoutes(tenantId);
  const adminPath = demoRoutes.admin;
  const adminLoginUrl = new URL("/v1/dev/auth/login-as", baseUrl);

  adminLoginUrl.searchParams.set("tenantId", tenantId);
  adminLoginUrl.searchParams.set("email", adminEmail);
  adminLoginUrl.searchParams.set("next", adminPath);

  return {
    baseUrl,
    tenantId,
    adminEmail,
    adminPath,
    adminLoginUrl: adminLoginUrl.toString(),
    demoRoutes,
  };
};

export const printReadyBlock = (extra = {}) => {
  console.log(
    JSON.stringify(
      {
        ...localDevDefaults(),
        ...extra,
      },
      null,
      2,
    ),
  );
};
