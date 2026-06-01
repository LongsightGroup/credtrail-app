import { loadLocalDevEnv } from "./local-dev-env.mjs";

export const localDevDefaults = () => {
  loadLocalDevEnv();

  const baseUrl = process.env.CREDTRAIL_DEV_BASE_URL?.trim() || "http://127.0.0.1:8787";
  const tenantId = process.env.CREDTRAIL_DEV_TENANT_ID?.trim() || "tenant_123";
  const adminEmail = process.env.CREDTRAIL_DEV_ADMIN_EMAIL?.trim() || "admin@credtrail.local";
  const adminPath = `/tenants/${encodeURIComponent(tenantId)}/admin`;
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
    demoRoutes: {
      admin: adminPath,
      badgeTemplates: `/tenants/${encodeURIComponent(tenantId)}/admin/rules/templates`,
      rules: `/tenants/${encodeURIComponent(tenantId)}/admin/rules`,
      ruleBuilder: `/tenants/${encodeURIComponent(tenantId)}/admin/rules/new`,
      manualIssue: `/tenants/${encodeURIComponent(tenantId)}/admin/operations/issue`,
      issuedBadges: `/tenants/${encodeURIComponent(tenantId)}/admin/operations/issued-badges`,
      publicTrustedCredential: "/badges/trusted-demo-credential",
      reporting: `/tenants/${encodeURIComponent(tenantId)}/admin/reporting`,
    },
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
