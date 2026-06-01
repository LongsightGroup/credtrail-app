export const localDevDemoTenantId = "tenant_123";
export const localDevDemoAdminEmail = "admin@credtrail.local";
export const localDevDemoLearnerEmail = "learner@example.edu";

export const localDevDemoRoutes = (tenantId = localDevDemoTenantId) => {
  return {
    admin: `/tenants/${encodeURIComponent(tenantId)}/admin`,
    badgeTemplates: `/tenants/${encodeURIComponent(tenantId)}/admin/rules/templates`,
    rules: `/tenants/${encodeURIComponent(tenantId)}/admin/rules`,
    ruleBuilder: `/tenants/${encodeURIComponent(tenantId)}/admin/rules/new`,
    manualIssue: `/tenants/${encodeURIComponent(tenantId)}/admin/operations/issue`,
    issuedBadges: `/tenants/${encodeURIComponent(tenantId)}/admin/operations/issued-badges`,
    reporting: `/tenants/${encodeURIComponent(tenantId)}/admin/reporting`,
    publicTrustedCredential: "/badges/trusted-demo-credential",
  };
};
