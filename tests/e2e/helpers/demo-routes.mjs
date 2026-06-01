export const tenantId = process.env.CREDTRAIL_DEV_TENANT_ID || "tenant_123";
export const learnerEmail = process.env.CREDTRAIL_DEV_LEARNER_EMAIL || "learner@example.edu";

export const demoRoutes = {
  admin: `/tenants/${encodeURIComponent(tenantId)}/admin`,
  badgeTemplates: `/tenants/${encodeURIComponent(tenantId)}/admin/rules/templates`,
  rules: `/tenants/${encodeURIComponent(tenantId)}/admin/rules`,
  manualIssue: `/tenants/${encodeURIComponent(tenantId)}/admin/operations/issue`,
  issuedBadges: `/tenants/${encodeURIComponent(tenantId)}/admin/operations/issued-badges`,
};

export const firstDayTemplateName = () => {
  const suffix = new Date().toISOString().replaceAll(/[-:TZ.]/g, "").slice(0, 14);
  return `First Day Demo ${suffix}`;
};
