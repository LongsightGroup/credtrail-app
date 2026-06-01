import {
  localDevDemoAdminEmail,
  localDevDemoLearnerEmail,
  localDevDemoRoutes,
  localDevDemoTenantId,
} from "../../../scripts/local-dev-demo-defaults.mjs";

export const tenantId = process.env.CREDTRAIL_DEV_TENANT_ID || localDevDemoTenantId;
export const adminEmail = process.env.CREDTRAIL_DEV_ADMIN_EMAIL || localDevDemoAdminEmail;
export const learnerEmail =
  process.env.CREDTRAIL_DEV_LEARNER_EMAIL || localDevDemoLearnerEmail;

export const demoRoutes = localDevDemoRoutes(tenantId);

export const firstDayTemplateName = (): string => {
  const suffix = new Date().toISOString().replaceAll(/[-:TZ.]/g, "").slice(0, 14);
  return `First Day Demo ${suffix}`;
};
