import type { JsonObject } from "@credtrail/core-domain";
import type { AssertionRecord } from "@credtrail/db";
import type { PublicBadgeViewModel } from "../badges/public-badge-model";
import type { LearnerDidSettingsNotice } from "../learner/pages";
import type { registerAssertionRoutes } from "../routes/assertion-routes";
import type { registerAuthRoutes } from "../routes/auth-routes";
import type { registerBadgeRuleRoutes } from "../routes/badge-rule-routes";
import type { registerBadgeTemplateImageRoutes } from "../routes/badge-template-image-routes";
import type { registerBootstrapAdminRoutes } from "../routes/bootstrap-admin-routes";
import type { registerCredentialRoutes } from "../routes/credential-routes";
import type { registerDidRoutes } from "../routes/did-routes";
import type { registerExecutiveRoutes } from "../routes/executive-routes";
import type { registerGoogleAuthRoutes } from "../routes/google-auth-routes";
import type { registerHealthRoutes } from "../routes/health-routes";
import type { registerLearnerRecordExportRoutes } from "../routes/learner-record-export-routes";
import type { registerLearnerRecordRoutes } from "../routes/learner-record-routes";
import type { registerLearnerRoutes } from "../routes/learner-routes";
import type { registerLtiRoutes } from "../routes/lti-routes";
import type { registerMigrationRoutes } from "../routes/migration-routes";
import type { registerOb3Routes } from "../routes/ob3-routes";
import type { registerOid4vciRoutes } from "../routes/oid4vci-routes";
import type { registerPresentationRoutes } from "../routes/presentation-routes";
import type { registerPublicBadgeRoutes } from "../routes/public-badge-routes";
import type { registerQueueRoutes } from "../routes/queue-routes";
import type { registerReportingRoutes } from "../routes/reporting-routes";
import type { registerSigningRoutes } from "../routes/signing-routes";
import type { registerTenantGovernanceRoutes } from "../routes/tenant-governance-routes";
import type { registerTenantLmsConnectionRoutes } from "../routes/tenant-lms-connection-routes";
import type { registerCommonMiddleware } from "../http/common-middleware";

export type AppDeps = Omit<Parameters<typeof registerCommonMiddleware>[0], "app"> &
  Omit<Parameters<typeof registerGoogleAuthRoutes>[0], "app"> &
  Omit<Parameters<typeof registerHealthRoutes>[0], "app"> &
  Omit<Parameters<typeof registerBootstrapAdminRoutes>[0], "app"> &
  Omit<Parameters<typeof registerOb3Routes>[0], "app"> &
  Omit<Parameters<typeof registerDidRoutes>[0], "app"> &
  Omit<Parameters<typeof registerCredentialRoutes<AssertionRecord, JsonObject>>[0], "app"> &
  Omit<Parameters<typeof registerOid4vciRoutes>[0], "app"> &
  Omit<Parameters<typeof registerPresentationRoutes>[0], "app"> &
  Omit<Parameters<typeof registerPublicBadgeRoutes<PublicBadgeViewModel>>[0], "app"> &
  Omit<Parameters<typeof registerLearnerRoutes<LearnerDidSettingsNotice | null>>[0], "app"> &
  Omit<Parameters<typeof registerLearnerRecordRoutes>[0], "app"> &
  Omit<Parameters<typeof registerLearnerRecordExportRoutes>[0], "app"> &
  Omit<Parameters<typeof registerLtiRoutes>[0], "app"> &
  Omit<Parameters<typeof registerMigrationRoutes>[0], "app"> &
  Omit<Parameters<typeof registerAuthRoutes>[0], "app"> &
  Omit<Parameters<typeof registerReportingRoutes>[0], "app"> &
  Omit<Parameters<typeof registerExecutiveRoutes>[0], "app"> &
  Omit<Parameters<typeof registerTenantGovernanceRoutes>[0], "app"> &
  Omit<Parameters<typeof registerBadgeTemplateImageRoutes>[0], "app"> &
  Omit<Parameters<typeof registerTenantLmsConnectionRoutes>[0], "app"> &
  Omit<Parameters<typeof registerBadgeRuleRoutes>[0], "app"> &
  Omit<Parameters<typeof registerAssertionRoutes>[0], "app"> &
  Omit<Parameters<typeof registerSigningRoutes>[0], "app"> &
  Omit<Parameters<typeof registerQueueRoutes>[0], "app">;
