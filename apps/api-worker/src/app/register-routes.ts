import type { JsonObject } from "@credtrail/core-domain";
import type { AssertionRecord } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppBindings, AppEnv } from "./types";
import type { VerificationViewModel } from "../badges/public-badge-model";
import type { LearnerDidSettingsNotice } from "../learner/pages";
import { registerCommonMiddleware } from "../http/common-middleware";
import { registerAppPageRenderer } from "../ui/render-page";
import { registerAssertionRoutes } from "../routes/assertion-routes";
import { registerAuthRoutes } from "../routes/auth-routes";
import { registerBootstrapAdminRoutes } from "../routes/bootstrap-admin-routes";
import { registerBadgeTemplateImageRoutes } from "../routes/badge-template-image-routes";
import { registerBadgeRuleRoutes } from "../routes/badge-rule-routes";
import { registerCredentialRoutes } from "../routes/credential-routes";
import { registerDesignSystemRoutes } from "../routes/design-system-routes";
import { registerDidRoutes } from "../routes/did-routes";
import { registerLearnerRoutes } from "../routes/learner-routes";
import { registerLearnerRecordExportRoutes } from "../routes/learner-record-export-routes";
import { registerLearnerRecordRoutes } from "../routes/learner-record-routes";
import { registerLtiRoutes } from "../routes/lti-routes";
import { registerMigrationRoutes } from "../routes/migration-routes";
import { registerOb3Routes } from "../routes/ob3-routes";
import { registerPresentationRoutes } from "../routes/presentation-routes";
import { registerPublicBadgeRoutes } from "../routes/public-badge-routes";
import { registerQueueRoutes } from "../routes/queue-routes";
import { registerGoogleAuthRoutes } from "../routes/google-auth-routes";
import { registerHealthRoutes } from "../routes/health-routes";
import { registerExecutiveRoutes } from "../routes/executive-routes";
import { registerReportingRoutes } from "../routes/reporting-routes";
import { registerSigningRoutes } from "../routes/signing-routes";
import { registerTenantGovernanceRoutes } from "../routes/tenant-governance-routes";
import { registerTenantLmsConnectionRoutes } from "../routes/tenant-lms-connection-routes";
import { registerOid4vciRoutes } from "../routes/oid4vci-routes";

type RegisterRoutesInput = {
  app: Hono<AppEnv>;
} & Omit<Parameters<typeof registerCommonMiddleware>[0], "app"> &
  Omit<Parameters<typeof registerGoogleAuthRoutes>[0], "app"> &
  Omit<Parameters<typeof registerHealthRoutes>[0], "app"> &
  Omit<Parameters<typeof registerBootstrapAdminRoutes>[0], "app"> &
  Omit<Parameters<typeof registerOb3Routes>[0], "app"> &
  Omit<Parameters<typeof registerDidRoutes>[0], "app"> &
  Omit<Parameters<typeof registerCredentialRoutes<AssertionRecord, JsonObject>>[0], "app"> &
  Omit<Parameters<typeof registerOid4vciRoutes>[0], "app"> &
  Omit<Parameters<typeof registerPresentationRoutes>[0], "app"> &
  Omit<Parameters<typeof registerPublicBadgeRoutes<VerificationViewModel>>[0], "app"> &
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

export const registerRoutes = (input: RegisterRoutesInput): void => {
  registerCommonMiddleware({
    app: input.app,
    observabilityContext: input.observabilityContext,
  });

  registerAppPageRenderer(input.app);

  registerGoogleAuthRoutes(input);
  registerDesignSystemRoutes(input);

  registerHealthRoutes({
    app: input.app,
    observabilityContext: input.observabilityContext,
    resolveDatabase: input.resolveDatabase,
    serviceName: input.serviceName,
    storageReadinessProbeKey: input.storageReadinessProbeKey,
  });

  registerBootstrapAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
  });

  registerOb3Routes(input);
  registerDidRoutes(input);
  registerCredentialRoutes(input);
  registerOid4vciRoutes(input);
  registerPresentationRoutes(input);
  registerPublicBadgeRoutes(input);
  registerLearnerRoutes(input);
  registerLearnerRecordRoutes(input);
  registerLearnerRecordExportRoutes(input);
  registerLtiRoutes(input);
  registerMigrationRoutes(input);
  registerAuthRoutes(input);
  registerReportingRoutes(input);
  registerExecutiveRoutes(input);
  registerTenantGovernanceRoutes(input);
  registerBadgeTemplateImageRoutes(input);
  registerTenantLmsConnectionRoutes(input);
  registerBadgeRuleRoutes(input);
  registerAssertionRoutes(input);
  registerSigningRoutes(input);
  registerQueueRoutes(input);
};

export type RegisterRoutesBindings = AppBindings;
