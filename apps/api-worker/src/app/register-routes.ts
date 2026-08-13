import type { Hono } from "hono";
import type { AppEnv } from "./types";
import type { AppDeps } from "./app-deps";
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

interface RegisterRoutesInput {
  app: Hono<AppEnv>;
  deps: AppDeps;
}

export const registerRoutes = (input: RegisterRoutesInput): void => {
  const routeInput = {
    app: input.app,
    ...input.deps,
  };

  registerCommonMiddleware({
    app: input.app,
    observabilityContext: input.deps.observabilityContext,
  });

  registerAppPageRenderer(input.app);

  registerGoogleAuthRoutes(routeInput);
  registerDesignSystemRoutes(routeInput);

  registerHealthRoutes({
    app: input.app,
    observabilityContext: input.deps.observabilityContext,
    resolveDatabase: input.deps.resolveDatabase,
    serviceName: input.deps.serviceName,
    storageReadinessProbeKey: input.deps.storageReadinessProbeKey,
  });

  registerBootstrapAdminRoutes({
    app: input.app,
    resolveDatabase: input.deps.resolveDatabase,
  });

  registerOb3Routes(routeInput);
  registerDidRoutes(routeInput);
  registerCredentialRoutes(routeInput);
  registerOid4vciRoutes(routeInput);
  registerPresentationRoutes(routeInput);
  registerPublicBadgeRoutes(routeInput);
  registerLearnerRoutes(routeInput);
  registerLearnerRecordRoutes(routeInput);
  registerLearnerRecordExportRoutes(routeInput);
  registerLtiRoutes(routeInput);
  registerMigrationRoutes(routeInput);
  registerAuthRoutes(routeInput);
  registerReportingRoutes(routeInput);
  registerExecutiveRoutes(routeInput);
  registerTenantGovernanceRoutes(routeInput);
  registerBadgeTemplateImageRoutes(routeInput);
  registerTenantLmsConnectionRoutes(routeInput);
  registerBadgeRuleRoutes(routeInput);
  registerAssertionRoutes(routeInput);
  registerSigningRoutes(routeInput);
  registerQueueRoutes(routeInput);
};
