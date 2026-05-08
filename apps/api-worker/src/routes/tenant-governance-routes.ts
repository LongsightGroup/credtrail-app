import {
  countTenantMembershipsByRole,
  createTenantAuthProvider,
  createTenantApiKey,
  createAuditLog,
  createDelegatedIssuingAuthorityGrant,
  ensureTenantMembership,
  createTenantOrgUnit,
  deleteTenantAuthProvider,
  deleteTenantSsoSamlConfiguration,
  findActiveTenantBreakGlassAccountByUserId,
  findDelegatedIssuingAuthorityGrantById,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  findTenantAuthPolicy,
  findTenantAuthProviderById,
  findTenantById,
  findTenantMembership,
  getTenantReportingEngagementCounts,
  getTenantReportingOverview,
  getTenantReportingTrends,
  findUserById,
  listAccessibleTenantContextsForUser,
  listImportLearnerRecordBatchQueueMessages,
  listTenantAuthProviders,
  findTenantSsoSamlConfiguration,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  listBadgeTemplates,
  listTenantApiKeys,
  listTenantReportingComparisons,
  listDelegatedIssuingAuthorityGrantEvents,
  listDelegatedIssuingAuthorityGrants,
  listTenantBreakGlassAccounts,
  listTenantMembers,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  removeTenantMembership,
  removeTenantMembershipOrgUnitScope,
  revokeTenantApiKey,
  revokeTenantBreakGlassAccount,
  revokeDelegatedIssuingAuthorityGrant,
  retryFailedImportLearnerRecordBatchQueueMessages,
  resolveTenantAuthPolicy,
  HOSTED_ENTERPRISE_OIDC_ONLY_ERROR,
  isHostedEnterpriseAuthProviderSupported,
  updateTenantAuthProvider,
  upsertTenantBreakGlassAccount,
  upsertTenantAuthPolicy,
  upsertTenantMembershipRole,
  upsertTenantMembershipOrgUnitScope,
  upsertUserByEmail,
  type LearnerRecordTrustLevel,
  type SessionRecord,
  type SqlDatabase,
  type TenantReportingLifecycleFilter,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { Hono } from "hono";
import {
  parseAdminLearnerRecordReviewQuery,
  parseCreateTenantApiKeyRequest,
  parseCreateTenantBreakGlassAccountRequest,
  parseCreateTenantMemberRequest,
  parseLearnerRecordImportBatchPathParams,
  parseLearnerRecordImportBatchDefaults,
  parseTenantMemberPathParams,
  parseTenantAuthProviderPathParams,
  parseCreateDelegatedIssuingAuthorityGrantRequest,
  parseRevokeTenantApiKeyRequest,
  parseCreateTenantOrgUnitRequest,
  parseDelegatedIssuingAuthorityGrantListQuery,
  parseTenantApiKeyListQuery,
  parseTenantApiKeyPathParams,
  parseRevokeDelegatedIssuingAuthorityGrantRequest,
  parseUpsertTenantAuthPolicyRequest,
  parseUpsertTenantAuthProviderRequest,
  parseUpsertTenantSsoSamlConfigurationRequest,
  parseTenantOrgUnitListQuery,
  parseTenantPathParams,
  parseTenantReportingOverviewQuery,
  parseTenantUserDelegatedGrantPathParams,
  parseTenantUserOrgUnitPathParams,
  parseTenantUserPathParams,
  parseUpdateTenantMemberRoleRequest,
  parseUpsertTenantMembershipOrgUnitScopeRequest,
} from "@credtrail/validation";
import { renderPageShell } from "@credtrail/ui-components";
import type { AppBindings, AppContext, AppEnv } from "../app";
import {
  institutionAdminAccessPage,
  institutionAdminApiKeysPage,
  institutionAdminBadgeStatusPage,
  institutionAdminDashboardPage,
  institutionAdminGovernancePage,
  institutionAdminIssuedBadgesPage,
  institutionAdminLearnerRecordImportsPage,
  institutionAdminLearnerRecordsPage,
  institutionAdminMembersPage,
  institutionAdminOperationsReviewQueuePage,
  institutionAdminOperationsPage,
  institutionAdminOrgUnitsPage,
  institutionAdminReportingPage,
  institutionAdminRulesPage,
} from "../admin/institution-admin-page";
import { institutionAdminRuleBuilderPage } from "../admin/institution-admin-rule-builder-page";
import { buildLocalTwoFactorPath } from "../auth/break-glass-policy";
import { resolveTenantReportingAccess } from "../auth/tenant-access";
import {
  enqueueLearnerRecordImportBatch,
  prepareLearnerRecordImportSubmission,
  summarizeLearnerRecordImportProgress,
} from "../learner-record/learner-record-import";
import { buildReportingMetricEntries } from "../reporting/metric-definitions";
import { createLearnerRecordPresentation } from "../learner-record/learner-record-presentation";
import { loadLearnerRecordExportBundle } from "../learner-record/learner-record-export";
import {
  toReportingComparisonFilters,
  toReportingEngagementFilters,
  toReportingOverviewFilters,
  toReportingTrendFilters,
} from "../reporting/reporting-page-filters";
import { buildOrganizationsPath } from "../auth/tenant-context-selection";

interface RegisterTenantGovernanceRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requestTenantMemberInvite?: (
    c: AppContext,
    input: {
      tenantId: string;
      email: string;
      role: TenantMembershipRole;
    },
  ) => Promise<{
    deliveryStatus: "sent" | "skipped" | "failed";
    inviteKind: "magic_link" | "sso_notice";
  }>;
  requestBreakGlassPasswordReset?: (
    c: AppContext,
    input: {
      tenantId: string;
      email: string;
    },
  ) => Promise<"sent" | "unavailable">;
  generateOpaqueToken: () => string;
  sha256Hex: (value: string) => Promise<string>;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

export const registerTenantGovernanceRoutes = (
  input: RegisterTenantGovernanceRoutesInput,
): void => {
  const {
    app,
    resolveDatabase,
    requestTenantMemberInvite,
    requestBreakGlassPasswordReset,
    generateOpaqueToken,
    sha256Hex,
    requireTenantRole,
    ADMIN_ROLES,
    ISSUER_ROLES,
  } = input;

  type InstitutionAdminPageData = Parameters<typeof institutionAdminDashboardPage>[0];
  type ReportingComparisonRow = Awaited<ReturnType<typeof listTenantReportingComparisons>>[number];
  type BadgeTemplateRecord = InstitutionAdminPageData["badgeTemplates"][number];
  type LearnerRecordImportWorkflowInput = Pick<
    NonNullable<InstitutionAdminPageData["learnerRecordImportWorkflow"]>,
    "defaults" | "submission" | "feedback"
  >;

  const requireEnterpriseTenant = async (
    c: AppContext,
    tenantId: string,
    db: SqlDatabase,
  ): Promise<Response | null> => {
    const tenant = await findTenantById(db, tenantId);

    if (tenant === null) {
      return c.json(
        {
          error: "Tenant not found",
        },
        404,
      );
    }

    if (tenant.planTier !== "enterprise") {
      return c.json(
        {
          error: "Feature requires enterprise tenant plan",
        },
        403,
      );
    }

    return null;
  };

  const LEGACY_SAML_DEPRECATED_ERROR =
    "Legacy SAML configuration is deprecated for hosted enterprise sign-in. Configure an OIDC provider instead.";
  const LEGACY_SAML_COMPATIBILITY_NOTICE =
    "Legacy SAML compatibility remains visible for cleanup only. Configure an OIDC provider for hosted enterprise sign-in.";
  const LEGACY_SAML_EDIT_BLOCKED_ERROR =
    "Legacy SAML compatibility entries are not editable from the supported enterprise auth workflow. Configure a new OIDC provider instead or delete the legacy entry.";
  const LEGACY_SAML_DEFAULT_PROVIDER_ERROR =
    "Default enterprise provider must be an OIDC provider. Legacy SAML compatibility entries cannot be selected.";

  const canManageTenantRole = (
    actorRole: TenantMembershipRole,
    targetRole: TenantMembershipRole,
  ): boolean => {
    return actorRole === "owner" || targetRole !== "owner";
  };

  const memberInviteSkipped = {
    deliveryStatus: "skipped" as const,
    inviteKind: "magic_link" as const,
  };

  const requestInviteForTenantMember = async (
    c: AppContext,
    input: {
      tenantId: string;
      email: string;
      role: TenantMembershipRole;
      sendInvite: boolean;
    },
  ): Promise<{
    deliveryStatus: "sent" | "skipped" | "failed";
    inviteKind: "magic_link" | "sso_notice";
  }> => {
    if (!input.sendInvite || requestTenantMemberInvite === undefined) {
      return memberInviteSkipped;
    }

    return requestTenantMemberInvite(c, {
      tenantId: input.tenantId,
      email: input.email,
      role: input.role,
    });
  };

  const assertRoleChangeAllowed = async (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      actorUserId: string;
      actorRole: TenantMembershipRole;
      targetUserId: string;
      previousRole: TenantMembershipRole | null;
      nextRole: TenantMembershipRole;
    },
  ): Promise<Response | null> => {
    if (!canManageTenantRole(input.actorRole, input.nextRole)) {
      return c.json(
        {
          error: "Only tenant owners can assign the owner role.",
        },
        403,
      );
    }

    if (input.previousRole === "owner" && input.actorRole !== "owner") {
      return c.json(
        {
          error: "Only tenant owners can change an owner membership.",
        },
        403,
      );
    }

    if (
      input.targetUserId === input.actorUserId &&
      (input.previousRole === "owner" || input.previousRole === "admin") &&
      input.nextRole !== input.previousRole
    ) {
      return c.json(
        {
          error: "You cannot change your own tenant admin role.",
        },
        409,
      );
    }

    if (input.previousRole === "owner" && input.nextRole !== "owner") {
      const counts = await countTenantMembershipsByRole(input.db, input.tenantId);

      if (counts.owner <= 1) {
        return c.json(
          {
            error: "At least one tenant owner must remain.",
          },
          409,
        );
      }
    }

    return null;
  };

  const membershipAuditAction = (
    previousRole: TenantMembershipRole | null,
    nextRole: TenantMembershipRole,
  ): "membership.role_assigned" | "membership.role_changed" | "membership.role_reasserted" => {
    if (previousRole === null) {
      return "membership.role_assigned";
    }

    return previousRole === nextRole ? "membership.role_reasserted" : "membership.role_changed";
  };

  const serializeTenantAuthPolicy = (
    policy: Awaited<ReturnType<typeof resolveTenantAuthPolicy>>,
  ): Record<string, unknown> => {
    return {
      tenantId: policy.tenantId,
      loginMode: policy.loginMode,
      breakGlassEnabled: policy.breakGlassEnabled,
      localMfaRequired: policy.localMfaRequired,
      defaultProviderId: policy.defaultProviderId,
      createdAt: policy.createdAt,
      updatedAt: policy.updatedAt,
    };
  };

  const serializeTenantAuthProvider = (
    provider: Awaited<ReturnType<typeof listTenantAuthProviders>>[number],
  ): Record<string, unknown> => {
    const compatibilityOnly = !isHostedEnterpriseAuthProviderSupported(provider);

    return {
      id: provider.id,
      tenantId: provider.tenantId,
      protocol: provider.protocol,
      label: provider.label,
      enabled: provider.enabled,
      isDefault: provider.isDefault,
      configJson: provider.configJson,
      createdAt: provider.createdAt,
      updatedAt: provider.updatedAt,
      supportedInHostedRuntime: !compatibilityOnly,
      compatibilityOnly,
      ...(compatibilityOnly ? { notice: LEGACY_SAML_COMPATIBILITY_NOTICE } : {}),
    };
  };

  const adminRoleRequiredPage = (tenantId: string): string => {
    return renderPageShell(
      "Admin access required",
      `<section style="display:grid;gap:0.9rem;max-width:44rem;">
        <article style="display:grid;gap:0.6rem;padding:1.15rem;border:1px solid rgba(0,39,76,0.17);border-radius:1rem;background:linear-gradient(165deg,rgba(255,255,255,0.96),rgba(248,252,255,0.93));box-shadow:0 14px 24px rgba(0,39,76,0.14);">
          <p style="margin:0;font-size:0.78rem;letter-spacing:0.1em;text-transform:uppercase;color:#0a4c8f;font-weight:700;">Institution Admin</p>
          <h1 style="margin:0;">Admin role required</h1>
          <p style="margin:0;color:#355577;">
            Your current tenant membership role does not allow institution admin access for
            <strong>${tenantId}</strong>.
          </p>
          <p style="margin:0;color:#355577;">
            Ask an existing tenant admin/owner to grant your account an admin role, then retry.
          </p>
          <p style="margin:0;">
            <a href="/showcase/${encodeURIComponent(tenantId)}">View public badge showcase</a>
          </p>
        </article>
      </section>`,
    );
  };

  const reportingAccessRequiredPage = (tenantId: string): string => {
    return renderPageShell(
      "Reporting access required",
      `<section style="display:grid;gap:0.9rem;max-width:44rem;">
        <article style="display:grid;gap:0.6rem;padding:1.15rem;border:1px solid rgba(0,39,76,0.17);border-radius:1rem;background:linear-gradient(165deg,rgba(255,255,255,0.96),rgba(248,252,255,0.93));box-shadow:0 14px 24px rgba(0,39,76,0.14);">
          <p style="margin:0;font-size:0.78rem;letter-spacing:0.1em;text-transform:uppercase;color:#0a4c8f;font-weight:700;">Reporting</p>
          <h1 style="margin:0;">Reporting access required</h1>
          <p style="margin:0;color:#355577;">
            Your current tenant membership does not allow reporting access for
            <strong>${tenantId}</strong>.
          </p>
          <p style="margin:0;color:#355577;">
            Ask a tenant admin to grant reporting scope or a broader reporting role, then retry.
          </p>
        </article>
      </section>`,
    );
  };

  const getOptionalFormValue = (formData: FormData, name: string): string | undefined => {
    const value = formData.get(name);

    if (typeof value !== "string") {
      return undefined;
    }

    const trimmed = value.trim();
    return trimmed.length === 0 ? undefined : trimmed;
  };

  const buildOrgUnitMap = (orgUnits: InstitutionAdminPageData["orgUnits"]) => {
    return new Map(orgUnits.map((orgUnit) => [orgUnit.id, orgUnit] as const));
  };

  const isOrgUnitWithinRoot = (
    orgUnitsById: ReadonlyMap<string, InstitutionAdminPageData["orgUnits"][number]>,
    orgUnitId: string,
    rootOrgUnitId: string,
  ): boolean => {
    const visited = new Set<string>();
    let currentOrgUnitId: string | null = orgUnitId;

    while (currentOrgUnitId !== null) {
      if (currentOrgUnitId === rootOrgUnitId) {
        return true;
      }

      if (visited.has(currentOrgUnitId)) {
        return false;
      }

      visited.add(currentOrgUnitId);
      currentOrgUnitId = orgUnitsById.get(currentOrgUnitId)?.parentOrgUnitId ?? null;
    }

    return false;
  };

  const isOrgUnitWithinRoots = (
    orgUnitsById: ReadonlyMap<string, InstitutionAdminPageData["orgUnits"][number]>,
    orgUnitId: string,
    rootOrgUnitIds: readonly string[],
  ): boolean => {
    return rootOrgUnitIds.some((rootOrgUnitId) =>
      isOrgUnitWithinRoot(orgUnitsById, orgUnitId, rootOrgUnitId),
    );
  };

  const filterOrgUnitsToScope = (
    orgUnits: InstitutionAdminPageData["orgUnits"],
    orgUnitsById: ReadonlyMap<string, InstitutionAdminPageData["orgUnits"][number]>,
    scopedRootOrgUnitIds: readonly string[],
  ) => {
    return orgUnits.filter((orgUnit) =>
      isOrgUnitWithinRoots(orgUnitsById, orgUnit.id, scopedRootOrgUnitIds),
    );
  };

  const filterComparisonRowsToScope = (
    comparisonRows: readonly ReportingComparisonRow[],
    orgUnitsById: ReadonlyMap<string, InstitutionAdminPageData["orgUnits"][number]>,
    scopedRootOrgUnitIds: readonly string[],
  ): ReportingComparisonRow[] => {
    return comparisonRows.filter((row) =>
      isOrgUnitWithinRoots(orgUnitsById, row.groupId, scopedRootOrgUnitIds),
    );
  };

  const filterBadgeTemplatesToIds = (
    badgeTemplates: readonly BadgeTemplateRecord[],
    allowedBadgeTemplateIds: ReadonlySet<string>,
  ): BadgeTemplateRecord[] => {
    return badgeTemplates.filter((badgeTemplate) => allowedBadgeTemplateIds.has(badgeTemplate.id));
  };

  const redirectToTenantLogin = (c: AppContext, tenantId: string, nextPath: string): Response => {
    const loginUrl = new URL("/login", c.req.url);
    loginUrl.searchParams.set("tenantId", tenantId);
    loginUrl.searchParams.set("next", nextPath);
    loginUrl.searchParams.set("reason", "auth_required");
    return c.redirect(`${loginUrl.pathname}${loginUrl.search}`, 302);
  };

  const loadInstitutionAdminPageData = async (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
  ): Promise<InstitutionAdminPageData | Response> => {
    const db = resolveDatabase(c.env);
    const tenant = await findTenantById(db, tenantId);

    if (tenant === null) {
      return c.json(
        {
          error: "Tenant not found",
        },
        404,
      );
    }

    const [
      currentUser,
      badgeTemplates,
      orgUnits,
      membershipOrgUnitScopes,
      tenantMembers,
      delegatedIssuingAuthorityGrants,
      apiKeys,
      badgeRules,
      authPolicy,
      authProviders,
      breakGlassAccounts,
    ] = await Promise.all([
      findUserById(db, sessionUserId),
      listBadgeTemplates(db, {
        tenantId,
        includeArchived: false,
      }),
      listTenantOrgUnits(db, {
        tenantId,
        includeInactive: true,
      }),
      listTenantMembershipOrgUnitScopes(db, {
        tenantId,
      }),
      listTenantMembers(db, tenantId),
      listDelegatedIssuingAuthorityGrants(db, {
        tenantId,
        includeRevoked: true,
        includeExpired: true,
      }),
      listTenantApiKeys(db, {
        tenantId,
        includeRevoked: true,
      }),
      listBadgeIssuanceRules(db, {
        tenantId,
      }),
      tenant.planTier === "enterprise" ? findTenantAuthPolicy(db, tenantId) : Promise.resolve(null),
      tenant.planTier === "enterprise"
        ? listTenantAuthProviders(db, tenantId)
        : Promise.resolve([]),
      tenant.planTier === "enterprise"
        ? listTenantBreakGlassAccounts(db, tenantId)
        : Promise.resolve([]),
    ]);

    const badgeRuleVersionLists = await Promise.all(
      badgeRules.map(async (rule) =>
        listBadgeIssuanceRuleVersions(db, {
          tenantId,
          ruleId: rule.id,
        }),
      ),
    );
    const badgeRuleVersions = badgeRuleVersionLists.flat();
    const activeApiKeys = apiKeys.filter((apiKey) => apiKey.revokedAt === null);
    const revokedApiKeyCount = apiKeys.length - activeApiKeys.length;
    const accessibleTenantContexts = await listAccessibleTenantContextsForUser(db, sessionUserId);
    const requestUrl = new URL(c.req.url);
    const switchOrganizationPath =
      accessibleTenantContexts.length > 1
        ? buildOrganizationsPath(`${requestUrl.pathname}${requestUrl.search}`)
        : null;

    return {
      tenant,
      userId: sessionUserId,
      ...(currentUser?.email === undefined ? {} : { userEmail: currentUser.email }),
      membershipRole,
      badgeTemplates,
      orgUnits,
      membershipOrgUnitScopes,
      tenantMembers,
      delegatedIssuingAuthorityGrants,
      activeApiKeys,
      revokedApiKeyCount,
      badgeRules,
      badgeRuleVersions,
      enterpriseAuthPolicy: authPolicy,
      enterpriseAuthProviders: authProviders,
      breakGlassAccounts,
      switchOrganizationPath,
    };
  };

  const loadLearnerRecordReviewPageData = async (input: {
    c: AppContext;
    tenantId: string;
    sessionUserId: string;
    membershipRole: TenantMembershipRole;
    learnerProfileId?: string;
    email?: string;
  }): Promise<InstitutionAdminPageData | Response> => {
    const pageData = await loadInstitutionAdminPageData(
      input.c,
      input.tenantId,
      input.sessionUserId,
      input.membershipRole,
    );

    if (pageData instanceof Response) {
      return pageData;
    }

    if (input.learnerProfileId === undefined && input.email === undefined) {
      return {
        ...pageData,
        learnerRecordReview: {
          lookup: {},
          learnerProfile: null,
          presentation: null,
          exportPath: null,
          standardsMappingPath: null,
          lookupState: "idle",
        },
      };
    }

    const db = resolveDatabase(input.c.env);
    const learnerProfile =
      input.learnerProfileId !== undefined
        ? await findLearnerProfileById(db, input.tenantId, input.learnerProfileId)
        : await findLearnerProfileByIdentity(db, {
            tenantId: input.tenantId,
            identityType: "email",
            identityValue: input.email!,
          });

    if (learnerProfile === null) {
      return {
        ...pageData,
        learnerRecordReview: {
          lookup: {
            ...(input.learnerProfileId === undefined
              ? {}
              : { learnerProfileId: input.learnerProfileId }),
            ...(input.email === undefined ? {} : { email: input.email }),
          },
          learnerProfile: null,
          presentation: null,
          exportPath: null,
          standardsMappingPath: null,
          lookupState: "unresolved",
        },
      };
    }

    const bundle = await loadLearnerRecordExportBundle(db, {
      tenantId: input.tenantId,
      learnerProfileId: learnerProfile.id,
    });

    if (bundle === null) {
      return {
        ...pageData,
        learnerRecordReview: {
          lookup: {
            ...(input.learnerProfileId === undefined
              ? {}
              : { learnerProfileId: input.learnerProfileId }),
            ...(input.email === undefined ? {} : { email: input.email }),
          },
          learnerProfile: null,
          presentation: null,
          exportPath: null,
          standardsMappingPath: null,
          lookupState: "unresolved",
        },
      };
    }

    const encodedLearnerProfileId = encodeURIComponent(learnerProfile.id);

    return {
      ...pageData,
      learnerRecordReview: {
        lookup: {
          ...(input.learnerProfileId === undefined
            ? {}
            : { learnerProfileId: input.learnerProfileId }),
          ...(input.email === undefined ? {} : { email: input.email }),
        },
        learnerProfile: {
          id: learnerProfile.id,
          displayName: learnerProfile.displayName,
          subjectId: learnerProfile.subjectId,
        },
        presentation: createLearnerRecordPresentation(bundle),
        exportPath: `/v1/tenants/${encodeURIComponent(input.tenantId)}/learner-records/${encodedLearnerProfileId}/export?profile=native_portable_json`,
        standardsMappingPath: `/v1/tenants/${encodeURIComponent(input.tenantId)}/learner-records/${encodedLearnerProfileId}/standards-mapping?profile=clr_alignment_json`,
        lookupState: "loaded",
      },
    };
  };

  const loadLearnerRecordImportPageData = async (input: {
    c: AppContext;
    tenantId: string;
    sessionUserId: string;
    membershipRole: TenantMembershipRole;
    workflow?: LearnerRecordImportWorkflowInput;
  }): Promise<InstitutionAdminPageData | Response> => {
    const pageData = await loadInstitutionAdminPageData(
      input.c,
      input.tenantId,
      input.sessionUserId,
      input.membershipRole,
    );

    if (pageData instanceof Response) {
      return pageData;
    }

    const progress = summarizeLearnerRecordImportProgress(
      await listImportLearnerRecordBatchQueueMessages(resolveDatabase(input.c.env), {
        tenantId: input.tenantId,
        limit: 100,
      }),
    );

    return {
      ...pageData,
      learnerRecordImportWorkflow: {
        templatePath: `/v1/tenants/${encodeURIComponent(input.tenantId)}/learner-record-imports/template.csv`,
        previewPath: `/tenants/${encodeURIComponent(input.tenantId)}/admin/operations/learner-record-imports/preview`,
        applyPath: `/tenants/${encodeURIComponent(input.tenantId)}/admin/operations/learner-record-imports/apply`,
        defaults: input.workflow?.defaults ?? {
          defaultTrustLevel: "issuer_verified" as LearnerRecordTrustLevel,
          defaultIssuerName: "",
        },
        submission: input.workflow?.submission ?? null,
        feedback: input.workflow?.feedback ?? null,
        progress,
      },
    };
  };

  const loadReportingPageData = async (input: {
    c: AppContext;
    tenantId: string;
    sessionUserId: string;
    membershipRole: TenantMembershipRole;
    issuedFrom?: string | undefined;
    issuedTo?: string | undefined;
    badgeTemplateId?: string | undefined;
    orgUnitId?: string | undefined;
    state?: TenantReportingLifecycleFilter | undefined;
  }): Promise<InstitutionAdminPageData | Response> => {
    if (input.membershipRole === "owner" || input.membershipRole === "admin") {
      return loadInstitutionAdminPageData(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
      );
    }

    const db = resolveDatabase(input.c.env);
    const reportingAccess = await resolveTenantReportingAccess({
      db,
      tenantId: input.tenantId,
      userId: input.sessionUserId,
      membershipRole: input.membershipRole,
    });

    if (reportingAccess === null) {
      input.c.header("Cache-Control", "no-store");
      return input.c.html(reportingAccessRequiredPage(input.tenantId), 403);
    }

    const [
      tenant,
      currentUser,
      badgeTemplates,
      orgUnits,
      membershipOrgUnitScopes,
      accessibleTenantContexts,
    ] = await Promise.all([
      findTenantById(db, input.tenantId),
      findUserById(db, input.sessionUserId),
      listBadgeTemplates(db, {
        tenantId: input.tenantId,
        includeArchived: false,
      }),
      listTenantOrgUnits(db, {
        tenantId: input.tenantId,
        includeInactive: true,
      }),
      listTenantMembershipOrgUnitScopes(db, {
        tenantId: input.tenantId,
        userId: input.sessionUserId,
      }),
      listAccessibleTenantContextsForUser(db, input.sessionUserId),
    ]);

    if (tenant === null) {
      return input.c.json(
        {
          error: "Tenant not found",
        },
        404,
      );
    }

    const requestUrl = new URL(input.c.req.url);
    const switchOrganizationPath =
      accessibleTenantContexts.length > 1
        ? buildOrganizationsPath(`${requestUrl.pathname}${requestUrl.search}`)
        : null;
    const orgUnitsById = buildOrgUnitMap(orgUnits);
    const scopedRootOrgUnitIds =
      reportingAccess.visibility === "scoped" ? reportingAccess.scopedOrgUnitIds : [];

    if (
      input.orgUnitId !== undefined &&
      scopedRootOrgUnitIds.length > 0 &&
      !isOrgUnitWithinRoots(orgUnitsById, input.orgUnitId, scopedRootOrgUnitIds)
    ) {
      input.c.header("Cache-Control", "no-store");
      return input.c.html(reportingAccessRequiredPage(input.tenantId), 403);
    }

    const reportingOrgUnitComparisonsRaw = await listTenantReportingComparisons(db, {
      tenantId: input.tenantId,
      ...toReportingComparisonFilters(
        {
          issuedFrom: input.issuedFrom,
          issuedTo: input.issuedTo,
          badgeTemplateId: input.badgeTemplateId,
          state: input.state,
        },
        "orgUnit",
      ),
      groupBy: "orgUnit",
    });
    const reportingOrgUnitComparisons =
      scopedRootOrgUnitIds.length === 0
        ? reportingOrgUnitComparisonsRaw
        : filterComparisonRowsToScope(
            reportingOrgUnitComparisonsRaw,
            orgUnitsById,
            scopedRootOrgUnitIds,
          );
    const selectedOrgUnitId =
      input.orgUnitId ??
      (scopedRootOrgUnitIds.length === 0
        ? undefined
        : (reportingOrgUnitComparisons[0]?.groupId ?? scopedRootOrgUnitIds[0]));
    const reportingPageFilters = {
      issuedFrom: input.issuedFrom,
      issuedTo: input.issuedTo,
      badgeTemplateId: input.badgeTemplateId,
      orgUnitId: selectedOrgUnitId,
      state: input.state,
    };
    const [
      reportingOverview,
      reportingEngagementCounts,
      reportingTrends,
      reportingTemplateComparisons,
    ] = await Promise.all([
      getTenantReportingOverview(db, {
        tenantId: input.tenantId,
        ...toReportingOverviewFilters(reportingPageFilters),
      }),
      getTenantReportingEngagementCounts(db, {
        tenantId: input.tenantId,
        ...toReportingEngagementFilters(reportingPageFilters),
      }),
      getTenantReportingTrends(db, {
        tenantId: input.tenantId,
        ...toReportingTrendFilters(reportingPageFilters),
      }),
      listTenantReportingComparisons(db, {
        tenantId: input.tenantId,
        ...toReportingComparisonFilters(reportingPageFilters, "badgeTemplate"),
      }),
    ]);
    const visibleBadgeTemplateIds = new Set(reportingTemplateComparisons.map((row) => row.groupId));

    if (input.badgeTemplateId !== undefined) {
      visibleBadgeTemplateIds.add(input.badgeTemplateId);
    }

    const visibleBadgeTemplates =
      scopedRootOrgUnitIds.length === 0
        ? badgeTemplates
        : filterBadgeTemplatesToIds(badgeTemplates, visibleBadgeTemplateIds);
    const visibleOrgUnits =
      scopedRootOrgUnitIds.length === 0
        ? orgUnits
        : filterOrgUnitsToScope(orgUnits, orgUnitsById, scopedRootOrgUnitIds);

    return {
      tenant,
      userId: input.sessionUserId,
      ...(currentUser?.email === undefined ? {} : { userEmail: currentUser.email }),
      membershipRole: input.membershipRole,
      badgeTemplates: visibleBadgeTemplates,
      orgUnits: visibleOrgUnits,
      membershipOrgUnitScopes,
      tenantMembers: [],
      delegatedIssuingAuthorityGrants: [],
      activeApiKeys: [],
      revokedApiKeyCount: 0,
      badgeRules: [],
      badgeRuleVersions: [],
      enterpriseAuthPolicy: null,
      enterpriseAuthProviders: [],
      breakGlassAccounts: [],
      switchOrganizationPath,
      reportingOverview,
      reportingEngagementCounts,
      reportingMetrics: buildReportingMetricEntries(reportingOverview.counts),
      reportingOrgUnitComparisons,
      reportingTemplateComparisons,
      reportingTrends,
    };
  };

  const renderInstitutionAdminWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
    renderPage: (pageData: Parameters<typeof institutionAdminDashboardPage>[0]) => string,
  ): Promise<Response> => {
    const roleCheck = await requireTenantRole(c, tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(c, tenantId, nextPath);
      }

      if (roleCheck.status === 423) {
        return c.redirect(
          buildLocalTwoFactorPath({
            tenantId,
            nextPath,
            setup: true,
            reason: "break_glass_mfa_setup_pending",
          }),
          302,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return c.html(adminRoleRequiredPage(tenantId), 403);
      }

      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const pageData = await loadInstitutionAdminPageData(
      c,
      tenantId,
      session.userId,
      membershipRole,
    );

    if (pageData instanceof Response) {
      return pageData;
    }

    c.header("Cache-Control", "no-store");

    return c.html(renderPage(pageData));
  };

  const renderLearnerRecordImportWorkspace = async (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
    workflow?: LearnerRecordImportWorkflowInput,
  ): Promise<Response> => {
    const pageData = await loadLearnerRecordImportPageData({
      c,
      tenantId,
      sessionUserId,
      membershipRole,
      ...(workflow === undefined ? {} : { workflow }),
    });

    if (pageData instanceof Response) {
      return pageData;
    }

    c.header("Cache-Control", "no-store");
    return c.html(institutionAdminLearnerRecordImportsPage(pageData));
  };

  const handleLearnerRecordImportUpload = async (input: {
    c: AppContext;
    tenantId: string;
    sessionUserId: string;
    membershipRole: TenantMembershipRole;
    mode: "preview" | "apply";
  }): Promise<Response> => {
    const contentType = input.c.req.header("content-type")?.toLowerCase() ?? "";

    if (!contentType.includes("multipart/form-data")) {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: "issuer_verified",
            defaultIssuerName: "",
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "Upload requires CSV form data",
            detail: 'Use multipart form upload with a file field named "file".',
          },
        },
      );
    }

    const formData = await input.c.req.formData();
    const upload = formData.get("file");
    const defaultIssuerName = getOptionalFormValue(formData, "defaultIssuerName") ?? "";
    let defaults;

    try {
      defaults = parseLearnerRecordImportBatchDefaults({
        defaultTrustLevel: getOptionalFormValue(formData, "defaultTrustLevel"),
        ...(defaultIssuerName.length === 0 ? {} : { defaultIssuerName }),
      });
    } catch {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: "issuer_verified",
            defaultIssuerName,
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "Import defaults are invalid",
            detail: "Choose a valid batch trust default before previewing or queueing the import.",
          },
        },
      );
    }

    if (!(upload instanceof File)) {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: defaults.defaultTrustLevel,
            defaultIssuerName,
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "CSV file is required",
            detail:
              'Attach a CSV file in the "file" field to preview or queue learner-record imports.',
          },
        },
      );
    }

    const fileContent = await upload.text();

    if (fileContent.trim().length === 0) {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: defaults.defaultTrustLevel,
            defaultIssuerName,
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "Uploaded CSV is empty",
            detail: "Add at least one learner-record row before previewing or queueing the batch.",
          },
        },
      );
    }

    const db = resolveDatabase(input.c.env);
    let prepared;

    try {
      prepared = await prepareLearnerRecordImportSubmission(db, {
        tenantId: input.tenantId,
        fileName: upload.name,
        mimeType: upload.type,
        content: fileContent,
        defaults,
        requestedAt: new Date().toISOString(),
        requestedByUserId: input.sessionUserId,
      });
    } catch (error: unknown) {
      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: defaults.defaultTrustLevel,
            defaultIssuerName,
          },
          submission: null,
          feedback: {
            tone: "warning",
            title: "Import file could not be prepared",
            detail:
              error instanceof Error
                ? error.message
                : "CredTrail could not parse this learner-record CSV.",
          },
        },
      );
    }

    const queuedRows =
      input.mode === "apply"
        ? await enqueueLearnerRecordImportBatch(db, input.tenantId, prepared.queuePayloads)
        : 0;
    const validRows = prepared.reports.filter((report) => report.status === "valid").length;
    const invalidRows = prepared.reports.length - validRows;

    return renderLearnerRecordImportWorkspace(
      input.c,
      input.tenantId,
      input.sessionUserId,
      input.membershipRole,
      {
        defaults: {
          defaultTrustLevel: defaults.defaultTrustLevel,
          defaultIssuerName,
        },
        submission: {
          mode: input.mode,
          batchId: prepared.batchId,
          fileName: prepared.fileName,
          totalRows: prepared.reports.length,
          validRows,
          invalidRows,
          queuedRows,
          rows: prepared.reports,
        },
        feedback: {
          tone: input.mode === "apply" ? "success" : "warning",
          title:
            input.mode === "apply"
              ? "Learner-record import batch queued"
              : "Learner-record import preview ready",
          detail:
            input.mode === "apply"
              ? `Queued ${String(queuedRows)} valid rows from ${prepared.fileName}. Invalid rows were kept out of the queue.`
              : "Review trust classification, smart defaults, and warnings below before queueing the import.",
        },
      },
    );
  };

  app.get("/tenants/:tenantId/admin", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin`,
      institutionAdminDashboardPage,
    );
  });

  app.get("/tenants/:tenantId/admin/operations", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations`,
      institutionAdminOperationsPage,
    );
  });

  app.get("/tenants/:tenantId/admin/operations/learner-record-imports", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/learner-record-imports`,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return c.html(adminRoleRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    return renderLearnerRecordImportWorkspace(
      c,
      pathParams.tenantId,
      roleCheck.session.userId,
      roleCheck.membershipRole,
    );
  });

  app.post("/tenants/:tenantId/admin/operations/learner-record-imports/preview", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/learner-record-imports`,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return c.html(adminRoleRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    return handleLearnerRecordImportUpload({
      c,
      tenantId: pathParams.tenantId,
      sessionUserId: roleCheck.session.userId,
      membershipRole: roleCheck.membershipRole,
      mode: "preview",
    });
  });

  app.post("/tenants/:tenantId/admin/operations/learner-record-imports/apply", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/learner-record-imports`,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return c.html(adminRoleRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    return handleLearnerRecordImportUpload({
      c,
      tenantId: pathParams.tenantId,
      sessionUserId: roleCheck.session.userId,
      membershipRole: roleCheck.membershipRole,
      mode: "apply",
    });
  });

  app.post(
    "/tenants/:tenantId/admin/operations/learner-record-imports/:batchId/retry",
    async (c) => {
      let pathParams;

      try {
        pathParams = parseLearnerRecordImportBatchPathParams(c.req.param());
      } catch {
        return c.json(
          {
            error: "Invalid learner-record import batch path",
          },
          400,
        );
      }

      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        if (roleCheck.status === 401) {
          return redirectToTenantLogin(
            c,
            pathParams.tenantId,
            `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/learner-record-imports`,
          );
        }

        if (roleCheck.status === 403) {
          c.header("Cache-Control", "no-store");
          return c.html(adminRoleRequiredPage(pathParams.tenantId), 403);
        }

        return roleCheck;
      }

      const retryResult = await retryFailedImportLearnerRecordBatchQueueMessages(
        resolveDatabase(c.env),
        {
          tenantId: pathParams.tenantId,
          batchId: pathParams.batchId,
        },
      );

      return renderLearnerRecordImportWorkspace(
        c,
        pathParams.tenantId,
        roleCheck.session.userId,
        roleCheck.membershipRole,
        {
          defaults: {
            defaultTrustLevel: "issuer_verified",
            defaultIssuerName: "",
          },
          submission: null,
          feedback:
            retryResult.matched === 0
              ? {
                  tone: "warning",
                  title: "Import batch not found",
                  detail: `Batch ${pathParams.batchId} is not available for retry in this tenant.`,
                }
              : {
                  tone: "success",
                  title: "Failed rows retried",
                  detail: `Retried ${String(retryResult.retried)} failed rows from batch ${pathParams.batchId}.`,
                },
        },
      );
    },
  );

  app.get("/tenants/:tenantId/admin/operations/learner-records", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/learner-records`,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return c.html(adminRoleRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    let reviewQuery;

    try {
      reviewQuery = parseAdminLearnerRecordReviewQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid learner-record review query",
        },
        400,
      );
    }

    const pageData = await loadLearnerRecordReviewPageData({
      c,
      tenantId: pathParams.tenantId,
      sessionUserId: roleCheck.session.userId,
      membershipRole: roleCheck.membershipRole,
      ...(reviewQuery.learnerProfileId ? { learnerProfileId: reviewQuery.learnerProfileId } : {}),
      ...(reviewQuery.email ? { email: reviewQuery.email } : {}),
    });

    if (pageData instanceof Response) {
      return pageData;
    }

    c.header("Cache-Control", "no-store");
    return c.html(institutionAdminLearnerRecordsPage(pageData));
  });

  app.get("/tenants/:tenantId/admin/operations/review-queue", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/review-queue`,
      institutionAdminOperationsReviewQueuePage,
    );
  });

  app.get("/tenants/:tenantId/admin/operations/issued-badges", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/issued-badges`,
      institutionAdminIssuedBadgesPage,
    );
  });

  app.get("/tenants/:tenantId/admin/operations/badge-status", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/badge-status`,
      institutionAdminBadgeStatusPage,
    );
  });

  app.get("/tenants/:tenantId/admin/reporting", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/reporting`,
        );
      }

      if (roleCheck.status === 423) {
        return c.redirect(
          buildLocalTwoFactorPath({
            tenantId: pathParams.tenantId,
            nextPath: `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/reporting`,
            setup: true,
            reason: "break_glass_mfa_setup_pending",
          }),
          302,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return c.html(reportingAccessRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    let reportingQuery;

    try {
      reportingQuery = parseTenantReportingOverviewQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid reporting overview query",
        },
        400,
      );
    }

    const { session, membershipRole } = roleCheck;
    let pageData = await loadReportingPageData({
      c,
      tenantId: pathParams.tenantId,
      sessionUserId: session.userId,
      membershipRole,
      issuedFrom: reportingQuery.issuedFrom,
      issuedTo: reportingQuery.issuedTo,
      badgeTemplateId: reportingQuery.badgeTemplateId,
      orgUnitId: reportingQuery.orgUnitId,
      state: reportingQuery.state,
    });

    if (pageData instanceof Response) {
      return pageData;
    }

    if (pageData.reportingOverview === undefined) {
      const db = resolveDatabase(c.env);
      const reportingPageFilters = {
        issuedFrom: reportingQuery.issuedFrom,
        issuedTo: reportingQuery.issuedTo,
        badgeTemplateId: reportingQuery.badgeTemplateId,
        orgUnitId: reportingQuery.orgUnitId,
        state: reportingQuery.state,
      };
      const [
        reportingOverview,
        reportingEngagementCounts,
        reportingTrends,
        reportingTemplateComparisons,
        reportingOrgUnitComparisons,
      ] = await Promise.all([
        getTenantReportingOverview(db, {
          tenantId: pathParams.tenantId,
          ...toReportingOverviewFilters(reportingPageFilters),
        }),
        getTenantReportingEngagementCounts(db, {
          tenantId: pathParams.tenantId,
          ...toReportingEngagementFilters(reportingPageFilters),
        }),
        getTenantReportingTrends(db, {
          tenantId: pathParams.tenantId,
          ...toReportingTrendFilters(reportingPageFilters),
        }),
        listTenantReportingComparisons(db, {
          tenantId: pathParams.tenantId,
          ...toReportingComparisonFilters(reportingPageFilters, "badgeTemplate"),
        }),
        listTenantReportingComparisons(db, {
          tenantId: pathParams.tenantId,
          ...toReportingComparisonFilters(reportingPageFilters, "orgUnit"),
        }),
      ]);

      pageData = {
        ...pageData,
        reportingOverview,
        reportingEngagementCounts,
        reportingMetrics: buildReportingMetricEntries(reportingOverview.counts),
        reportingOrgUnitComparisons,
        reportingTemplateComparisons,
        reportingTrends,
      };
    }

    c.header("Cache-Control", "no-store");

    return c.html(institutionAdminReportingPage(pageData));
  });

  app.get("/tenants/:tenantId/admin/rules", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules`,
      institutionAdminRulesPage,
    );
  });

  app.get("/tenants/:tenantId/admin/access", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access`,
      institutionAdminAccessPage,
    );
  });

  app.get("/tenants/:tenantId/admin/access/members", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/members`,
      institutionAdminMembersPage,
    );
  });

  app.get("/tenants/:tenantId/admin/access/governance", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/governance`,
      institutionAdminGovernancePage,
    );
  });

  app.get("/tenants/:tenantId/admin/access/api-keys", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/api-keys`,
      institutionAdminApiKeysPage,
    );
  });

  app.get("/tenants/:tenantId/admin/access/org-units", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    return renderInstitutionAdminWorkspace(
      c,
      pathParams.tenantId,
      `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/access/org-units`,
      institutionAdminOrgUnitsPage,
    );
  });

  app.get("/tenants/:tenantId/admin/rules/new", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules/new`,
        );
      }

      if (roleCheck.status === 423) {
        return c.redirect(
          buildLocalTwoFactorPath({
            tenantId: pathParams.tenantId,
            nextPath: `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/rules/new`,
            setup: true,
            reason: "break_glass_mfa_setup_pending",
          }),
          302,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return c.html(adminRoleRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const tenant = await findTenantById(db, pathParams.tenantId);

    if (tenant === null) {
      return c.json(
        {
          error: "Tenant not found",
        },
        404,
      );
    }

    const [currentUser, badgeTemplates, badgeRules] = await Promise.all([
      findUserById(db, session.userId),
      listBadgeTemplates(db, {
        tenantId: pathParams.tenantId,
        includeArchived: false,
      }),
      listBadgeIssuanceRules(db, {
        tenantId: pathParams.tenantId,
      }),
    ]);
    const badgeRuleVersionLists = await Promise.all(
      badgeRules.map(async (rule) =>
        listBadgeIssuanceRuleVersions(db, {
          tenantId: pathParams.tenantId,
          ruleId: rule.id,
        }),
      ),
    );
    const badgeRuleVersions = badgeRuleVersionLists.flat();

    c.header("Cache-Control", "no-store");

    return c.html(
      institutionAdminRuleBuilderPage({
        tenant,
        userId: session.userId,
        ...(currentUser?.email === undefined ? {} : { userEmail: currentUser.email }),
        membershipRole,
        badgeTemplates,
        badgeRules,
        badgeRuleVersions,
        ...(c.env.RULE_BUILDER_TUTORIAL_EMBED_URL === undefined
          ? {}
          : { ruleBuilderTutorialEmbedUrl: c.env.RULE_BUILDER_TUTORIAL_EMBED_URL }),
      }),
    );
  });

  app.get("/v1/tenants/:tenantId/sso/saml", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const configuration = await findTenantSsoSamlConfiguration(db, pathParams.tenantId);

    if (configuration === null) {
      return c.json(
        {
          error: "SAML SSO configuration not found",
        },
        404,
      );
    }

    return c.json({
      tenantId: pathParams.tenantId,
      deprecated: true,
      notice: LEGACY_SAML_COMPATIBILITY_NOTICE,
      configuration,
    });
  });

  app.put("/v1/tenants/:tenantId/sso/saml", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantSsoSamlConfigurationRequest>;

    try {
      request = parseUpsertTenantSsoSamlConfigurationRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid SAML SSO configuration payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }
    void request;
    void session;
    void membershipRole;

    return c.json(
      {
        error: LEGACY_SAML_DEPRECATED_ERROR,
      },
      410,
    );
  });

  app.delete("/v1/tenants/:tenantId/sso/saml", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const removed = await deleteTenantSsoSamlConfiguration(db, pathParams.tenantId);

    if (removed) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.sso_saml_configuration_deleted",
        targetType: "tenant_sso_saml_configuration",
        targetId: pathParams.tenantId,
        metadata: {
          role: membershipRole,
        },
      });
    }

    return c.json({
      tenantId: pathParams.tenantId,
      removed,
    });
  });

  app.get("/v1/tenants/:tenantId/auth-policy", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const policy = await resolveTenantAuthPolicy(db, pathParams.tenantId);
    return c.json(serializeTenantAuthPolicy(policy));
  });

  app.put("/v1/tenants/:tenantId/auth-policy", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantAuthPolicyRequest>;

    try {
      request = parseUpsertTenantAuthPolicyRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid tenant auth policy payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    if (request.defaultProviderId !== undefined && request.defaultProviderId !== null) {
      const provider = await findTenantAuthProviderById(
        db,
        pathParams.tenantId,
        request.defaultProviderId,
      );

      if (provider === null) {
        return c.json(
          {
            error: "Default auth provider not found",
          },
          400,
        );
      }

      if (!isHostedEnterpriseAuthProviderSupported(provider)) {
        return c.json(
          {
            error: LEGACY_SAML_DEFAULT_PROVIDER_ERROR,
          },
          400,
        );
      }
    }

    const policy = await upsertTenantAuthPolicy(db, {
      tenantId: pathParams.tenantId,
      loginMode: request.loginMode,
      breakGlassEnabled: request.breakGlassEnabled,
      localMfaRequired: request.localMfaRequired,
      defaultProviderId: request.defaultProviderId,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.auth_policy_upserted",
      targetType: "tenant_auth_policy",
      targetId: pathParams.tenantId,
      metadata: {
        role: membershipRole,
        loginMode: policy.loginMode,
        breakGlassEnabled: policy.breakGlassEnabled,
        localMfaRequired: policy.localMfaRequired,
        defaultProviderId: policy.defaultProviderId,
        enforceForRoles: policy.enforceForRoles,
      },
    });

    return c.json(serializeTenantAuthPolicy(policy));
  });

  app.get("/v1/tenants/:tenantId/auth-providers", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const providers = await listTenantAuthProviders(db, pathParams.tenantId);
    return c.json(providers.map(serializeTenantAuthProvider));
  });

  app.post("/v1/tenants/:tenantId/auth-providers", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantAuthProviderRequest>;

    try {
      request = parseUpsertTenantAuthProviderRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid tenant auth provider payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    if (request.protocol !== "oidc") {
      return c.json(
        {
          error: HOSTED_ENTERPRISE_OIDC_ONLY_ERROR,
        },
        400,
      );
    }

    const provider = await createTenantAuthProvider(db, {
      tenantId: pathParams.tenantId,
      protocol: request.protocol,
      label: request.label,
      enabled: request.enabled,
      isDefault: request.isDefault,
      configJson: request.configJson,
    });

    if (provider.isDefault) {
      const currentPolicy = await resolveTenantAuthPolicy(db, pathParams.tenantId);
      await upsertTenantAuthPolicy(db, {
        tenantId: pathParams.tenantId,
        loginMode: currentPolicy.loginMode,
        breakGlassEnabled: currentPolicy.breakGlassEnabled,
        localMfaRequired: currentPolicy.localMfaRequired,
        defaultProviderId: provider.id,
        enforceForRoles: currentPolicy.enforceForRoles,
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.auth_provider_created",
      targetType: "tenant_auth_provider",
      targetId: provider.id,
      metadata: {
        role: membershipRole,
        protocol: provider.protocol,
        label: provider.label,
        enabled: provider.enabled,
        isDefault: provider.isDefault,
      },
    });

    return c.json(serializeTenantAuthProvider(provider), 201);
  });

  app.put("/v1/tenants/:tenantId/auth-providers/:providerId", async (c) => {
    const pathParams = parseTenantAuthProviderPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantAuthProviderRequest>;

    try {
      request = parseUpsertTenantAuthProviderRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid tenant auth provider payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const existingProvider = await findTenantAuthProviderById(
      db,
      pathParams.tenantId,
      pathParams.providerId,
    );

    if (existingProvider === null) {
      return c.json(
        {
          error: "Tenant auth provider not found",
        },
        404,
      );
    }

    if (!isHostedEnterpriseAuthProviderSupported(existingProvider)) {
      return c.json(
        {
          error: LEGACY_SAML_EDIT_BLOCKED_ERROR,
        },
        400,
      );
    }

    if (request.protocol !== "oidc") {
      return c.json(
        {
          error: HOSTED_ENTERPRISE_OIDC_ONLY_ERROR,
        },
        400,
      );
    }

    const provider = await updateTenantAuthProvider(db, {
      tenantId: pathParams.tenantId,
      providerId: pathParams.providerId,
      protocol: request.protocol,
      label: request.label,
      enabled: request.enabled,
      isDefault: request.isDefault,
      configJson: request.configJson,
    });

    if (provider === null) {
      return c.json(
        {
          error: "Tenant auth provider not found",
        },
        404,
      );
    }

    const currentPolicy = await resolveTenantAuthPolicy(db, pathParams.tenantId);
    await upsertTenantAuthPolicy(db, {
      tenantId: pathParams.tenantId,
      loginMode: currentPolicy.loginMode,
      breakGlassEnabled: currentPolicy.breakGlassEnabled,
      localMfaRequired: currentPolicy.localMfaRequired,
      defaultProviderId: provider.isDefault
        ? provider.id
        : currentPolicy.defaultProviderId === provider.id
          ? null
          : currentPolicy.defaultProviderId,
      enforceForRoles: currentPolicy.enforceForRoles,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.auth_provider_updated",
      targetType: "tenant_auth_provider",
      targetId: provider.id,
      metadata: {
        role: membershipRole,
        protocol: provider.protocol,
        label: provider.label,
        enabled: provider.enabled,
        isDefault: provider.isDefault,
      },
    });

    return c.json(serializeTenantAuthProvider(provider));
  });

  app.delete("/v1/tenants/:tenantId/auth-providers/:providerId", async (c) => {
    const pathParams = parseTenantAuthProviderPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const removed = await deleteTenantAuthProvider(db, pathParams.tenantId, pathParams.providerId);

    if (removed) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.auth_provider_deleted",
        targetType: "tenant_auth_provider",
        targetId: pathParams.providerId,
        metadata: {
          role: membershipRole,
        },
      });
    }

    return c.json({ removed });
  });

  app.get("/v1/tenants/:tenantId/members", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const members = await listTenantMembers(resolveDatabase(c.env), pathParams.tenantId);

    return c.json({
      tenantId: pathParams.tenantId,
      members,
    });
  });

  app.post("/v1/tenants/:tenantId/members", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateTenantMemberRequest>;

    try {
      request = parseCreateTenantMemberRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid tenant member payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const user = await upsertUserByEmail(db, request.email);
    const existingMembership = await findTenantMembership(db, pathParams.tenantId, user.id);
    const rolePolicyResponse = await assertRoleChangeAllowed(c, {
      db,
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      actorRole: membershipRole,
      targetUserId: user.id,
      previousRole: existingMembership?.role ?? null,
      nextRole: request.role,
    });

    if (rolePolicyResponse !== null) {
      return rolePolicyResponse;
    }

    const roleResult = await upsertTenantMembershipRole(db, {
      tenantId: pathParams.tenantId,
      userId: user.id,
      role: request.role,
    });
    const invite = await requestInviteForTenantMember(c, {
      tenantId: pathParams.tenantId,
      email: user.email,
      role: roleResult.membership.role,
      sendInvite: request.sendInvite !== false,
    });
    const action = membershipAuditAction(roleResult.previousRole, roleResult.membership.role);

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action,
      targetType: "membership",
      targetId: `${pathParams.tenantId}:${user.id}`,
      metadata: {
        actorRole: membershipRole,
        userId: user.id,
        email: user.email,
        previousRole: roleResult.previousRole,
        newRole: roleResult.membership.role,
        role: roleResult.membership.role,
        changed: roleResult.changed,
        inviteDeliveryStatus: invite.deliveryStatus,
        inviteKind: invite.inviteKind,
      },
    });

    if (invite.deliveryStatus !== "skipped") {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "membership.invite_sent",
        targetType: "membership",
        targetId: `${pathParams.tenantId}:${user.id}`,
        metadata: {
          actorRole: membershipRole,
          userId: user.id,
          email: user.email,
          newRole: roleResult.membership.role,
          role: roleResult.membership.role,
          inviteDeliveryStatus: invite.deliveryStatus,
          inviteKind: invite.inviteKind,
        },
      });
    }

    return c.json(
      {
        tenantId: pathParams.tenantId,
        member: {
          ...roleResult.membership,
          email: user.email,
        },
        previousRole: roleResult.previousRole,
        changed: roleResult.changed,
        invite,
      },
      roleResult.previousRole === null ? 201 : 200,
    );
  });

  app.patch("/v1/tenants/:tenantId/members/:userId/role", async (c) => {
    const pathParams = parseTenantMemberPathParams(c.req.param());
    let request: ReturnType<typeof parseUpdateTenantMemberRoleRequest>;

    try {
      request = parseUpdateTenantMemberRoleRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid tenant member role payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const existingMembership = await findTenantMembership(
      db,
      pathParams.tenantId,
      pathParams.userId,
    );

    if (existingMembership === null) {
      return c.json(
        {
          error: "Tenant member not found",
        },
        404,
      );
    }

    const rolePolicyResponse = await assertRoleChangeAllowed(c, {
      db,
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      actorRole: membershipRole,
      targetUserId: pathParams.userId,
      previousRole: existingMembership.role,
      nextRole: request.role,
    });

    if (rolePolicyResponse !== null) {
      return rolePolicyResponse;
    }

    const [roleResult, user] = await Promise.all([
      upsertTenantMembershipRole(db, {
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        role: request.role,
      }),
      findUserById(db, pathParams.userId),
    ]);
    const action = membershipAuditAction(roleResult.previousRole, roleResult.membership.role);

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action,
      targetType: "membership",
      targetId: `${pathParams.tenantId}:${pathParams.userId}`,
      metadata: {
        actorRole: membershipRole,
        userId: pathParams.userId,
        email: user?.email ?? null,
        previousRole: roleResult.previousRole,
        newRole: roleResult.membership.role,
        role: roleResult.membership.role,
        changed: roleResult.changed,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      member: {
        ...roleResult.membership,
        email: user?.email ?? "",
      },
      previousRole: roleResult.previousRole,
      changed: roleResult.changed,
    });
  });

  app.post("/v1/tenants/:tenantId/members/:userId/invite", async (c) => {
    const pathParams = parseTenantMemberPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const [membership, user] = await Promise.all([
      findTenantMembership(db, pathParams.tenantId, pathParams.userId),
      findUserById(db, pathParams.userId),
    ]);

    if (membership === null || user === null) {
      return c.json(
        {
          error: "Tenant member not found",
        },
        404,
      );
    }

    if (!canManageTenantRole(membershipRole, membership.role)) {
      return c.json(
        {
          error: "Only tenant owners can invite owner members.",
        },
        403,
      );
    }

    const invite = await requestInviteForTenantMember(c, {
      tenantId: pathParams.tenantId,
      email: user.email,
      role: membership.role,
      sendInvite: true,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "membership.invite_sent",
      targetType: "membership",
      targetId: `${pathParams.tenantId}:${pathParams.userId}`,
      metadata: {
        actorRole: membershipRole,
        userId: pathParams.userId,
        email: user.email,
        newRole: membership.role,
        role: membership.role,
        inviteDeliveryStatus: invite.deliveryStatus,
        inviteKind: invite.inviteKind,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      invite,
    });
  });

  app.delete("/v1/tenants/:tenantId/members/:userId", async (c) => {
    const pathParams = parseTenantMemberPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const [membership, user] = await Promise.all([
      findTenantMembership(db, pathParams.tenantId, pathParams.userId),
      findUserById(db, pathParams.userId),
    ]);

    if (membership === null) {
      return c.json(
        {
          error: "Tenant member not found",
        },
        404,
      );
    }

    if (pathParams.userId === session.userId) {
      return c.json(
        {
          error: "You cannot remove your own tenant membership.",
        },
        409,
      );
    }

    if (membership.role === "owner" && membershipRole !== "owner") {
      return c.json(
        {
          error: "Only tenant owners can remove an owner membership.",
        },
        403,
      );
    }

    if (membership.role === "owner") {
      const counts = await countTenantMembershipsByRole(db, pathParams.tenantId);

      if (counts.owner <= 1) {
        return c.json(
          {
            error: "At least one tenant owner must remain.",
          },
          409,
        );
      }
    }

    const removed = await removeTenantMembership(db, pathParams.tenantId, pathParams.userId);
    const revokedBreakGlass = await revokeTenantBreakGlassAccount(db, {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      revokedAt: new Date().toISOString(),
    });

    if (removed) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "membership.removed",
        targetType: "membership",
        targetId: `${pathParams.tenantId}:${pathParams.userId}`,
        metadata: {
          actorRole: membershipRole,
          userId: pathParams.userId,
          email: user?.email ?? null,
          previousRole: membership.role,
          revokedBreakGlass,
        },
      });
    }

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      removed,
      revokedBreakGlass,
    });
  });

  app.get("/v1/tenants/:tenantId/break-glass-accounts", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const accounts = await listTenantBreakGlassAccounts(db, pathParams.tenantId);
    return c.json(accounts);
  });

  app.post("/v1/tenants/:tenantId/break-glass-accounts", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateTenantBreakGlassAccountRequest>;

    try {
      request = parseCreateTenantBreakGlassAccountRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid break-glass account payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const user = await upsertUserByEmail(db, request.email);
    const membershipResult = await ensureTenantMembership(db, pathParams.tenantId, user.id);
    const account = await upsertTenantBreakGlassAccount(db, {
      tenantId: pathParams.tenantId,
      userId: user.id,
      createdByUserId: session.userId,
    });
    const passwordResetStatus =
      request.sendEnrollmentEmail === false || requestBreakGlassPasswordReset === undefined
        ? "skipped"
        : await requestBreakGlassPasswordReset(c, {
            tenantId: pathParams.tenantId,
            email: request.email,
          });

    if (membershipResult.created) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "membership.role_assigned",
        targetType: "membership",
        targetId: `${pathParams.tenantId}:${user.id}`,
        metadata: {
          userId: user.id,
          role: membershipResult.membership.role,
        },
      });
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.break_glass_account_upserted",
      targetType: "tenant_break_glass_account",
      targetId: `${pathParams.tenantId}:${user.id}`,
      metadata: {
        role: membershipRole,
        email: request.email,
        sendEnrollmentEmail: request.sendEnrollmentEmail !== false,
        passwordResetStatus,
      },
    });

    return c.json(
      {
        account,
        passwordResetStatus,
      },
      201,
    );
  });

  app.delete("/v1/tenants/:tenantId/break-glass-accounts/:userId", async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const enterpriseCheck = await requireEnterpriseTenant(c, pathParams.tenantId, db);

    if (enterpriseCheck !== null) {
      return enterpriseCheck;
    }

    const existingAccount = await findActiveTenantBreakGlassAccountByUserId(
      db,
      pathParams.tenantId,
      pathParams.userId,
    );
    const removed = await revokeTenantBreakGlassAccount(db, {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      revokedAt: new Date().toISOString(),
    });

    if (removed) {
      await createAuditLog(db, {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.break_glass_account_revoked",
        targetType: "tenant_break_glass_account",
        targetId: `${pathParams.tenantId}:${pathParams.userId}`,
        metadata: {
          role: membershipRole,
          email: existingAccount?.email ?? null,
        },
      });
    }

    return c.json({ removed });
  });

  app.get("/v1/tenants/:tenantId/api-keys", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const query = parseTenantApiKeyListQuery({
      includeRevoked: c.req.query("includeRevoked"),
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const keys = await listTenantApiKeys(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      includeRevoked: query.includeRevoked,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      keys: keys.map((key) => ({
        id: key.id,
        tenantId: key.tenantId,
        label: key.label,
        keyPrefix: key.keyPrefix,
        scopesJson: key.scopesJson,
        createdByUserId: key.createdByUserId,
        expiresAt: key.expiresAt,
        lastUsedAt: key.lastUsedAt,
        revokedAt: key.revokedAt,
        createdAt: key.createdAt,
        updatedAt: key.updatedAt,
      })),
    });
  });

  app.post("/v1/tenants/:tenantId/api-keys", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateTenantApiKeyRequest>;

    try {
      request = parseCreateTenantApiKeyRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid API key payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const rawApiKey = `ctak_${generateOpaqueToken()}${generateOpaqueToken()}`;
    const keyHash = await sha256Hex(rawApiKey);
    const keyPrefix = rawApiKey.slice(0, 12);
    const scopes =
      request.scopes === undefined || request.scopes.length === 0
        ? ["queue.issue", "queue.revoke"]
        : request.scopes;
    const keyRecord = await createTenantApiKey(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      label: request.label,
      keyPrefix,
      keyHash,
      scopesJson: JSON.stringify(scopes),
      createdByUserId: session.userId,
      expiresAt: request.expiresAt,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "tenant.api_key_created",
      targetType: "tenant_api_key",
      targetId: keyRecord.id,
      metadata: {
        role: membershipRole,
        label: keyRecord.label,
        keyPrefix: keyRecord.keyPrefix,
        scopes,
        expiresAt: keyRecord.expiresAt,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        apiKey: rawApiKey,
        key: {
          id: keyRecord.id,
          label: keyRecord.label,
          keyPrefix: keyRecord.keyPrefix,
          scopesJson: keyRecord.scopesJson,
          createdByUserId: keyRecord.createdByUserId,
          expiresAt: keyRecord.expiresAt,
          revokedAt: keyRecord.revokedAt,
          createdAt: keyRecord.createdAt,
        },
      },
      201,
    );
  });

  app.post("/v1/tenants/:tenantId/api-keys/:apiKeyId/revoke", async (c) => {
    const pathParams = parseTenantApiKeyPathParams(c.req.param());
    let request: ReturnType<typeof parseRevokeTenantApiKeyRequest>;

    try {
      let payload: unknown = {};

      try {
        payload = await c.req.json<unknown>();
      } catch {
        payload = {};
      }

      request = parseRevokeTenantApiKeyRequest(payload);
    } catch {
      return c.json(
        {
          error: "Invalid API key revoke payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const revokedAt = request.revokedAt ?? new Date().toISOString();
    const revoked = await revokeTenantApiKey(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      apiKeyId: pathParams.apiKeyId,
      revokedAt,
    });

    if (revoked) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.api_key_revoked",
        targetType: "tenant_api_key",
        targetId: pathParams.apiKeyId,
        metadata: {
          role: membershipRole,
          revokedAt,
        },
      });
    }

    return c.json({
      tenantId: pathParams.tenantId,
      apiKeyId: pathParams.apiKeyId,
      revoked,
    });
  });

  app.get("/v1/tenants/:tenantId/org-units", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const query = parseTenantOrgUnitListQuery({
      includeInactive: c.req.query("includeInactive"),
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const orgUnits = await listTenantOrgUnits(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      includeInactive: query.includeInactive,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      orgUnits,
    });
  });

  app.post("/v1/tenants/:tenantId/org-units", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateTenantOrgUnitRequest>;

    try {
      request = parseCreateTenantOrgUnitRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid org unit request payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;

    try {
      const orgUnit = await createTenantOrgUnit(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        unitType: request.unitType,
        slug: request.slug,
        displayName: request.displayName,
        parentOrgUnitId: request.parentOrgUnitId,
        createdByUserId: session.userId,
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "tenant.org_unit_created",
        targetType: "org_unit",
        targetId: orgUnit.id,
        metadata: {
          role: membershipRole,
          unitType: orgUnit.unitType,
          slug: orgUnit.slug,
          parentOrgUnitId: orgUnit.parentOrgUnitId,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          orgUnit,
        },
        201,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes("UNIQUE constraint failed")) {
          return c.json(
            {
              error: "Org unit slug already exists for tenant",
            },
            409,
          );
        }

        if (
          (error.message.includes("Parent org unit") &&
            error.message.includes("not found for tenant")) ||
          error.message.includes("cannot have a parent org unit") ||
          error.message.includes("requires parent org unit type") ||
          error.message.includes("is inactive for tenant")
        ) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }
      }

      throw error;
    }
  });

  app.get("/v1/tenants/:tenantId/users/:userId/org-unit-scopes", async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const scopes = await listTenantMembershipOrgUnitScopes(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      scopes,
    });
  });

  app.put("/v1/tenants/:tenantId/users/:userId/org-unit-scopes/:orgUnitId", async (c) => {
    const pathParams = parseTenantUserOrgUnitPathParams(c.req.param());
    let request: ReturnType<typeof parseUpsertTenantMembershipOrgUnitScopeRequest>;

    try {
      request = parseUpsertTenantMembershipOrgUnitScopeRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid org-unit scope payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;

    try {
      const result = await upsertTenantMembershipOrgUnitScope(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        orgUnitId: pathParams.orgUnitId,
        role: request.role,
        createdByUserId: session.userId,
      });

      const action =
        result.previousRole === null
          ? "membership.org_scope_assigned"
          : result.previousRole === result.scope.role
            ? "membership.org_scope_reasserted"
            : "membership.org_scope_changed";

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action,
        targetType: "membership_org_scope",
        targetId: `${pathParams.tenantId}:${pathParams.userId}:${pathParams.orgUnitId}`,
        metadata: {
          role: membershipRole,
          userId: pathParams.userId,
          orgUnitId: pathParams.orgUnitId,
          previousRole: result.previousRole,
          scopeRole: result.scope.role,
          changed: result.changed,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          userId: pathParams.userId,
          orgUnitId: pathParams.orgUnitId,
          scope: result.scope,
          previousRole: result.previousRole,
          changed: result.changed,
        },
        result.previousRole === null ? 201 : 200,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes("Membership not found for tenant")) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }

        if (error.message.includes("Org unit") && error.message.includes("not found for tenant")) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }
      }

      throw error;
    }
  });

  app.delete("/v1/tenants/:tenantId/users/:userId/org-unit-scopes/:orgUnitId", async (c) => {
    const pathParams = parseTenantUserOrgUnitPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const removed = await removeTenantMembershipOrgUnitScope(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      orgUnitId: pathParams.orgUnitId,
    });

    if (removed) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "membership.org_scope_removed",
        targetType: "membership_org_scope",
        targetId: `${pathParams.tenantId}:${pathParams.userId}:${pathParams.orgUnitId}`,
        metadata: {
          role: membershipRole,
          userId: pathParams.userId,
          orgUnitId: pathParams.orgUnitId,
        },
      });
    }

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      orgUnitId: pathParams.orgUnitId,
      removed,
    });
  });

  app.get("/v1/tenants/:tenantId/users/:userId/issuing-authority-grants", async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    const query = parseDelegatedIssuingAuthorityGrantListQuery({
      includeRevoked: c.req.query("includeRevoked"),
      includeExpired: c.req.query("includeExpired"),
    });
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const grants = await listDelegatedIssuingAuthorityGrants(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      delegateUserId: pathParams.userId,
      includeRevoked: query.includeRevoked,
      includeExpired: query.includeExpired,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      userId: pathParams.userId,
      grants,
    });
  });

  app.post("/v1/tenants/:tenantId/users/:userId/issuing-authority-grants", async (c) => {
    const pathParams = parseTenantUserPathParams(c.req.param());
    let request: ReturnType<typeof parseCreateDelegatedIssuingAuthorityGrantRequest>;

    try {
      request = parseCreateDelegatedIssuingAuthorityGrantRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid delegated authority grant payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const startsAt = request.startsAt ?? new Date().toISOString();

    try {
      const grant = await createDelegatedIssuingAuthorityGrant(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        delegateUserId: pathParams.userId,
        delegatedByUserId: session.userId,
        orgUnitId: request.orgUnitId,
        allowedActions: request.allowedActions,
        badgeTemplateIds: request.badgeTemplateIds,
        startsAt,
        endsAt: request.endsAt,
        reason: request.reason,
      });

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "delegated_issuing_authority.granted",
        targetType: "delegated_issuing_authority_grant",
        targetId: grant.id,
        metadata: {
          role: membershipRole,
          delegateUserId: pathParams.userId,
          orgUnitId: request.orgUnitId,
          allowedActions: request.allowedActions,
          badgeTemplateIds: request.badgeTemplateIds ?? [],
          startsAt,
          endsAt: request.endsAt,
        },
      });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          userId: pathParams.userId,
          grant,
        },
        201,
      );
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes("conflicts with existing grant")) {
          return c.json(
            {
              error: error.message,
            },
            409,
          );
        }

        if (
          error.message.includes("Membership not found for tenant") ||
          (error.message.includes("Org unit") && error.message.includes("not found for tenant")) ||
          (error.message.includes("Badge template") &&
            error.message.includes("not found for tenant")) ||
          error.message.includes("outside delegated org-unit scope") ||
          error.message.includes("is inactive for tenant") ||
          error.message.includes("must be after") ||
          error.message.includes("must be a valid ISO timestamp")
        ) {
          return c.json(
            {
              error: error.message,
            },
            422,
          );
        }
      }

      throw error;
    }
  });

  app.post(
    "/v1/tenants/:tenantId/users/:userId/issuing-authority-grants/:grantId/revoke",
    async (c) => {
      const pathParams = parseTenantUserDelegatedGrantPathParams(c.req.param());
      let request: ReturnType<typeof parseRevokeDelegatedIssuingAuthorityGrantRequest>;

      try {
        let payload: unknown = {};

        try {
          payload = await c.req.json<unknown>();
        } catch {
          payload = {};
        }

        request = parseRevokeDelegatedIssuingAuthorityGrantRequest(payload);
      } catch {
        return c.json(
          {
            error: "Invalid delegated authority revoke payload",
          },
          400,
        );
      }

      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const existingGrant = await findDelegatedIssuingAuthorityGrantById(
        db,
        pathParams.tenantId,
        pathParams.grantId,
      );

      if (existingGrant?.delegateUserId !== pathParams.userId) {
        return c.json(
          {
            error: "Delegated issuing authority grant not found",
          },
          404,
        );
      }

      const revokedAt = request.revokedAt ?? new Date().toISOString();

      try {
        const result = await revokeDelegatedIssuingAuthorityGrant(db, {
          tenantId: pathParams.tenantId,
          grantId: pathParams.grantId,
          revokedByUserId: session.userId,
          revokedReason: request.reason,
          revokedAt,
        });

        if (result.status === "revoked") {
          await createAuditLog(db, {
            tenantId: pathParams.tenantId,
            actorUserId: session.userId,
            action: "delegated_issuing_authority.revoked",
            targetType: "delegated_issuing_authority_grant",
            targetId: pathParams.grantId,
            metadata: {
              role: membershipRole,
              delegateUserId: pathParams.userId,
              revokedAt,
              reason: request.reason,
            },
          });
        }

        return c.json({
          tenantId: pathParams.tenantId,
          userId: pathParams.userId,
          status: result.status,
          grant: result.grant,
        });
      } catch (error: unknown) {
        if (error instanceof Error) {
          if (
            error.message.includes("not found for tenant") ||
            error.message.includes("must be a valid ISO timestamp")
          ) {
            return c.json(
              {
                error: error.message,
              },
              422,
            );
          }
        }

        throw error;
      }
    },
  );

  app.get(
    "/v1/tenants/:tenantId/users/:userId/issuing-authority-grants/:grantId/events",
    async (c) => {
      const pathParams = parseTenantUserDelegatedGrantPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const limitRaw = c.req.query("limit");
      let limit: number | undefined;

      if (limitRaw !== undefined) {
        const parsed = Number.parseInt(limitRaw, 10);

        if (!Number.isFinite(parsed) || parsed < 1) {
          return c.json(
            {
              error: "limit must be a positive integer",
            },
            400,
          );
        }

        limit = parsed;
      }

      const db = resolveDatabase(c.env);
      const grant = await findDelegatedIssuingAuthorityGrantById(
        db,
        pathParams.tenantId,
        pathParams.grantId,
      );

      if (grant?.delegateUserId !== pathParams.userId) {
        return c.json(
          {
            error: "Delegated issuing authority grant not found",
          },
          404,
        );
      }

      const events = await listDelegatedIssuingAuthorityGrantEvents(db, {
        tenantId: pathParams.tenantId,
        grantId: pathParams.grantId,
        ...(limit === undefined ? {} : { limit }),
      });

      return c.json({
        tenantId: pathParams.tenantId,
        userId: pathParams.userId,
        grant,
        events,
      });
    },
  );
};
