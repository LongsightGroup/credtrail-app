import {
  countTenantMembershipsByRole,
  createLearnerRecordImportPreview,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  findTenantAuthPolicy,
  findBadgeTemplateById,
  findTenantById,
  listBadgeTemplateImageRevisions,
  findUserById,
  listAccessibleTenantContextsForUser,
  listImportLearnerRecordBatchQueueMessages,
  listTenantAuthProviders,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  listBadgeTemplateImageRevisionCountsByTenant,
  listBadgeTemplates,
  listTenantApiKeys,
  listTenantAssertions,
  listDelegatedIssuingAuthorityGrants,
  listTenantBreakGlassAccounts,
  listTenantLmsConnections,
  listTenantMembers,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  type DelegatedIssuingAuthorityAction,
  type LearnerRecordTrustLevel,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantReportingLifecycleFilter,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { Hono } from "hono";
import {
  parseLearnerRecordImportBatchDefaults,
  parseTenantReportingOverviewQuery,
} from "@credtrail/validation";
import { appPage, type AppPage, renderAppPage } from "../ui/render-page";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { consumeAdminFlashCookie } from "../admin/admin-flash";
import {
  consumeAdminListMessageFlash,
  setAdminListMessageFlash,
} from "../admin/admin-list-message-flash";
import {
  buildIssuedBadgesPagePath,
  issuedBadgesInvalidFiltersError,
  safeParseIssuedBadgesPageQuery,
  shouldLoadIssuedBadgesList,
} from "../admin/issued-badges-admin-helpers";
import {
  loadInstitutionAdminWorkspacePageData,
  renderInstitutionAdminWorkspacePage,
} from "../admin/institution-admin-workspace";
import {
  institutionAdminApiKeysPage,
  institutionAdminDashboardPage,
  institutionAdminIssuedBadgesPage,
  institutionAdminLearnerRecordImportsPage,
  institutionAdminRuleTemplateEditorPage,
  institutionAdminRuleTemplatesPage,
} from "../admin/institution-admin-page";
import {
  renderInstitutionAdminAuthenticationWorkspace,
  renderInstitutionAdminGovernanceDelegationNewWorkspace,
  renderInstitutionAdminGovernanceWorkspace,
  renderInstitutionAdminLmsConnectionEditWorkspace,
  renderInstitutionAdminLmsConnectionNewWorkspace,
  renderInstitutionAdminLmsConnectionsWorkspace,
  renderInstitutionAdminManualIssueWorkspace,
  renderInstitutionAdminMembersWorkspace,
  renderInstitutionAdminOperationsWorkspace,
  renderInstitutionAdminOrgUnitsWorkspace,
  renderInstitutionAdminReviewQueueWorkspace,
  renderInstitutionAdminRulesWorkspace,
} from "../admin/institution-admin-workspace-renderers";
import { registerTenantAccessEnterpriseAdminRoutes } from "./tenant-access-enterprise-admin-routes";
import { registerTenantAccessGovernanceAdminRoutes } from "./tenant-access-governance-admin-routes";
import { registerTenantAccessMembersAdminRoutes } from "./tenant-access-members-admin-routes";
import { registerTenantBadgeRuleActionsAdminRoutes } from "./tenant-badge-rule-actions-admin-routes";
import { registerTenantOperationsAdminRoutes } from "./tenant-operations-admin-routes";
import { registerTenantOrgUnitsAdminRoutes } from "./tenant-org-units-admin-routes";
import type { BadgeTemplateHistoryPanel } from "../admin/institution-admin-templates-page";
import { AdminActions, AdminButtonLink, AdminPageHeader, AdminPanel } from "../admin/components";
import { loadBadgeTemplateHistoryPayload } from "../badges/badge-template-history-payload";
import { parseBadgeTemplateListPageQuery } from "../admin/badge-template-admin-helpers";
import { registerBadgeTemplateEditorArtworkAdminRoutes } from "./badge-template-editor-artwork-admin-routes";
import { registerBadgeTemplateListAdminRoutes } from "./badge-template-list-admin-routes";
import { registerTenantApiKeyAdminRoutes } from "./tenant-api-key-admin-routes";
import { registerTenantIssuedBadgesAdminRoutes } from "./tenant-issued-badges-admin-routes";
import { registerTenantReviewQueueAdminRoutes } from "./tenant-review-queue-admin-routes";
import { registerTenantRuleValueListsAdminRoutes } from "./tenant-rule-value-lists-admin-routes";
import type { IssueBadgeForTenant } from "./badge-rule-evaluation-types";
import { registerTenantLmsConnectionAdminRoutes } from "./tenant-lms-connection-admin-routes";
import { registerTenantAdminPageRoutes } from "./tenant-admin-page-routes";
import { registerTenantAdminReportingPageRoutes } from "./tenant-admin-reporting-page-routes";
import { registerTenantApiKeyRoutes } from "./tenant-api-key-routes";
import { registerTenantAuthManagementRoutes } from "./tenant-auth-management-routes";
import { registerTenantBreakGlassRoutes } from "./tenant-break-glass-routes";
import { registerTenantLearnerRecordAdminRoutes } from "./tenant-learner-record-admin-routes";
import { registerTenantMemberManagementRoutes } from "./tenant-member-management-routes";
import { registerTenantMembershipScopeRoutes } from "./tenant-membership-scope-routes";
import { registerTenantDelegatedAuthorityRoutes } from "./tenant-delegated-authority-routes";
import { registerTenantOrgUnitRoutes } from "./tenant-org-unit-routes";
import { loadInstitutionAdminReportingPageData } from "./tenant-admin-reporting-data-loader";
import { buildLocalTwoFactorPath } from "../auth/break-glass-policy";
import {
  prepareLearnerRecordImportSubmission,
  queueReviewedLearnerRecordImportPreview,
  summarizeLearnerRecordImportProgress,
} from "../learner-record/learner-record-import";
import { createLearnerRecordPresentation } from "../learner-record/learner-record-presentation";
import { loadLearnerRecordExportBundle } from "../learner-record/learner-record-export";
import { applySmartReportingDefaults } from "../reporting/reporting-defaults";
import { buildOrganizationsPath } from "../auth/tenant-context-selection";

interface RegisterTenantGovernanceRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  defaultInstitutionOrgUnitId: (tenantId: string) => string;
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
  requireScopedOrgUnitPermission: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      orgUnitId: string;
      requiredRole: TenantMembershipOrgUnitScopeRole;
      allowWhenNoScopes?: boolean;
    },
  ) => Promise<Response | null>;
  requireDelegatedIssuingAuthorityPermission: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      ownerOrgUnitId: string;
      badgeTemplateId: string;
      requiredAction: DelegatedIssuingAuthorityAction;
    },
  ) => Promise<Response | null>;
  assertionBelongsToTenant: (tenantId: string, assertionId: string) => boolean;
  issueBadgeForTenant: IssueBadgeForTenant;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

const LEARNER_RECORD_IMPORT_PREVIEW_TTL_HOURS = 24;

const addHoursToIso = (fromIso: string, hours: number): string => {
  const fromMs = Date.parse(fromIso);

  if (!Number.isFinite(fromMs)) {
    throw new Error("Invalid ISO timestamp");
  }

  return new Date(fromMs + hours * 60 * 60 * 1000).toISOString();
};

export const adminRoleRequiredPage = (tenantId: string): AppPage => {
  return appPage({
    title: "Admin access required",
    assets: ["institutionAdminCss"],
    variant: "admin",
    body: (
      <section class="ct-admin-content">
        <AdminPageHeader
          as="header"
          title="Admin role required"
          description={
            <>
              Your current organization membership role does not allow institution admin access for{" "}
              <strong>{tenantId}</strong>.
            </>
          }
        />
        <section class="ct-admin ct-stack">
          <AdminPanel>
            <p class="ct-admin__eyebrow">Institution Admin</p>
            <p>
              Ask an existing tenant admin/owner to grant your account an admin role, then retry.
            </p>
            <AdminActions>
              <AdminButtonLink
                href={`/showcase/${encodeURIComponent(tenantId)}`}
                variant="secondary"
              >
                View public badge showcase
              </AdminButtonLink>
            </AdminActions>
          </AdminPanel>
        </section>
      </section>
    ),
  });
};

export const reportingAccessRequiredPage = (tenantId: string): AppPage => {
  return appPage({
    title: "Reporting access required",
    assets: ["institutionAdminCss"],
    variant: "admin",
    body: (
      <section class="ct-admin-content">
        <AdminPageHeader
          as="header"
          title="Reporting access required"
          description={
            <>
              Your current organization membership does not allow reporting access for{" "}
              <strong>{tenantId}</strong>.
            </>
          }
        />
        <section class="ct-admin ct-stack">
          <AdminPanel>
            <p class="ct-admin__eyebrow">Reporting</p>
            <p>
              Ask a tenant admin to grant reporting scope or a broader reporting role, then retry.
            </p>
          </AdminPanel>
        </section>
      </section>
    ),
  });
};

export const registerTenantGovernanceRoutes = (
  input: RegisterTenantGovernanceRoutesInput,
): void => {
  const {
    app,
    resolveDatabase,
    requestTenantMemberInvite,
    requestBreakGlassPasswordReset,
    defaultInstitutionOrgUnitId,
    generateOpaqueToken,
    sha256Hex,
    requireTenantRole,
    requireScopedOrgUnitPermission,
    requireDelegatedIssuingAuthorityPermission,
    assertionBelongsToTenant,
    issueBadgeForTenant,
    ADMIN_ROLES,
    ISSUER_ROLES,
  } = input;

  type InstitutionAdminPageData = Parameters<typeof institutionAdminDashboardPage>[0];
  type InstitutionAdminRuleTemplatesPageData = Parameters<
    typeof institutionAdminRuleTemplatesPage
  >[0];
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

  const getOptionalFormValue = (formData: FormData, name: string): string | undefined => {
    const value = formData.get(name);

    if (typeof value !== "string") {
      return undefined;
    }

    const trimmed = value.trim();
    return trimmed.length === 0 ? undefined : trimmed;
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
    options?: {
      badgeTemplatesIncludeArchived?: boolean;
    },
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
      lmsConnections,
      badgeRules,
      authPolicy,
      authProviders,
      breakGlassAccounts,
    ] = await Promise.all([
      findUserById(db, sessionUserId),
      listBadgeTemplates(db, {
        tenantId,
        includeArchived: options?.badgeTemplatesIncludeArchived ?? false,
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
      listTenantLmsConnections(db, tenantId),
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
      lmsConnections,
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

  const loadInstitutionAdminShellData = async (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
  ): Promise<
    | Pick<
        InstitutionAdminPageData,
        "membershipRole" | "switchOrganizationPath" | "tenant" | "userEmail" | "userId"
      >
    | Response
  > => {
    const db = resolveDatabase(c.env);
    const [tenant, currentUser, accessibleTenantContexts] = await Promise.all([
      findTenantById(db, tenantId),
      findUserById(db, sessionUserId),
      listAccessibleTenantContextsForUser(db, sessionUserId),
    ]);

    if (tenant === null) {
      return c.json(
        {
          error: "Tenant not found",
        },
        404,
      );
    }

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
      switchOrganizationPath,
    };
  };

  const loadInstitutionAdminTemplatesPageData = async (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
    input: {
      includeArchived: boolean;
    },
  ): Promise<InstitutionAdminRuleTemplatesPageData | Response> => {
    const shellData = await loadInstitutionAdminShellData(
      c,
      tenantId,
      sessionUserId,
      membershipRole,
    );

    if (shellData instanceof Response) {
      return shellData;
    }

    const db = resolveDatabase(c.env);
    const [badgeTemplates, badgeTemplateImageRevisionCounts] = await Promise.all([
      listBadgeTemplates(db, {
        tenantId,
        includeArchived: input.includeArchived,
      }),
      listBadgeTemplateImageRevisionCountsByTenant(db, tenantId),
    ]);
    const badgeTemplateImageRevisionCountsById = Object.fromEntries(
      badgeTemplateImageRevisionCounts.map((entry) => [entry.badgeTemplateId, entry.revisionCount]),
    );

    return {
      ...shellData,
      badgeTemplates,
      badgeTemplateImageRevisionCountsById,
      badgeTemplatesPage: {
        searchQuery: "",
        includeArchived: input.includeArchived,
        returnToRuleBuilder: false,
        deepLinkHistoryTemplateId: null,
        deepLinkHistoryUnavailable: null,
      },
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
    return loadInstitutionAdminReportingPageData({
      ...input,
      resolveDatabase,
      loadInstitutionAdminPageData,
      reportingAccessRequiredPage,
    });
  };

  const resolveInstitutionAdminAdminRole = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<
    | Response
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
  > => {
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
        return renderAppPage(c, adminRoleRequiredPage(tenantId), 403);
      }

      return roleCheck;
    }

    return roleCheck;
  };

  const renderInstitutionAdminWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
    renderPage: (pageData: Parameters<typeof institutionAdminDashboardPage>[0]) => AppPage,
  ): Promise<Response> => {
    const roleCheck = await resolveInstitutionAdminAdminRole(c, tenantId, nextPath);

    if (roleCheck instanceof Response) {
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

    return renderAppPage(c, renderPage(pageData));
  };

  const renderInstitutionAdminApiKeysWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<Response> => {
    const loaded = await loadInstitutionAdminWorkspacePageData({
      c,
      tenantId,
      nextPath,
      resolveInstitutionAdminAdminRole,
      loadInstitutionAdminPageData,
    });

    if (loaded instanceof Response) {
      return loaded;
    }

    const { pageData, session } = loaded;
    const flash = await consumeAdminListMessageFlash(c, {
      tenantId,
      userId: session.userId,
      workspace: "access_api_keys",
    });
    const revealedSecret = await consumeAdminFlashCookie(c, {
      kind: "api_key_secret",
      tenantId,
      userId: session.userId,
    });

    return await renderInstitutionAdminWorkspacePage(
      c,
      renderAppPage,
      institutionAdminApiKeysPage({
        ...pageData,
        apiKeysWorkspace: {
          listNotice: flash?.tone === "success" ? flash.message : null,
          listError: flash?.tone === "error" ? flash.message : null,
          revealedSecret,
          openCreatePanel:
            revealedSecret !== null || flash?.tone === "error" || flash?.tone === "success",
        },
      }),
    );
  };

  const renderInstitutionAdminIssuedBadgesWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<Response> => {
    const loaded = await loadInstitutionAdminWorkspacePageData({
      c,
      tenantId,
      nextPath,
      resolveInstitutionAdminAdminRole,
      loadInstitutionAdminPageData,
    });

    if (loaded instanceof Response) {
      return loaded;
    }

    const { pageData, session } = loaded;
    const parsedQuery = safeParseIssuedBadgesPageQuery(c.req.query());

    if (!parsedQuery.ok) {
      await setAdminListMessageFlash(c, {
        tenantId,
        userId: session.userId,
        workspace: "issued_badges",
        tone: "error",
        message: issuedBadgesInvalidFiltersError,
      });

      return c.redirect(buildIssuedBadgesPagePath(tenantId), 303);
    }

    const issuedBadgesQuery = parsedQuery.value;
    const flash = await consumeAdminListMessageFlash(c, {
      tenantId,
      userId: session.userId,
      workspace: "issued_badges",
    });
    const assertions = shouldLoadIssuedBadgesList(c.req.query())
      ? await listTenantAssertions(resolveDatabase(c.env), {
          tenantId,
          ...(issuedBadgesQuery.listQuery.badgeTemplateId === undefined
            ? {}
            : { badgeTemplateId: issuedBadgesQuery.listQuery.badgeTemplateId }),
          ...(issuedBadgesQuery.listQuery.recipientQuery === undefined
            ? {}
            : { recipientQuery: issuedBadgesQuery.listQuery.recipientQuery }),
          ...(issuedBadgesQuery.listQuery.state === undefined
            ? {}
            : { state: issuedBadgesQuery.listQuery.state }),
          ...(issuedBadgesQuery.listQuery.limit === undefined
            ? {}
            : { limit: issuedBadgesQuery.listQuery.limit }),
        })
      : [];

    return await renderInstitutionAdminWorkspacePage(
      c,
      renderAppPage,
      institutionAdminIssuedBadgesPage({
        ...pageData,
        issuedBadgesWorkspace: {
          filters: issuedBadgesQuery.filters,
          assertions,
          listNotice: flash?.tone === "success" ? flash.message : null,
          listError: flash?.tone === "error" ? flash.message : null,
          lifecycleAssertionId: issuedBadgesQuery.lifecycleAssertionId,
          lifecycleMode: issuedBadgesQuery.lifecycleMode,
        },
      }),
    );
  };

  const workspaceRendererDeps = {
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
    loadInstitutionAdminPageData,
  };

  const renderRulesWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<Response> => {
    return renderInstitutionAdminRulesWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );
  };

  const renderReviewQueueWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<Response> => {
    return renderInstitutionAdminReviewQueueWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );
  };

  const renderLmsConnectionsWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminLmsConnectionsWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );

  const renderLmsConnectionNewWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminLmsConnectionNewWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );

  const renderLmsConnectionEditWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminLmsConnectionEditWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );

  const renderAuthenticationWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminAuthenticationWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );

  const renderGovernanceDelegationNewWorkspace = (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) =>
    renderInstitutionAdminGovernanceDelegationNewWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );

  const renderManualIssueWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminManualIssueWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );

  const renderInstitutionAdminTemplatesWorkspace = async (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ): Promise<Response> => {
    const roleCheck = await resolveInstitutionAdminAdminRole(c, tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const searchQuery = (c.req.query("q") ?? "").trim();
    const includeArchived =
      c.req.query("includeArchived") === "1" || c.req.query("includeArchived") === "true";
    const returnToRuleBuilder = c.req.query("returnTo") === "rule-builder";
    const historyParam = c.req.query("history");
    const badgeTemplateIdParam = (c.req.query("badgeTemplateId") ?? "").trim();
    const historyDeepLinkRequested =
      (historyParam === "1" || historyParam === "true") && badgeTemplateIdParam.length > 0;

    if (historyDeepLinkRequested && !includeArchived) {
      const db = resolveDatabase(c.env);
      const deepLinkTemplate = await findBadgeTemplateById(db, tenantId, badgeTemplateIdParam);

      if (deepLinkTemplate?.isArchived === true) {
        const redirectUrl = new URL(c.req.url);
        redirectUrl.searchParams.set("includeArchived", "1");
        return c.redirect(redirectUrl.toString(), 302);
      }
    }

    let deepLinkHistoryTemplateId = historyDeepLinkRequested ? badgeTemplateIdParam : null;
    let deepLinkHistoryUnavailable: "not_found" | null = null;

    const pageData = await loadInstitutionAdminTemplatesPageData(
      c,
      tenantId,
      session.userId,
      membershipRole,
      { includeArchived },
    );

    if (pageData instanceof Response) {
      return pageData;
    }

    // Title/slug/ID search is applied in memory after the tenant list loads. Replace with
    // DB-side filtering when template counts grow large (for example Sakai imports).
    const normalizedSearch = searchQuery.toLowerCase();
    let filteredTemplates =
      normalizedSearch.length === 0
        ? [...pageData.badgeTemplates]
        : pageData.badgeTemplates.filter((template) => {
            return (
              template.title.toLowerCase().includes(normalizedSearch) ||
              template.slug.toLowerCase().includes(normalizedSearch) ||
              template.id.toLowerCase().includes(normalizedSearch)
            );
          });

    if (deepLinkHistoryTemplateId !== null) {
      const deepLinkTemplate = pageData.badgeTemplates.find(
        (template) => template.id === deepLinkHistoryTemplateId,
      );

      if (deepLinkTemplate === undefined) {
        const db = resolveDatabase(c.env);
        const templateFromDb = await findBadgeTemplateById(db, tenantId, deepLinkHistoryTemplateId);

        if (templateFromDb === null) {
          deepLinkHistoryTemplateId = null;
          deepLinkHistoryUnavailable = "not_found";
        } else {
          filteredTemplates = [
            templateFromDb,
            ...filteredTemplates.filter((template) => template.id !== templateFromDb.id),
          ];
        }
      } else if (!filteredTemplates.some((template) => template.id === deepLinkTemplate.id)) {
        filteredTemplates = [
          deepLinkTemplate,
          ...filteredTemplates.filter((template) => template.id !== deepLinkTemplate.id),
        ];
      }
    }

    const autoOpenTemplateAuditTemplateId =
      deepLinkHistoryTemplateId !== null &&
      deepLinkHistoryUnavailable === null &&
      filteredTemplates.some((template) => template.id === deepLinkHistoryTemplateId)
        ? deepLinkHistoryTemplateId
        : null;

    let historyPanel: BadgeTemplateHistoryPanel | null = null;
    let historyLoadError: string | null = null;

    if (autoOpenTemplateAuditTemplateId !== null) {
      const historyTemplate =
        filteredTemplates.find((template) => template.id === autoOpenTemplateAuditTemplateId) ??
        (await findBadgeTemplateById(
          resolveDatabase(c.env),
          tenantId,
          autoOpenTemplateAuditTemplateId,
        ));

      if (historyTemplate === null) {
        historyLoadError = "Unable to load template history. Refresh and try again.";
      } else {
        const db = resolveDatabase(c.env);

        try {
          const [{ timeline, imageRevisionCount }, revisions] = await Promise.all([
            loadBadgeTemplateHistoryPayload(db, {
              tenantId,
              badgeTemplateId: historyTemplate.id,
              limit: 100,
            }),
            listBadgeTemplateImageRevisions(db, {
              tenantId,
              badgeTemplateId: historyTemplate.id,
              limit: 25,
            }),
          ]);

          historyPanel = {
            templateId: historyTemplate.id,
            templateTitle: historyTemplate.title,
            timeline,
            imageRevisionCount,
            revisions,
          };
        } catch {
          historyLoadError = "Unable to load template history. Refresh and try again.";
        }
      }
    }

    const flash = await consumeAdminListMessageFlash(c, {
      tenantId,
      userId: session.userId,
      workspace: "badge_templates",
    });

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      institutionAdminRuleTemplatesPage({
        ...pageData,
        badgeTemplates: filteredTemplates,
        badgeTemplatesPage: {
          searchQuery,
          includeArchived,
          returnToRuleBuilder,
          deepLinkHistoryTemplateId: autoOpenTemplateAuditTemplateId,
          deepLinkHistoryUnavailable,
          historyLoadError,
          listNotice: flash?.tone === "success" ? flash.message : null,
          listError: flash?.tone === "error" ? flash.message : null,
        },
        historyPanel,
      }),
    );
  };

  const parseBadgeTemplateEditorArtworkNotice = (
    query: Record<string, string | string[] | undefined>,
  ): { tone: "success" | "error"; message: string } | null => {
    const artworkErrorRaw = query["artworkError"];
    const artworkError =
      typeof artworkErrorRaw === "string"
        ? artworkErrorRaw.trim()
        : Array.isArray(artworkErrorRaw)
          ? (artworkErrorRaw[0]?.trim() ?? "")
          : "";

    if (artworkError.length > 0) {
      return { tone: "error", message: artworkError };
    }

    const artworkRaw = query["artwork"];
    const artwork =
      typeof artworkRaw === "string"
        ? artworkRaw.trim()
        : Array.isArray(artworkRaw)
          ? (artworkRaw[0]?.trim() ?? "")
          : "";

    if (artwork === "uploaded") {
      return { tone: "success", message: "Approved artwork uploaded." };
    }

    if (artwork === "applied") {
      return { tone: "success", message: "Generated draft applied as approved artwork." };
    }

    return null;
  };

  const parseBadgeTemplateEditorDetailsNotice = (
    query: Record<string, string | string[] | undefined>,
  ): { tone: "success" | "error"; message: string } | null => {
    const detailsErrorRaw = query["detailsError"];
    const detailsError =
      typeof detailsErrorRaw === "string"
        ? detailsErrorRaw.trim()
        : Array.isArray(detailsErrorRaw)
          ? (detailsErrorRaw[0]?.trim() ?? "")
          : "";

    if (detailsError.length > 0) {
      return { tone: "error", message: detailsError };
    }

    const detailsRaw = query["details"];
    const details =
      typeof detailsRaw === "string"
        ? detailsRaw.trim()
        : Array.isArray(detailsRaw)
          ? (detailsRaw[0]?.trim() ?? "")
          : "";

    if (details === "created") {
      return {
        tone: "success",
        message: "Badge template created. Add artwork before using it in rules.",
      };
    }

    if (details === "saved") {
      return { tone: "success", message: "Template details saved." };
    }

    return null;
  };

  const renderInstitutionAdminTemplateEditorWorkspace = async (
    c: AppContext,
    tenantId: string,
    badgeTemplateId: string,
    nextPath: string,
  ): Promise<Response> => {
    const roleCheck = await resolveInstitutionAdminAdminRole(c, tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const shellData = await loadInstitutionAdminShellData(
      c,
      tenantId,
      session.userId,
      membershipRole,
    );

    if (shellData instanceof Response) {
      return shellData;
    }

    const db = resolveDatabase(c.env);
    const [badgeTemplate, imageRevisionCounts] = await Promise.all([
      findBadgeTemplateById(db, tenantId, badgeTemplateId),
      listBadgeTemplateImageRevisionCountsByTenant(db, tenantId),
    ]);

    if (badgeTemplate === null) {
      return c.redirect(`/tenants/${encodeURIComponent(tenantId)}/admin/rules/templates`, 302);
    }

    const revisionCount =
      imageRevisionCounts.find((entry) => entry.badgeTemplateId === badgeTemplate.id)
        ?.revisionCount ?? 0;

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      institutionAdminRuleTemplateEditorPage({
        ...shellData,
        badgeTemplate,
        badgeTemplateImageRevisionCount: revisionCount,
        returnToRuleBuilder: c.req.query("returnTo") === "rule-builder",
        listPageQuery: parseBadgeTemplateListPageQuery(c.req.query()),
        detailsNotice: parseBadgeTemplateEditorDetailsNotice(c.req.query()),
        artworkNotice: parseBadgeTemplateEditorArtworkNotice(c.req.query()),
      }),
    );
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
    return renderAppPage(c, institutionAdminLearnerRecordImportsPage(pageData));
  };

  const handleLearnerRecordImportUpload = async (input: {
    c: AppContext;
    tenantId: string;
    sessionUserId: string;
    membershipRole: TenantMembershipRole;
    mode: "preview" | "apply";
  }): Promise<Response> => {
    const contentType = input.c.req.header("content-type")?.toLowerCase() ?? "";

    if (
      !contentType.includes("multipart/form-data") &&
      !contentType.includes("application/x-www-form-urlencoded")
    ) {
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
    const db = resolveDatabase(input.c.env);

    if (input.mode === "apply") {
      const batchId = getOptionalFormValue(formData, "batchId") ?? "";
      const nowIso = new Date().toISOString();

      if (batchId.length === 0) {
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
              title: "Preview is required before queueing",
              detail: "Preview the CSV first, then use the queue action shown under the preview.",
            },
          },
        );
      }

      let queueResult: Awaited<ReturnType<typeof queueReviewedLearnerRecordImportPreview>>;

      try {
        queueResult = await queueReviewedLearnerRecordImportPreview(db, {
          tenantId: input.tenantId,
          batchId,
          queuedAt: nowIso,
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
              defaultIssuerName: "",
            },
            submission: null,
            feedback: {
              tone: "warning",
              title: "Reviewed preview could not be queued",
              detail:
                "Check import progress before trying again. If this batch does not appear, preview the CSV again.",
            },
          },
        );
      }

      if (queueResult.status === "missing") {
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
              title: "Reviewed preview is no longer available",
              detail: "Preview the CSV again, then use the queue action shown under the preview.",
            },
          },
        );
      }

      if (queueResult.status === "invalid_preview") {
        const defaults = queueResult.defaults ?? {
          defaultTrustLevel: "issuer_verified" as const,
        };
        const defaultIssuerName = defaults.defaultIssuerName ?? "";
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
              title: "Reviewed preview could not be queued",
              detail: "Preview the CSV again so CredTrail can rebuild the reviewed queue payload.",
            },
          },
        );
      }

      const defaultIssuerName = queueResult.defaults.defaultIssuerName ?? "";

      if (queueResult.status === "already_queued") {
        return renderLearnerRecordImportWorkspace(
          input.c,
          input.tenantId,
          input.sessionUserId,
          input.membershipRole,
          {
            defaults: {
              defaultTrustLevel: queueResult.defaults.defaultTrustLevel,
              defaultIssuerName,
            },
            submission: null,
            feedback: {
              tone: "warning",
              title: "Reviewed preview was already queued",
              detail: "Open the import progress table below to review the queued batch.",
            },
          },
        );
      }

      const reports = queueResult.reports;
      const validRows = reports.filter((report) => report.status === "valid").length;
      const invalidRows = reports.length - validRows;

      return renderLearnerRecordImportWorkspace(
        input.c,
        input.tenantId,
        input.sessionUserId,
        input.membershipRole,
        {
          defaults: {
            defaultTrustLevel: queueResult.defaults.defaultTrustLevel,
            defaultIssuerName,
          },
          submission: {
            mode: "apply",
            batchId: queueResult.preview.batchId,
            fileName: queueResult.preview.fileName,
            totalRows: reports.length,
            validRows,
            invalidRows,
            queuedRows: queueResult.queuedRows,
            rows: reports,
            queueForm: null,
          },
          feedback: {
            tone: "success",
            title: "Learner-record import batch queued",
            detail: `Queued ${String(queueResult.queuedRows)} valid rows from ${queueResult.preview.fileName}. Invalid rows were kept out of the queue.`,
          },
        },
      );
    }

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

    let fileContent: string;
    let fileName: string;
    let mimeType: string;

    if (upload instanceof File && upload.size > 0) {
      fileContent = await upload.text();
      fileName = upload.name;
      mimeType = upload.type;
    } else {
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
            detail: 'Attach a CSV file in the "file" field to preview learner-record imports.',
          },
        },
      );
    }

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

    let prepared;
    const requestedAt = new Date().toISOString();

    try {
      prepared = await prepareLearnerRecordImportSubmission(db, {
        tenantId: input.tenantId,
        fileName,
        mimeType,
        content: fileContent,
        defaults,
        requestedAt,
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

    const validRows = prepared.reports.filter((report) => report.status === "valid").length;
    const invalidRows = prepared.reports.length - validRows;

    if (validRows > 0) {
      await createLearnerRecordImportPreview(db, {
        tenantId: input.tenantId,
        batchId: prepared.batchId,
        fileName: prepared.fileName,
        format: prepared.format,
        defaultsJson: JSON.stringify(prepared.defaults),
        reportsJson: JSON.stringify(prepared.reports),
        queuePayloadsJson: JSON.stringify(prepared.queuePayloads),
        createdByUserId: input.sessionUserId,
        createdAt: requestedAt,
        expiresAt: addHoursToIso(requestedAt, LEARNER_RECORD_IMPORT_PREVIEW_TTL_HOURS),
      });
    }

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
          mode: "preview",
          batchId: prepared.batchId,
          fileName: prepared.fileName,
          totalRows: prepared.reports.length,
          validRows,
          invalidRows,
          queuedRows: 0,
          rows: prepared.reports,
          queueForm: validRows > 0 ? { batchId: prepared.batchId } : null,
        },
        feedback: {
          tone: "warning",
          title: "Learner-record import preview ready",
          detail:
            "Review trust classification, smart defaults, and warnings below before queueing the import.",
        },
      },
    );
  };

  registerBadgeTemplateEditorArtworkAdminRoutes({
    app,
    resolveDatabase,
    requireScopedOrgUnitPermission,
    resolveInstitutionAdminAdminRole,
  });

  registerBadgeTemplateListAdminRoutes({
    app,
    resolveDatabase,
    defaultInstitutionOrgUnitId,
    requireScopedOrgUnitPermission,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantApiKeyAdminRoutes({
    app,
    generateOpaqueToken,
    resolveDatabase,
    sha256Hex,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantLmsConnectionAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantIssuedBadgesAdminRoutes({
    app,
    resolveDatabase,
    requireDelegatedIssuingAuthorityPermission,
    assertionBelongsToTenant,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantReviewQueueAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
    issueBadgeForTenant,
  });

  registerTenantRuleValueListsAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessMembersAdminRoutes({
    app,
    assertRoleChangeAllowed,
    canManageTenantRole,
    membershipAuditAction,
    requestInviteForTenantMember,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessGovernanceAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessEnterpriseAdminRoutes({
    app,
    resolveDatabase,
    requireEnterpriseTenant,
    ...(requestBreakGlassPasswordReset === undefined
      ? {}
      : {
          requestBreakGlassPasswordReset: async (c, input) => {
            const status = await requestBreakGlassPasswordReset(c, input);

            if (status === "unavailable") {
              return "failed";
            }

            return status;
          },
        }),
    resolveInstitutionAdminAdminRole,
  });

  registerTenantOrgUnitsAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantBadgeRuleActionsAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantOperationsAdminRoutes({
    app,
    issueBadgeForTenant,
    requireDelegatedIssuingAuthorityPermission,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  const renderMembersWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminMembersWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );

  const renderGovernanceWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminGovernanceWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );

  const renderOrgUnitsWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminOrgUnitsWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );

  const renderOperationsWorkspace = (c: AppContext, tenantId: string, nextPath: string) =>
    renderInstitutionAdminOperationsWorkspace(
      c,
      renderAppPage,
      tenantId,
      nextPath,
      workspaceRendererDeps,
    );

  registerTenantAdminPageRoutes({
    app,
    ADMIN_ROLES,
    adminRoleRequiredPage,
    requireTenantRole,
    redirectToTenantLogin,
    renderInstitutionAdminWorkspace,
    renderInstitutionAdminOperationsWorkspace: renderOperationsWorkspace,
    renderInstitutionAdminMembersWorkspace: renderMembersWorkspace,
    renderInstitutionAdminGovernanceWorkspace: renderGovernanceWorkspace,
    renderInstitutionAdminOrgUnitsWorkspace: renderOrgUnitsWorkspace,
    renderInstitutionAdminApiKeysWorkspace,
    renderInstitutionAdminIssuedBadgesWorkspace,
    renderInstitutionAdminReviewQueueWorkspace: renderReviewQueueWorkspace,
    renderInstitutionAdminRulesWorkspace: renderRulesWorkspace,
    renderInstitutionAdminLmsConnectionsWorkspace: renderLmsConnectionsWorkspace,
    renderInstitutionAdminLmsConnectionNewWorkspace: renderLmsConnectionNewWorkspace,
    renderInstitutionAdminLmsConnectionEditWorkspace: renderLmsConnectionEditWorkspace,
    renderInstitutionAdminAuthenticationWorkspace: renderAuthenticationWorkspace,
    renderInstitutionAdminGovernanceDelegationNewWorkspace: renderGovernanceDelegationNewWorkspace,
    renderInstitutionAdminManualIssueWorkspace: renderManualIssueWorkspace,
    renderInstitutionAdminTemplatesWorkspace,
    renderInstitutionAdminTemplateEditorWorkspace,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantLearnerRecordAdminRoutes({
    app,
    ADMIN_ROLES,
    adminRoleRequiredPage,
    handleLearnerRecordImportUpload,
    loadLearnerRecordReviewPageData,
    redirectToTenantLogin,
    renderLearnerRecordImportWorkspace,
    resolveDatabase,
    requireTenantRole,
  });

  const renderReportingWorkspace = async (
    c: AppContext,
    tenantId: string,
    pagePath: string,
    renderPage: (pageData: InstitutionAdminPageData) => AppPage,
  ): Promise<Response> => {
    const roleCheck = await requireTenantRole(c, tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(c, tenantId, pagePath);
      }

      if (roleCheck.status === 423) {
        return c.redirect(
          buildLocalTwoFactorPath({
            tenantId,
            nextPath: pagePath,
            setup: true,
            reason: "break_glass_mfa_setup_pending",
          }),
          302,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return renderAppPage(c, reportingAccessRequiredPage(tenantId), 403);
      }

      return roleCheck;
    }

    let reportingQuery: ReturnType<typeof parseTenantReportingOverviewQuery>;

    try {
      reportingQuery = applySmartReportingDefaults({
        query: parseTenantReportingOverviewQuery(c.req.query()),
      });
    } catch {
      return c.json(
        {
          error: "Invalid reporting overview query",
        },
        400,
      );
    }

    const { session, membershipRole } = roleCheck;
    const pageData = await loadReportingPageData({
      c,
      tenantId,
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

    c.header("Cache-Control", "no-store");

    return renderAppPage(c, renderPage(pageData));
  };

  registerTenantAdminReportingPageRoutes({
    app,
    renderReportingWorkspace,
  });

  registerTenantAuthManagementRoutes({
    app,
    resolveDatabase,
    requireEnterpriseTenant,
    requireTenantRole,
    ADMIN_ROLES,
  });

  registerTenantMemberManagementRoutes({
    app,
    assertRoleChangeAllowed,
    canManageTenantRole,
    membershipAuditAction,
    requestInviteForTenantMember,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
  });

  registerTenantBreakGlassRoutes({
    app,
    requestBreakGlassPasswordReset,
    requireEnterpriseTenant,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
  });

  registerTenantApiKeyRoutes({
    app,
    generateOpaqueToken,
    resolveDatabase,
    sha256Hex,
    requireTenantRole,
    ADMIN_ROLES,
  });

  registerTenantOrgUnitRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
    ISSUER_ROLES,
  });

  registerTenantMembershipScopeRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
  });

  registerTenantDelegatedAuthorityRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
  });
};
