import {
  canReopenApprovedBadgeIssuanceRuleVersion,
  findTenantById,
  findUserById,
  listBadgeIssuanceRuleVersionApprovalEvents,
  listBadgeIssuanceRuleVersionApprovalSteps,
  listPendingBadgeIssuanceRuleApprovalsForActor,
  type BadgeIssuanceRuleApprovalEventRecord,
  type BadgeIssuanceRuleApprovalStepRecord,
  type TenantRecord,
  type UserRecord,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleVersionSelectionQuery,
  parseBadgeIssuanceRuleVersionPathParams,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { badgeRuleApprovalsQueuePage } from "../admin/badge-rule-approval-pages";
import { buildBadgeRuleReviewAction } from "../admin/badge-rule-approval-review-model";
import { badgeRuleApprovalReviewPage } from "../admin/badge-rule-approval-review-page";
import { buildBadgeRuleVersionNavigationModel } from "../admin/badge-rule-version-navigator";
import {
  buildBadgeRuleApprovalsPath,
  buildBadgeRuleVersionReviewPath,
} from "../admin/access-admin-helpers";
import { consumeAdminListMessageFlash } from "../admin/admin-list-message-flash";
import type { AppContext, AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import {
  actorCanDecideBadgeRuleVersionApproval,
  actorCanViewBadgeRuleVersionApproval,
} from "../badges/badge-rule-approval-access";
import {
  previewBadgeRuleVersionImpact,
  type BadgeRuleImpactPreview,
} from "../lti/badge-rule-impact-preview";
import { renderAppPage } from "../ui/render-page";
import {
  loadBadgeRuleVersionPageContext,
  type BadgeRuleVersionPageContext,
  type ResolveBadgeRuleVersionPageActor,
} from "./badge-rule-version-page-context";

interface RegisterTenantBadgeRuleApprovalWorkspaceAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  sha256Hex: (value: string) => Promise<string>;
  resolveBadgeRuleApprovalWorkspaceRole: ResolveBadgeRuleVersionPageActor;
}

interface AuthorizedReviewPageData extends BadgeRuleVersionPageContext {
  readonly tenant: TenantRecord;
  readonly user: UserRecord | null;
  readonly submittedByUser: UserRecord | null;
  readonly approvalSteps: readonly BadgeIssuanceRuleApprovalStepRecord[];
  readonly approvalEvents: readonly BadgeIssuanceRuleApprovalEventRecord[];
  readonly canDecide: boolean;
  readonly canReopen: boolean;
}

export const registerTenantBadgeRuleApprovalWorkspaceAdminRoutes = (
  input: RegisterTenantBadgeRuleApprovalWorkspaceAdminRoutesInput,
): void => {
  const { app, resolveDatabase, resolveBadgeRuleApprovalWorkspaceRole, sha256Hex } = input;

  const loadAuthorizedReviewPageData = async (
    c: AppContext,
    input: {
      pathParams: ReturnType<typeof parseBadgeIssuanceRuleVersionPathParams>;
      nextPath: string;
    },
  ): Promise<Response | AuthorizedReviewPageData> => {
    const { pathParams } = input;
    const loaded = await loadBadgeRuleVersionPageContext(c, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      nextPath: input.nextPath,
      resolveDatabase,
      resolveActor: resolveBadgeRuleApprovalWorkspaceRole,
    });

    if (loaded instanceof Response) {
      return loaded;
    }

    const approvalSteps = await listBadgeIssuanceRuleVersionApprovalSteps(loaded.db, pathParams);

    const canView = await actorCanViewBadgeRuleVersionApproval(loaded.db, {
      tenantId: loaded.version.tenantId,
      actorUserId: loaded.principal.userId,
      actorRole: loaded.membershipRole,
      version: loaded.version,
      approvalSteps,
    });

    if (!canView) {
      return c.json({ error: "Approval step not assigned to this reviewer" }, 403);
    }

    const submittedByUserPromise =
      loaded.version.submittedByUserId === null
        ? Promise.resolve(null)
        : findUserById(loaded.db, loaded.version.submittedByUserId);
    const [tenant, user, submittedByUser, approvalEvents, canDecide] = await Promise.all([
      findTenantById(loaded.db, pathParams.tenantId),
      findUserById(loaded.db, loaded.principal.userId),
      submittedByUserPromise,
      listBadgeIssuanceRuleVersionApprovalEvents(loaded.db, pathParams),
      actorCanDecideBadgeRuleVersionApproval(loaded.db, {
        tenantId: loaded.version.tenantId,
        actorUserId: loaded.principal.userId,
        actorRole: loaded.membershipRole,
        version: loaded.version,
        approvalSteps,
      }),
    ]);

    if (tenant === null) {
      return c.json({ error: "Tenant not found" }, 404);
    }

    if (loaded.version.submittedByUserId !== null && submittedByUser === null) {
      return c.json({ error: "Badge rule submitter not found" }, 409);
    }

    return {
      ...loaded,
      tenant,
      user,
      submittedByUser,
      approvalSteps,
      approvalEvents,
      canDecide,
      canReopen: canReopenApprovedBadgeIssuanceRuleVersion({
        version: loaded.version,
        actorUserId: loaded.principal.userId,
        actorRole: loaded.membershipRole,
      }),
    };
  };

  const renderReviewPage = async (
    c: AppContext,
    input: {
      data: AuthorizedReviewPageData;
      impactPreview: BadgeRuleImpactPreview;
    },
  ): Promise<Response> => {
    const { data, impactPreview } = input;
    const flash = await consumeAdminListMessageFlash(c, {
      tenantId: data.tenant.id,
      userId: data.principal.userId,
      workspace: "rule_approvals",
    });
    const navigation = buildBadgeRuleVersionNavigationModel({
      rule: data.rule,
      selectedVersion: data.version,
      versions: data.versions,
    });

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      badgeRuleApprovalReviewPage(
        {
          tenant: data.tenant,
          userId: data.principal.userId,
          ...(data.user?.email === undefined ? {} : { userEmail: data.user.email }),
          membershipRole: data.membershipRole,
        },
        {
          rule: data.rule,
          navigation,
          definition: data.definition,
          orgUnit: data.orgUnit,
          submittedByEmail: data.submittedByUser?.email ?? null,
          impactPreview,
          approvalSteps: data.approvalSteps,
          approvalEvents: data.approvalEvents,
          action: buildBadgeRuleReviewAction({
            canDecide: data.canDecide,
            canReopen: data.canReopen,
          }),
          listNotice: flash?.tone === "success" ? flash.message : null,
          listError: flash?.tone === "error" ? flash.message : null,
        },
      ),
    );
  };

  app.get("/tenants/:tenantId/admin/rules/approvals", async (c) => {
    const { tenantId } = parseTenantPathParams(c.req.param());
    const nextPath = buildBadgeRuleApprovalsPath(tenantId);
    const roleCheck = await resolveBadgeRuleApprovalWorkspaceRole(c, tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { principal, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const [tenant, user, flash, entries] = await Promise.all([
      findTenantById(db, tenantId),
      findUserById(db, principal.userId),
      consumeAdminListMessageFlash(c, {
        tenantId,
        userId: principal.userId,
        workspace: "rule_approvals",
      }),
      listPendingBadgeIssuanceRuleApprovalsForActor(db, {
        tenantId,
        actorUserId: principal.userId,
        actorRole: membershipRole,
        limit: 100,
      }),
    ]);

    if (tenant === null) {
      return c.json({ error: "Tenant not found" }, 404);
    }

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      badgeRuleApprovalsQueuePage(
        {
          tenant,
          userId: principal.userId,
          ...(user?.email === undefined ? {} : { userEmail: user.email }),
          membershipRole,
        },
        {
          entries,
          listNotice: flash?.tone === "success" ? flash.message : null,
          listError: flash?.tone === "error" ? flash.message : null,
        },
      ),
    );
  });

  app.get("/tenants/:tenantId/admin/rules/approvals/:ruleId", (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    let query: ReturnType<typeof parseBadgeIssuanceRuleVersionSelectionQuery>;

    try {
      query = parseBadgeIssuanceRuleVersionSelectionQuery(c.req.query());
    } catch {
      return c.json({ error: "Invalid badge rule version selection" }, 400);
    }

    c.header("Cache-Control", "no-store");

    if (query.versionId === undefined) {
      return c.redirect(buildBadgeRuleApprovalsPath(pathParams.tenantId), 302);
    }

    return c.redirect(
      buildBadgeRuleVersionReviewPath(pathParams.tenantId, pathParams.ruleId, query.versionId),
      302,
    );
  });

  app.get("/tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    const nextPath = buildBadgeRuleVersionReviewPath(
      pathParams.tenantId,
      pathParams.ruleId,
      pathParams.versionId,
    );
    const reviewData = await loadAuthorizedReviewPageData(c, {
      pathParams,
      nextPath,
    });

    if (reviewData instanceof Response) {
      return reviewData;
    }

    return renderReviewPage(c, {
      data: reviewData,
      impactPreview: { status: "not_requested" },
    });
  });

  app.post(
    "/tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId/impact-preview",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      const nextPath = buildBadgeRuleVersionReviewPath(
        pathParams.tenantId,
        pathParams.ruleId,
        pathParams.versionId,
      );
      const reviewData = await loadAuthorizedReviewPageData(c, {
        pathParams,
        nextPath,
      });

      if (reviewData instanceof Response) {
        return reviewData;
      }

      const impactPreview = await previewBadgeRuleVersionImpact({
        db: reviewData.db,
        env: c.env,
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
        nowIso: new Date().toISOString(),
        sha256Hex,
      });

      return renderReviewPage(c, {
        data: reviewData,
        impactPreview,
      });
    },
  );
};
