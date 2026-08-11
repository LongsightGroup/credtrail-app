import {
  canReopenApprovedBadgeIssuanceRuleVersion,
  findTenantById,
  findUserById,
  listBadgeIssuanceRuleVersionApprovalEvents,
  listBadgeIssuanceRuleVersionApprovalSteps,
  listPendingBadgeIssuanceRuleApprovalsForActor,
  previousBadgeIssuanceRuleVersion,
  type BadgeIssuanceRuleApprovalEventRecord,
  type BadgeIssuanceRuleApprovalStepRecord,
  type TenantRecord,
  type UserRecord,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleVersionPathParams,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import {
  badgeRuleApprovalReviewPage,
  badgeRuleApprovalsQueuePage,
} from "../admin/badge-rule-approval-pages";
import {
  buildBadgeRuleApprovalsPath,
  buildBadgeRuleVersionReviewPath,
} from "../admin/access-admin-helpers";
import { consumeAdminListMessageFlash } from "../admin/admin-list-message-flash";
import type { AppContext, AppEnv } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import {
  actorCanDecideBadgeRuleVersionApproval,
  actorCanViewBadgeRuleVersionApproval,
} from "../badges/badge-rule-approval-access";
import { buildBadgeRuleVersionDefinitionDiff } from "../badges/badge-rule-version-diff";
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
      actorUserId: loaded.session.userId,
      actorRole: loaded.membershipRole,
      version: loaded.version,
      approvalSteps,
    });

    if (!canView) {
      return c.json({ error: "Approval step not assigned to this reviewer" }, 403);
    }

    const [tenant, user, approvalEvents, canDecide] = await Promise.all([
      findTenantById(loaded.db, pathParams.tenantId),
      findUserById(loaded.db, loaded.session.userId),
      listBadgeIssuanceRuleVersionApprovalEvents(loaded.db, pathParams),
      actorCanDecideBadgeRuleVersionApproval(loaded.db, {
        tenantId: loaded.version.tenantId,
        actorUserId: loaded.session.userId,
        actorRole: loaded.membershipRole,
        version: loaded.version,
        approvalSteps,
      }),
    ]);

    if (tenant === null) {
      return c.json({ error: "Tenant not found" }, 404);
    }

    return {
      ...loaded,
      tenant,
      user,
      approvalSteps,
      approvalEvents,
      canDecide,
      canReopen: canReopenApprovedBadgeIssuanceRuleVersion({
        version: loaded.version,
        actorUserId: loaded.session.userId,
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
      userId: data.session.userId,
      workspace: "rule_approvals",
    });

    const baseVersion = previousBadgeIssuanceRuleVersion(data.versions, data.version.versionNumber);
    const diff =
      baseVersion === null
        ? null
        : buildBadgeRuleVersionDefinitionDiff({
            baseRuleJson: baseVersion.ruleJson,
            selectedRuleJson: data.version.ruleJson,
          });

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      badgeRuleApprovalReviewPage(
        {
          tenant: data.tenant,
          userId: data.session.userId,
          ...(data.user?.email === undefined ? {} : { userEmail: data.user.email }),
          membershipRole: data.membershipRole,
        },
        {
          rule: data.rule,
          version: data.version,
          versions: data.versions,
          definition: data.definition,
          baseVersion,
          diff,
          impactPreview,
          approvalSteps: data.approvalSteps,
          approvalEvents: data.approvalEvents,
          canDecide: data.canDecide,
          canReopen: data.canReopen,
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

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const [tenant, user, flash, entries] = await Promise.all([
      findTenantById(db, tenantId),
      findUserById(db, session.userId),
      consumeAdminListMessageFlash(c, {
        tenantId,
        userId: session.userId,
        workspace: "rule_approvals",
      }),
      listPendingBadgeIssuanceRuleApprovalsForActor(db, {
        tenantId,
        actorUserId: session.userId,
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
          userId: session.userId,
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
