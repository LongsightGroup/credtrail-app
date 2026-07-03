import {
  actorCanDecideApprovalStep,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  findTenantById,
  findUserById,
  listBadgeIssuanceRuleVersionApprovalEvents,
  listBadgeIssuanceRuleVersionApprovalSteps,
  listBadgeIssuanceRuleVersions,
  listPendingBadgeIssuanceRuleApprovalsForActor,
  type BadgeIssuanceRuleApprovalStepRecord,
  type BadgeIssuanceRuleVersionRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
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
import { buildBadgeRuleVersionDefinitionDiff } from "../badges/badge-rule-version-diff";
import {
  previewBadgeRuleVersionImpact,
  type BadgeRuleImpactPreview,
} from "../lti/badge-rule-impact-preview";
import { renderAppPage } from "../ui/render-page";

interface RegisterTenantBadgeRuleApprovalWorkspaceAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  sha256Hex: (value: string) => Promise<string>;
  resolveBadgeRuleApprovalWorkspaceRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
  >;
}

const actorCanDecideReviewVersion = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    actorUserId: string;
    actorRole: TenantMembershipRole;
    version: BadgeIssuanceRuleVersionRecord;
    approvalSteps: readonly BadgeIssuanceRuleApprovalStepRecord[];
  },
): Promise<boolean> => {
  if (input.version.status !== "pending_approval") {
    return false;
  }

  if (
    input.version.createdByUserId === input.actorUserId ||
    input.version.submittedByUserId === input.actorUserId
  ) {
    return false;
  }

  const pendingStep = input.approvalSteps.find((step) => step.status === "pending");

  if (pendingStep === undefined) {
    return false;
  }

  return actorCanDecideApprovalStep(db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
    step: pendingStep,
  });
};

export const registerTenantBadgeRuleApprovalWorkspaceAdminRoutes = (
  input: RegisterTenantBadgeRuleApprovalWorkspaceAdminRoutesInput,
): void => {
  const { app, resolveDatabase, resolveBadgeRuleApprovalWorkspaceRole, sha256Hex } = input;

  const renderReviewPage = async (
    c: AppContext,
    input: {
      pathParams: ReturnType<typeof parseBadgeIssuanceRuleVersionPathParams>;
      session: SessionRecord;
      membershipRole: TenantMembershipRole;
      impactPreview: BadgeRuleImpactPreview;
    },
  ): Promise<Response> => {
    const { pathParams, session, membershipRole, impactPreview } = input;
    const db = resolveDatabase(c.env);
    const [tenant, user, rule, version, versions, approvalSteps, approvalEvents, flash] =
      await Promise.all([
        findTenantById(db, pathParams.tenantId),
        findUserById(db, session.userId),
        findBadgeIssuanceRuleById(db, pathParams.tenantId, pathParams.ruleId),
        findBadgeIssuanceRuleVersionById(db, pathParams),
        listBadgeIssuanceRuleVersions(db, pathParams),
        listBadgeIssuanceRuleVersionApprovalSteps(db, pathParams),
        listBadgeIssuanceRuleVersionApprovalEvents(db, pathParams),
        consumeAdminListMessageFlash(c, {
          tenantId: pathParams.tenantId,
          userId: session.userId,
          workspace: "rule_approvals",
        }),
      ]);

    if (tenant === null) {
      return c.json({ error: "Tenant not found" }, 404);
    }

    if (rule === null || version === null) {
      return c.json({ error: "Badge rule version not found" }, 404);
    }

    const baseVersion =
      versions
        .filter((candidate) => candidate.versionNumber < version.versionNumber)
        .sort((left, right) => right.versionNumber - left.versionNumber)[0] ?? null;
    const diff =
      baseVersion === null
        ? null
        : buildBadgeRuleVersionDefinitionDiff({
            baseRuleJson: baseVersion.ruleJson,
            selectedRuleJson: version.ruleJson,
          });
    const canDecide = await actorCanDecideReviewVersion(db, {
      tenantId: version.tenantId,
      actorUserId: session.userId,
      actorRole: membershipRole,
      version,
      approvalSteps,
    });

    c.header("Cache-Control", "no-store");

    return renderAppPage(
      c,
      badgeRuleApprovalReviewPage(
        {
          tenant,
          userId: session.userId,
          ...(user?.email === undefined ? {} : { userEmail: user.email }),
          membershipRole,
        },
        {
          rule,
          version,
          baseVersion,
          diff,
          impactPreview,
          approvalSteps,
          approvalEvents,
          canDecide,
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
    const roleCheck = await resolveBadgeRuleApprovalWorkspaceRole(c, pathParams.tenantId, nextPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const impactPreview = await previewBadgeRuleVersionImpact({
      db: resolveDatabase(c.env),
      env: c.env,
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      nowIso: new Date().toISOString(),
      sha256Hex,
    });

    return renderReviewPage(c, {
      pathParams,
      session,
      membershipRole,
      impactPreview,
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
      const roleCheck = await resolveBadgeRuleApprovalWorkspaceRole(
        c,
        pathParams.tenantId,
        nextPath,
      );

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const impactPreview = await previewBadgeRuleVersionImpact({
        db,
        env: c.env,
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
        nowIso: new Date().toISOString(),
        sha256Hex,
      });

      return renderReviewPage(c, {
        pathParams,
        session,
        membershipRole,
        impactPreview,
      });
    },
  );
};
