import {
  activateBadgeIssuanceRuleVersion,
  createAuditLog,
  createBadgeIssuanceRuleVersion,
  decideBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersionApprovalEvents,
  listBadgeIssuanceRuleVersionApprovalSteps,
  listBadgeIssuanceRuleVersions,
  submitBadgeIssuanceRuleVersionForApproval,
  tenantMembershipRoleSatisfiesMinimumRole,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinition,
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleVersionDiffQuery,
  parseBadgeIssuanceRuleVersionPathParams,
  parseCreateBadgeIssuanceRuleVersionRequest,
  parseDecideBadgeIssuanceRuleVersionRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";

interface RegisterBadgeRuleVersionRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ISSUER_ROLES: readonly TenantMembershipRole[];
  ADMIN_ROLES: readonly TenantMembershipRole[];
  TENANT_MEMBER_ROLES: readonly TenantMembershipRole[];
}

interface RuleDefinitionDiffChange {
  path: string;
  changeType: "added" | "removed" | "changed";
  before: unknown;
  after: unknown;
}

const isJsonRecord = (value: unknown): value is Record<string, unknown> => {
  return value !== null && typeof value === "object" && !Array.isArray(value);
};

const areJsonValuesEqual = (left: unknown, right: unknown): boolean => {
  return JSON.stringify(left) === JSON.stringify(right);
};

const collectRuleDefinitionDiff = (
  baseValue: unknown,
  compareValue: unknown,
  path: string,
  changes: RuleDefinitionDiffChange[],
): void => {
  if (areJsonValuesEqual(baseValue, compareValue)) {
    return;
  }

  if (Array.isArray(baseValue) && Array.isArray(compareValue)) {
    const maxLength = Math.max(baseValue.length, compareValue.length);

    for (let index = 0; index < maxLength; index += 1) {
      const childPath = `${path}[${String(index)}]`;

      if (!(index in baseValue)) {
        changes.push({
          path: childPath,
          changeType: "added",
          before: null,
          after: compareValue[index],
        });
        continue;
      }

      if (!(index in compareValue)) {
        changes.push({
          path: childPath,
          changeType: "removed",
          before: baseValue[index],
          after: null,
        });
        continue;
      }

      collectRuleDefinitionDiff(baseValue[index], compareValue[index], childPath, changes);
    }

    return;
  }

  if (isJsonRecord(baseValue) && isJsonRecord(compareValue)) {
    const keySet = new Set<string>([...Object.keys(baseValue), ...Object.keys(compareValue)]);

    for (const key of keySet) {
      const childPath = path.length === 0 ? key : `${path}.${key}`;
      const baseHasKey = Object.prototype.hasOwnProperty.call(baseValue, key);
      const compareHasKey = Object.prototype.hasOwnProperty.call(compareValue, key);

      if (!baseHasKey) {
        changes.push({
          path: childPath,
          changeType: "added",
          before: null,
          after: compareValue[key],
        });
        continue;
      }

      if (!compareHasKey) {
        changes.push({
          path: childPath,
          changeType: "removed",
          before: baseValue[key],
          after: null,
        });
        continue;
      }

      collectRuleDefinitionDiff(baseValue[key], compareValue[key], childPath, changes);
    }

    return;
  }

  changes.push({
    path: path.length === 0 ? "$" : path,
    changeType: "changed",
    before: baseValue,
    after: compareValue,
  });
};

const resolveRuleDefinition = (
  rawRuleJson: string,
): ReturnType<typeof parseBadgeIssuanceRuleDefinition> => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(rawRuleJson) as unknown;
  } catch {
    throw new Error("Stored rule JSON is invalid");
  }

  return parseBadgeIssuanceRuleDefinition(parsed);
};

export const registerBadgeRuleVersionRoutes = (
  input: RegisterBadgeRuleVersionRoutesInput,
): void => {
  const {
    app,
    resolveDatabase,
    requireTenantRole,
    ISSUER_ROLES,
    ADMIN_ROLES,
    TENANT_MEMBER_ROLES,
  } = input;

  app.get("/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/diff", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    let query;

    try {
      query = parseBadgeIssuanceRuleVersionDiffQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule version diff query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const selectedVersion = await findBadgeIssuanceRuleVersionById(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
    });

    if (selectedVersion === null) {
      return c.json(
        {
          error: "Badge rule version not found",
        },
        404,
      );
    }

    const versions = await listBadgeIssuanceRuleVersions(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
    });
    const baseVersion =
      query.baseVersionId === undefined
        ? versions
            .filter((candidate) => candidate.versionNumber < selectedVersion.versionNumber)
            .sort((left, right) => right.versionNumber - left.versionNumber)[0]
        : versions.find((candidate) => candidate.id === query.baseVersionId);

    if (baseVersion === undefined) {
      return c.json(
        {
          error:
            query.baseVersionId === undefined
              ? "No base version found. Specify baseVersionId to compare against."
              : "Base badge rule version not found",
        },
        404,
      );
    }

    const baseDefinition = resolveRuleDefinition(baseVersion.ruleJson);
    const selectedDefinition = resolveRuleDefinition(selectedVersion.ruleJson);
    const changes: RuleDefinitionDiffChange[] = [];

    collectRuleDefinitionDiff(baseDefinition, selectedDefinition, "definition", changes);

    return c.json({
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      selectedVersion: {
        id: selectedVersion.id,
        versionNumber: selectedVersion.versionNumber,
        status: selectedVersion.status,
      },
      baseVersion: {
        id: baseVersion.id,
        versionNumber: baseVersion.versionNumber,
        status: baseVersion.status,
      },
      diff: {
        changed: changes.length > 0,
        changeCount: changes.length,
        changes,
      },
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rules/:ruleId/versions", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    let request;

    try {
      request = parseCreateBadgeIssuanceRuleVersionRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule version payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const existingRule = await findBadgeIssuanceRuleById(
      resolveDatabase(c.env),
      pathParams.tenantId,
      pathParams.ruleId,
    );

    if (existingRule === null) {
      return c.json(
        {
          error: "Badge rule not found",
        },
        404,
      );
    }

    const createdVersion = await createBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      ruleJson: JSON.stringify(request.definition),
      approvalChain: request.approvalChain,
      changeSummary: request.changeSummary,
      createdByUserId: session.userId,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.version_created",
      targetType: "badge_rule_version",
      targetId: createdVersion.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: createdVersion.versionNumber,
        status: createdVersion.status,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        version: createdVersion,
      },
      201,
    );
  });

  app.post(
    "/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/submit-approval",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;
      const currentVersion = await findBadgeIssuanceRuleVersionById(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
      });

      if (currentVersion === null) {
        return c.json(
          {
            error: "Badge rule version not found",
          },
          404,
        );
      }

      if (currentVersion.status !== "draft" && currentVersion.status !== "rejected") {
        return c.json(
          {
            error: `Only draft/rejected versions can be submitted for approval (current: ${currentVersion.status})`,
          },
          409,
        );
      }

      const updatedVersion = await submitBadgeIssuanceRuleVersionForApproval(
        resolveDatabase(c.env),
        {
          tenantId: pathParams.tenantId,
          ruleId: pathParams.ruleId,
          versionId: pathParams.versionId,
          actorUserId: session.userId,
          actorRole: membershipRole,
        },
      );

      if (updatedVersion === null) {
        return c.json(
          {
            error: "Badge rule version not found",
          },
          404,
        );
      }

      await createAuditLog(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        actorUserId: session.userId,
        action: "badge_rule.version_submitted_for_approval",
        targetType: "badge_rule_version",
        targetId: updatedVersion.id,
        metadata: {
          role: membershipRole,
          ruleId: pathParams.ruleId,
          versionNumber: updatedVersion.versionNumber,
          status: updatedVersion.status,
        },
      });

      return c.json({
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        version: updatedVersion,
      });
    },
  );

  app.post("/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/decision", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    let request;

    try {
      request = parseDecideBadgeIssuanceRuleVersionRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule approval decision payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const currentVersion = await findBadgeIssuanceRuleVersionById(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
    });

    if (currentVersion === null) {
      return c.json(
        {
          error: "Badge rule version not found",
        },
        404,
      );
    }

    if (currentVersion.status !== "pending_approval") {
      return c.json(
        {
          error: `Only pending_approval versions can be decided (current: ${currentVersion.status})`,
        },
        409,
      );
    }

    const approvalSteps = await listBadgeIssuanceRuleVersionApprovalSteps(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
    });
    const currentApprovalStep = approvalSteps.find((step) => step.status === "pending");

    if (currentApprovalStep === undefined) {
      return c.json(
        {
          error: "No pending approval step exists for this rule version",
        },
        409,
      );
    }

    if (
      !tenantMembershipRoleSatisfiesMinimumRole(membershipRole, currentApprovalStep.requiredRole)
    ) {
      return c.json(
        {
          error: `Current approval step requires role ${currentApprovalStep.requiredRole}`,
        },
        403,
      );
    }

    const decidedVersion = await decideBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      decision: request.decision,
      actorUserId: session.userId,
      actorRole: membershipRole,
      comment: request.comment,
    });

    if (decidedVersion === null) {
      return c.json(
        {
          error: "Badge rule version is no longer pending approval",
        },
        409,
      );
    }

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.version_approval_decided",
      targetType: "badge_rule_version",
      targetId: decidedVersion.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: decidedVersion.versionNumber,
        stepNumber: currentApprovalStep.stepNumber,
        requiredRole: currentApprovalStep.requiredRole,
        decision: request.decision,
        comment: request.comment ?? null,
        status: decidedVersion.status,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      version: decidedVersion,
    });
  });

  app.get(
    "/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/approval-history",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const version = await findBadgeIssuanceRuleVersionById(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
      });

      if (version === null) {
        return c.json(
          {
            error: "Badge rule version not found",
          },
          404,
        );
      }

      const [steps, events] = await Promise.all([
        listBadgeIssuanceRuleVersionApprovalSteps(resolveDatabase(c.env), {
          tenantId: pathParams.tenantId,
          ruleId: pathParams.ruleId,
          versionId: pathParams.versionId,
        }),
        listBadgeIssuanceRuleVersionApprovalEvents(resolveDatabase(c.env), {
          tenantId: pathParams.tenantId,
          ruleId: pathParams.ruleId,
          versionId: pathParams.versionId,
        }),
      ]);
      const currentStep = steps.find((step) => step.status === "pending") ?? null;

      return c.json({
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        version,
        approval: {
          currentStep,
          steps,
          events,
        },
      });
    },
  );

  app.post("/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/activate", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const currentVersion = await findBadgeIssuanceRuleVersionById(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
    });

    if (currentVersion === null) {
      return c.json(
        {
          error: "Badge rule version not found",
        },
        404,
      );
    }

    if (currentVersion.status !== "approved" && currentVersion.status !== "active") {
      return c.json(
        {
          error: `Only approved versions can be activated (current: ${currentVersion.status})`,
        },
        409,
      );
    }

    const activatedVersion = await activateBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      actorUserId: session.userId,
    });

    if (activatedVersion === null) {
      return c.json(
        {
          error: "Badge rule version not found",
        },
        404,
      );
    }

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.version_activated",
      targetType: "badge_rule_version",
      targetId: activatedVersion.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: activatedVersion.versionNumber,
        status: activatedVersion.status,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      version: activatedVersion,
    });
  });
};
