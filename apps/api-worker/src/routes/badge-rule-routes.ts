import {
  activateBadgeIssuanceRuleVersion,
  createAuditLog,
  createBadgeIssuanceRule,
  createBadgeIssuanceRuleEvaluation,
  createBadgeIssuanceRuleValueList,
  createBadgeIssuanceRuleVersion,
  decideBadgeIssuanceRuleVersion,
  findActiveBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleEvaluationById,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  findTenantCanvasGradebookIntegration,
  listAuditLogs,
  listBadgeIssuanceRuleEvaluations,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleValueLists,
  listBadgeIssuanceRuleVersionApprovalEvents,
  listBadgeIssuanceRuleVersionApprovalSteps,
  listBadgeIssuanceRuleVersions,
  listIssuedBadgeTemplateIdsForRecipient,
  resolveBadgeIssuanceRuleEvaluationReview,
  submitBadgeIssuanceRuleVersionForApproval,
  updateTenantCanvasGradebookIntegrationTokens,
  type BadgeIssuanceRuleEvaluationRecord,
  type BadgeIssuanceRuleLmsProviderKind,
  type BadgeIssuanceRuleValueListRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { Hono } from "hono";
import {
  parseBadgeIssuanceRuleAuditLogQuery,
  parseBadgeIssuanceRuleDefinition,
  parseBadgeIssuanceRuleEvaluationPathParams,
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleReviewQueueQuery,
  parseBadgeIssuanceRuleValueListQuery,
  parseBadgeIssuanceRuleVersionDiffQuery,
  parseBadgeIssuanceRuleVersionPathParams,
  parseCreateBadgeIssuanceRuleRequest,
  parseCreateBadgeIssuanceRuleValueListRequest,
  parseCreateBadgeIssuanceRuleVersionRequest,
  parseDecideBadgeIssuanceRuleVersionRequest,
  parseEvaluateBadgeIssuanceRuleRequest,
  parsePreviewEvaluateBadgeIssuanceRuleRequest,
  parsePreviewSimulateBadgeIssuanceRuleRequest,
  parseResolveBadgeIssuanceRuleReviewRequest,
  parseTenantPathParams,
  type BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { refreshCanvasAccessToken } from "../lms/canvas-oauth";
import { createGradebookProvider } from "../lms/gradebook-provider";
import {
  evaluateBadgeIssuanceRuleDefinition,
  extractBadgeIssuanceRuleRequirements,
  summarizeBadgeIssuanceRuleEvaluation,
  type BadgeIssuanceRuleCompletionFact,
  type BadgeIssuanceRuleCustomFieldFact,
  type BadgeIssuanceRuleEvaluationFacts,
  type BadgeIssuanceRuleGradeFact,
  type BadgeIssuanceRuleSubmissionFact,
  type BadgeIssuanceRuleSurveyCompletionFact,
} from "../rules/engine";

interface DirectIssueBadgeRequest {
  badgeTemplateId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  idempotencyKey: string;
}

interface DirectIssueBadgeResult {
  status: "issued" | "already_issued";
  assertionId: string;
}

interface IssueBadgeHttpErrorPayload {
  error: string;
  did?: string | undefined;
}

interface IssueBadgeHttpErrorShape {
  statusCode: 400 | 404 | 409 | 422 | 500 | 502;
  payload: IssueBadgeHttpErrorPayload;
}

const isIssueBadgeHttpError = (error: unknown): error is IssueBadgeHttpErrorShape => {
  if (error === null || typeof error !== "object") {
    return false;
  }

  const candidate = error as Partial<IssueBadgeHttpErrorShape> & {
    payload?: { error?: unknown };
  };

  if (
    candidate.statusCode !== 400 &&
    candidate.statusCode !== 404 &&
    candidate.statusCode !== 409 &&
    candidate.statusCode !== 422 &&
    candidate.statusCode !== 500 &&
    candidate.statusCode !== 502
  ) {
    return false;
  }

  if (candidate.payload === undefined) {
    return false;
  }

  if (typeof candidate.payload.error !== "string") {
    return false;
  }

  return true;
};

interface RegisterBadgeRuleRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
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
  issueBadgeForTenant: (
    c: AppContext,
    tenantId: string,
    request: DirectIssueBadgeRequest,
    issuedByUserId?: string,
  ) => Promise<DirectIssueBadgeResult>;
  ISSUER_ROLES: readonly TenantMembershipRole[];
  ADMIN_ROLES: readonly TenantMembershipRole[];
  TENANT_MEMBER_ROLES: readonly TenantMembershipRole[];
}

const isAccessTokenExpired = (accessTokenExpiresAt: string | null, nowIso: string): boolean => {
  if (accessTokenExpiresAt === null) {
    return false;
  }

  const expiryMs = Date.parse(accessTokenExpiresAt);
  const nowMs = Date.parse(nowIso);

  if (!Number.isFinite(expiryMs) || !Number.isFinite(nowMs)) {
    return false;
  }

  return nowMs >= expiryMs;
};

const TENANT_ROLE_RANK: Record<TenantMembershipRole, number> = {
  viewer: 0,
  issuer: 1,
  admin: 2,
  owner: 3,
};

const roleSatisfiesMinimumRole = (
  actorRole: TenantMembershipRole,
  requiredRole: TenantMembershipRole,
): boolean => {
  return TENANT_ROLE_RANK[actorRole] >= TENANT_ROLE_RANK[requiredRole];
};

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

type BadgeRuleEvaluationOutcome = "matched" | "no_match" | "review_required";

function collectRuleValueListReferences(
  condition: BadgeIssuanceRuleDefinition["conditions"],
  output: Set<string>,
): void {
  if ("all" in condition) {
    for (const child of condition.all) {
      collectRuleValueListReferences(child, output);
    }

    return;
  }

  if ("any" in condition) {
    for (const child of condition.any) {
      collectRuleValueListReferences(child, output);
    }

    return;
  }

  if ("not" in condition) {
    collectRuleValueListReferences(condition.not, output);
    return;
  }

  if ("courseListId" in condition && typeof condition.courseListId === "string") {
    output.add(condition.courseListId);
  }

  if ("badgeTemplateListId" in condition && typeof condition.badgeTemplateListId === "string") {
    output.add(condition.badgeTemplateListId);
  }
}

function valueListById(
  valueLists: readonly BadgeIssuanceRuleValueListRecord[],
): Map<string, BadgeIssuanceRuleValueListRecord> {
  return new Map(valueLists.map((valueList) => [valueList.id, valueList]));
}

function resolveCourseListCondition(
  condition:
    | Extract<BadgeIssuanceRuleDefinition["conditions"], { type: "grade_threshold" }>
    | Extract<BadgeIssuanceRuleDefinition["conditions"], { type: "course_completion" }>
    | Extract<BadgeIssuanceRuleDefinition["conditions"], { type: "program_completion" }>,
  valueLists: Map<string, BadgeIssuanceRuleValueListRecord>,
): BadgeIssuanceRuleDefinition["conditions"] {
  if (condition.courseListId === undefined) {
    return condition;
  }

  const valueList = valueLists.get(condition.courseListId);

  if (valueList === undefined) {
    throw new Error(`Rule value list ${condition.courseListId} was not found`);
  }

  if (valueList.kind !== "course_ids") {
    throw new Error(`Rule value list ${condition.courseListId} is not a course list`);
  }

  if (condition.type === "program_completion") {
    return {
      type: "program_completion",
      courseIds: valueList.values,
      ...(condition.minimumCompleted === undefined
        ? {}
        : { minimumCompleted: condition.minimumCompleted }),
    };
  }

  const expandedConditions = valueList.values.map((courseId) => {
    if (condition.type === "grade_threshold") {
      return {
        type: "grade_threshold" as const,
        courseId,
        ...(condition.scoreField === undefined ? {} : { scoreField: condition.scoreField }),
        ...(condition.minScore === undefined ? {} : { minScore: condition.minScore }),
        ...(condition.maxScore === undefined ? {} : { maxScore: condition.maxScore }),
      };
    }

    return {
      type: "course_completion" as const,
      courseId,
      ...(condition.requireCompleted === undefined
        ? {}
        : { requireCompleted: condition.requireCompleted }),
      ...(condition.minCompletionPercent === undefined
        ? {}
        : { minCompletionPercent: condition.minCompletionPercent }),
    };
  });

  return {
    any: expandedConditions,
  };
}

function resolveBadgeTemplateListCondition(
  condition: Extract<BadgeIssuanceRuleDefinition["conditions"], { type: "prerequisite_badge" }>,
  valueLists: Map<string, BadgeIssuanceRuleValueListRecord>,
): BadgeIssuanceRuleDefinition["conditions"] {
  if (condition.badgeTemplateListId === undefined) {
    return condition;
  }

  const valueList = valueLists.get(condition.badgeTemplateListId);

  if (valueList === undefined) {
    throw new Error(`Rule value list ${condition.badgeTemplateListId} was not found`);
  }

  if (valueList.kind !== "badge_template_ids") {
    throw new Error(
      `Rule value list ${condition.badgeTemplateListId} is not a badge-template list`,
    );
  }

  return {
    any: valueList.values.map((badgeTemplateId) => ({
      type: "prerequisite_badge" as const,
      badgeTemplateId,
    })),
  };
}

function resolveRuleConditionValueLists(
  condition: BadgeIssuanceRuleDefinition["conditions"],
  valueLists: Map<string, BadgeIssuanceRuleValueListRecord>,
): BadgeIssuanceRuleDefinition["conditions"] {
  if ("all" in condition) {
    return {
      all: condition.all.map((child) => resolveRuleConditionValueLists(child, valueLists)),
    };
  }

  if ("any" in condition) {
    return {
      any: condition.any.map((child) => resolveRuleConditionValueLists(child, valueLists)),
    };
  }

  if ("not" in condition) {
    return {
      not: resolveRuleConditionValueLists(condition.not, valueLists),
    };
  }

  switch (condition.type) {
    case "grade_threshold":
    case "course_completion":
    case "program_completion":
      return resolveCourseListCondition(condition, valueLists);
    case "prerequisite_badge":
      return resolveBadgeTemplateListCondition(condition, valueLists);
    case "assignment_submission":
    case "survey_completion":
    case "time_window":
    case "custom_field":
      return condition;
  }
}

async function resolveBadgeIssuanceRuleDefinitionValueLists(
  db: SqlDatabase,
  tenantId: string,
  definition: BadgeIssuanceRuleDefinition,
): Promise<BadgeIssuanceRuleDefinition> {
  const referencedValueListIds = new Set<string>();
  collectRuleValueListReferences(definition.conditions, referencedValueListIds);

  if (referencedValueListIds.size === 0) {
    return definition;
  }

  const valueLists = await listBadgeIssuanceRuleValueLists(db, {
    tenantId,
    includeArchived: false,
  });
  const selectedValueLists = valueLists.filter((valueList) =>
    referencedValueListIds.has(valueList.id),
  );
  const resolvedDefinition = {
    ...definition,
    conditions: resolveRuleConditionValueLists(
      definition.conditions,
      valueListById(selectedValueLists),
    ),
  };

  return parseBadgeIssuanceRuleDefinition(resolvedDefinition);
}

function badgeRuleEvaluationOutcome(
  definition: BadgeIssuanceRuleDefinition,
  evaluation: ReturnType<typeof evaluateBadgeIssuanceRuleDefinition>,
): BadgeRuleEvaluationOutcome {
  if (evaluation.matched) {
    return "matched";
  }

  const summary = summarizeBadgeIssuanceRuleEvaluation(evaluation);

  if (definition.options?.reviewOnMissingFacts === true && summary.missingDataCount > 0) {
    return "review_required";
  }

  return "no_match";
}

function parseFactsFromEvaluationRecord(
  evaluationRecord: BadgeIssuanceRuleEvaluationRecord,
): BadgeIssuanceRuleEvaluationFacts | null {
  try {
    const parsed = JSON.parse(evaluationRecord.evaluationJson) as unknown;

    if (parsed === null || typeof parsed !== "object" || !("facts" in parsed)) {
      return null;
    }

    const facts = parsed.facts as Partial<BadgeIssuanceRuleEvaluationFacts>;

    if (typeof facts.learnerId !== "string" || typeof facts.nowIso !== "string") {
      return null;
    }

    return {
      learnerId: facts.learnerId,
      nowIso: facts.nowIso,
      grades: Array.isArray(facts.grades) ? facts.grades : [],
      completions: Array.isArray(facts.completions) ? facts.completions : [],
      submissions: Array.isArray(facts.submissions) ? facts.submissions : [],
      surveyCompletions: Array.isArray(facts.surveyCompletions) ? facts.surveyCompletions : [],
      customFields: Array.isArray(facts.customFields) ? facts.customFields : [],
      earnedBadgeTemplateIds: Array.isArray(facts.earnedBadgeTemplateIds)
        ? facts.earnedBadgeTemplateIds
        : [],
    };
  } catch {
    return null;
  }
}

const loadRuleFacts = async (input: {
  db: SqlDatabase;
  tenantId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  learnerId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  definition: ReturnType<typeof parseBadgeIssuanceRuleDefinition>;
  requestedFacts?: ReturnType<typeof parseEvaluateBadgeIssuanceRuleRequest>["facts"];
  nowIso: string;
}): Promise<BadgeIssuanceRuleEvaluationFacts> => {
  const requestedFacts = input.requestedFacts;

  if (requestedFacts !== undefined) {
    const earnedBadgeTemplateIds =
      requestedFacts.earnedBadgeTemplateIds ??
      (await listIssuedBadgeTemplateIdsForRecipient(input.db, {
        tenantId: input.tenantId,
        recipientIdentity: input.recipientIdentity,
        recipientIdentityType: input.recipientIdentityType,
      }));

    return {
      learnerId: input.learnerId,
      nowIso: requestedFacts.nowIso ?? input.nowIso,
      grades: (requestedFacts.grades ?? []).map((fact) => ({
        courseId: fact.courseId,
        learnerId: fact.learnerId,
        currentScore: fact.currentScore ?? null,
        finalScore: fact.finalScore ?? null,
      })),
      completions: (requestedFacts.completions ?? []).map((fact) => ({
        courseId: fact.courseId,
        learnerId: fact.learnerId,
        completed: fact.completed,
        completionPercent: fact.completionPercent ?? null,
      })),
      submissions: (requestedFacts.submissions ?? []).map((fact) => ({
        courseId: fact.courseId,
        assignmentId: fact.assignmentId,
        learnerId: fact.learnerId,
        score: fact.score ?? null,
        workflowState: fact.workflowState ?? null,
        submittedAt: fact.submittedAt ?? null,
      })),
      surveyCompletions: (requestedFacts.surveyCompletions ?? []).map((fact) => ({
        surveyId: fact.surveyId,
        learnerId: fact.learnerId,
        source: fact.source ?? null,
        completed: fact.completed,
        completedAt: fact.completedAt ?? null,
      })),
      customFields: (requestedFacts.customFields ?? []).map((fact) => ({
        learnerId: fact.learnerId,
        fieldName: fact.fieldName,
        value: fact.value,
      })),
      earnedBadgeTemplateIds,
    };
  }

  const requirements = extractBadgeIssuanceRuleRequirements(input.definition);
  const providerLabel = input.lmsProviderKind === "sakai" ? "Sakai" : "Canvas";

  if (input.lmsProviderKind !== "canvas" && input.lmsProviderKind !== "sakai") {
    throw new Error(
      `Automated rule evaluation is not implemented for LMS provider "${input.lmsProviderKind}"`,
    );
  }

  const integration = await findTenantCanvasGradebookIntegration(input.db, input.tenantId);

  if (integration === null) {
    throw new Error(
      `${providerLabel} gradebook integration is required for automated rule evaluation`,
    );
  }

  let accessToken = integration.accessToken;

  if (accessToken === null) {
    throw new Error(
      `${providerLabel} gradebook integration has no access token. Connect LMS first.`,
    );
  }

  if (
    isAccessTokenExpired(integration.accessTokenExpiresAt, input.nowIso) &&
    integration.refreshToken !== null
  ) {
    const refresh = await refreshCanvasAccessToken({
      tokenEndpoint: integration.tokenEndpoint,
      clientId: integration.clientId,
      clientSecret: integration.clientSecret,
      refreshToken: integration.refreshToken,
    });
    const refreshed = await updateTenantCanvasGradebookIntegrationTokens(input.db, {
      tenantId: input.tenantId,
      accessToken: refresh.accessToken,
      refreshToken: refresh.refreshToken,
      accessTokenExpiresAt:
        refresh.expiresInSeconds === undefined
          ? undefined
          : new Date(Date.parse(input.nowIso) + refresh.expiresInSeconds * 1000).toISOString(),
      refreshTokenExpiresAt:
        refresh.refreshTokenExpiresInSeconds === undefined
          ? undefined
          : new Date(
              Date.parse(input.nowIso) + refresh.refreshTokenExpiresInSeconds * 1000,
            ).toISOString(),
    });

    if (refreshed !== null && refreshed.accessToken !== null) {
      accessToken = refreshed.accessToken;
    }
  }

  const provider = createGradebookProvider({
    config: {
      kind: input.lmsProviderKind,
      apiBaseUrl: integration.apiBaseUrl,
      accessToken,
    },
  });

  const grades: BadgeIssuanceRuleGradeFact[] = [];
  const completions: BadgeIssuanceRuleCompletionFact[] = [];
  const submissions: BadgeIssuanceRuleSubmissionFact[] = [];
  const surveyCompletions: BadgeIssuanceRuleSurveyCompletionFact[] = [];
  const customFields: BadgeIssuanceRuleCustomFieldFact[] = [];

  for (const courseId of requirements.courseIds) {
    const [courseGrades, courseCompletions] = await Promise.all([
      provider.listGrades({
        courseId,
        learnerId: input.learnerId,
      }),
      provider.listCompletions({
        courseId,
        learnerId: input.learnerId,
      }),
    ]);

    grades.push(
      ...courseGrades.map((grade) => ({
        courseId: grade.courseId,
        learnerId: grade.learnerId,
        currentScore: grade.currentScore,
        finalScore: grade.finalScore,
      })),
    );
    completions.push(
      ...courseCompletions.map((completion) => ({
        courseId: completion.courseId,
        learnerId: completion.learnerId,
        completed: completion.completed,
        completionPercent: completion.completionPercent,
      })),
    );
  }

  for (const assignment of requirements.assignmentRefs) {
    const assignmentSubmissions = await provider.listSubmissions({
      courseId: assignment.courseId,
      assignmentId: assignment.assignmentId,
      learnerId: input.learnerId,
    });

    submissions.push(
      ...assignmentSubmissions.map((submission) => ({
        courseId: submission.courseId,
        assignmentId: submission.assignmentId,
        learnerId: submission.learnerId,
        score: submission.score,
        workflowState: submission.workflowState,
        submittedAt: submission.submittedAt,
      })),
    );
  }

  const earnedBadgeTemplateIds = await listIssuedBadgeTemplateIdsForRecipient(input.db, {
    tenantId: input.tenantId,
    recipientIdentity: input.recipientIdentity,
    recipientIdentityType: input.recipientIdentityType,
  });

  return {
    learnerId: input.learnerId,
    nowIso: input.nowIso,
    grades,
    completions,
    submissions,
    surveyCompletions,
    customFields,
    earnedBadgeTemplateIds,
  };
};

export const registerBadgeRuleRoutes = (input: RegisterBadgeRuleRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    requireTenantRole,
    issueBadgeForTenant,
    ISSUER_ROLES,
    ADMIN_ROLES,
    TENANT_MEMBER_ROLES,
  } = input;

  app.get("/v1/tenants/:tenantId/badge-rule-value-lists", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let query;

    try {
      query = parseBadgeIssuanceRuleValueListQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule value-list query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const valueLists = await listBadgeIssuanceRuleValueLists(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ...(query.kind === undefined ? {} : { kind: query.kind }),
      includeArchived: false,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      valueLists,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rule-value-lists", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parseCreateBadgeIssuanceRuleValueListRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule value-list payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const valueList = await createBadgeIssuanceRuleValueList(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      label: request.label,
      kind: request.kind,
      values: request.values,
      createdByUserId: session.userId,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.value_list_created",
      targetType: "badge_rule_value_list",
      targetId: valueList.id,
      metadata: {
        role: membershipRole,
        kind: valueList.kind,
        valueCount: valueList.values.length,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        valueList,
      },
      201,
    );
  });

  app.get("/v1/tenants/:tenantId/badge-rules", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const rules = await listBadgeIssuanceRules(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      rules,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rules", async (c) => {
    const tenantParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parseCreateBadgeIssuanceRuleRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge issuance rule payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, tenantParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const definitionJson = JSON.stringify(request.definition);
    const created = await createBadgeIssuanceRule(resolveDatabase(c.env), {
      tenantId: tenantParams.tenantId,
      name: request.name,
      description: request.description,
      badgeTemplateId: request.badgeTemplateId,
      lmsProviderKind: request.lmsProviderKind,
      ruleJson: definitionJson,
      approvalChain: request.approvalChain,
      changeSummary: request.changeSummary,
      createdByUserId: session.userId,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: tenantParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.created",
      targetType: "badge_rule",
      targetId: created.rule.id,
      metadata: {
        role: membershipRole,
        versionId: created.version.id,
        versionNumber: created.version.versionNumber,
        status: created.version.status,
      },
    });

    return c.json(
      {
        tenantId: tenantParams.tenantId,
        rule: created.rule,
        version: {
          ...created.version,
          definition: request.definition,
        },
      },
      201,
    );
  });

  app.post("/v1/tenants/:tenantId/badge-rules/preview-evaluate", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parsePreviewEvaluateBadgeIssuanceRuleRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule preview payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const nowIso = new Date().toISOString();
    let definition: BadgeIssuanceRuleDefinition;

    try {
      definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
        db,
        pathParams.tenantId,
        request.definition,
      );
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to resolve rule value lists",
        },
        422,
      );
    }

    let facts: BadgeIssuanceRuleEvaluationFacts;

    try {
      facts = await loadRuleFacts({
        db,
        tenantId: pathParams.tenantId,
        lmsProviderKind: request.lmsProviderKind,
        learnerId: request.learnerId,
        recipientIdentity: request.recipientIdentity,
        recipientIdentityType: request.recipientIdentityType,
        definition,
        requestedFacts: request.facts,
        nowIso,
      });
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to load rule facts",
        },
        502,
      );
    }

    const evaluation = evaluateBadgeIssuanceRuleDefinition(definition, facts);
    const evaluationSummary = summarizeBadgeIssuanceRuleEvaluation(evaluation);
    const outcome = badgeRuleEvaluationOutcome(definition, evaluation);

    return c.json({
      tenantId: pathParams.tenantId,
      definition,
      evaluation,
      evaluationSummary,
      outcome,
      facts,
      dryRun: true,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rules/preview-simulate", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let request;

    try {
      request = parsePreviewSimulateBadgeIssuanceRuleRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule simulation payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    let definition: BadgeIssuanceRuleDefinition;

    try {
      definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
        db,
        pathParams.tenantId,
        request.definition,
      );
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to resolve rule value lists",
        },
        422,
      );
    }

    const sampleLimit = request.sampleLimit ?? 25;
    const historicalEvaluations = await listBadgeIssuanceRuleEvaluations(db, {
      tenantId: pathParams.tenantId,
      badgeTemplateId: request.badgeTemplateId,
      limit: sampleLimit,
    });
    const samples = historicalEvaluations
      .map((evaluationRecord) => {
        const facts = parseFactsFromEvaluationRecord(evaluationRecord);

        if (facts === null) {
          return null;
        }

        const projectedEvaluation = evaluateBadgeIssuanceRuleDefinition(definition, facts);
        const projectedOutcome = badgeRuleEvaluationOutcome(definition, projectedEvaluation);
        const projectedSummary = summarizeBadgeIssuanceRuleEvaluation(projectedEvaluation);

        return {
          evaluationId: evaluationRecord.id,
          learnerId: evaluationRecord.learnerId,
          recipientIdentity: evaluationRecord.recipientIdentity,
          historicalMatched: evaluationRecord.matched,
          historicalIssuanceStatus: evaluationRecord.issuanceStatus,
          projectedMatched: projectedEvaluation.matched,
          projectedOutcome,
          projectedSummary,
          changed:
            projectedEvaluation.matched !== evaluationRecord.matched ||
            projectedOutcome !==
              (evaluationRecord.issuanceStatus === "review_required"
                ? "review_required"
                : evaluationRecord.matched
                  ? "matched"
                  : "no_match"),
        };
      })
      .filter((sample): sample is NonNullable<typeof sample> => sample !== null);

    const matchedCount = samples.filter((sample) => sample.projectedOutcome === "matched").length;
    const reviewRequiredCount = samples.filter(
      (sample) => sample.projectedOutcome === "review_required",
    ).length;
    const changedCount = samples.filter((sample) => sample.changed).length;

    return c.json({
      tenantId: pathParams.tenantId,
      sampleCount: samples.length,
      summary: {
        matchedCount,
        reviewRequiredCount,
        noMatchCount: samples.length - matchedCount - reviewRequiredCount,
        changedCount,
        historicalMatchedCount: samples.filter((sample) => sample.historicalMatched).length,
        historicalReviewRequiredCount: samples.filter(
          (sample) => sample.historicalIssuanceStatus === "review_required",
        ).length,
      },
      samples,
    });
  });

  app.get("/v1/tenants/:tenantId/badge-rules/review-queue", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    let query;

    try {
      query = parseBadgeIssuanceRuleReviewQueueQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid review queue query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const reviewStatus = query.status ?? "pending";
    const db = resolveDatabase(c.env);
    const evaluations = await listBadgeIssuanceRuleEvaluations(db, {
      tenantId: pathParams.tenantId,
      issuanceStatus: "review_required",
      reviewStatus,
      limit: query.limit ?? 50,
    });
    const ruleCache = new Map<string, Awaited<ReturnType<typeof findBadgeIssuanceRuleById>>>();
    const queue = await Promise.all(
      evaluations.map(async (evaluationRecord) => {
        let rule = ruleCache.get(evaluationRecord.ruleId);

        if (rule === undefined) {
          rule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, evaluationRecord.ruleId);
          ruleCache.set(evaluationRecord.ruleId, rule);
        }

        const facts = parseFactsFromEvaluationRecord(evaluationRecord);
        const parsedPayload = (() => {
          try {
            return JSON.parse(evaluationRecord.evaluationJson) as unknown;
          } catch {
            return null;
          }
        })();
        const evaluation =
          parsedPayload !== null &&
          typeof parsedPayload === "object" &&
          "evaluation" in parsedPayload &&
          parsedPayload.evaluation !== null &&
          typeof parsedPayload.evaluation === "object"
            ? parsedPayload.evaluation
            : null;
        const summary =
          evaluation !== null &&
          "matched" in evaluation &&
          "tree" in evaluation &&
          typeof evaluation.matched === "boolean" &&
          evaluation.tree !== null &&
          typeof evaluation.tree === "object"
            ? summarizeBadgeIssuanceRuleEvaluation(
                evaluation as ReturnType<typeof evaluateBadgeIssuanceRuleDefinition>,
              )
            : null;

        return {
          ...evaluationRecord,
          ruleName: rule?.name ?? null,
          badgeTemplateId: rule?.badgeTemplateId ?? null,
          facts,
          evaluation,
          evaluationSummary: summary,
        };
      }),
    );

    return c.json({
      tenantId: pathParams.tenantId,
      reviewStatus,
      queue,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rules/review-queue/:evaluationId/resolve", async (c) => {
    const pathParams = parseBadgeIssuanceRuleEvaluationPathParams(c.req.param());
    let request;

    try {
      request = parseResolveBadgeIssuanceRuleReviewRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid review queue resolution payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const evaluationRecord = await findBadgeIssuanceRuleEvaluationById(db, {
      tenantId: pathParams.tenantId,
      evaluationId: pathParams.evaluationId,
    });

    if (evaluationRecord === null) {
      return c.json(
        {
          error: "Review queue entry not found",
        },
        404,
      );
    }

    if (evaluationRecord.reviewStatus !== "pending") {
      return c.json(
        {
          error: "Review queue entry is no longer pending",
        },
        409,
      );
    }

    const rule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, evaluationRecord.ruleId);

    if (rule === null) {
      return c.json(
        {
          error: "Badge rule not found for review queue entry",
        },
        404,
      );
    }

    let issuance: DirectIssueBadgeResult | null = null;

    if (request.decision === "issue") {
      try {
        issuance = await issueBadgeForTenant(
          c,
          pathParams.tenantId,
          {
            badgeTemplateId: rule.badgeTemplateId,
            recipientIdentity: evaluationRecord.recipientIdentity,
            recipientIdentityType: evaluationRecord.recipientIdentityType,
            idempotencyKey: `rule-review:${evaluationRecord.id}`,
          },
          session.userId,
        );
      } catch (error) {
        if (isIssueBadgeHttpError(error)) {
          return c.json(error.payload, error.statusCode);
        }

        return c.json(
          {
            error:
              error instanceof Error ? error.message : "Failed to issue badge from review queue",
          },
          502,
        );
      }
    }

    const resolved = await resolveBadgeIssuanceRuleEvaluationReview(db, {
      tenantId: pathParams.tenantId,
      evaluationId: evaluationRecord.id,
      reviewDecision: request.decision,
      reviewComment: request.comment,
      reviewedByUserId: session.userId,
      issuanceStatus:
        request.decision === "issue" ? (issuance?.status ?? "issued") : "review_dismissed",
      assertionId: request.decision === "issue" ? issuance?.assertionId : undefined,
    });

    if (resolved === null) {
      return c.json(
        {
          error: "Review queue entry is no longer pending",
        },
        409,
      );
    }

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.review_resolved",
      targetType: "badge_rule_evaluation",
      targetId: evaluationRecord.id,
      metadata: {
        role: membershipRole,
        ruleId: evaluationRecord.ruleId,
        versionId: evaluationRecord.versionId,
        decision: request.decision,
        issuanceStatus: resolved.issuanceStatus,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      review: resolved,
      issuance,
    });
  });

  app.get("/v1/tenants/:tenantId/badge-rules/:ruleId", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const rule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, pathParams.ruleId);

    if (rule === null) {
      return c.json(
        {
          error: "Badge rule not found",
        },
        404,
      );
    }

    const versions = await listBadgeIssuanceRuleVersions(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      rule,
      versions,
    });
  });

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

  app.get("/v1/tenants/:tenantId/badge-rules/:ruleId/audit-log", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    let query;

    try {
      query = parseBadgeIssuanceRuleAuditLogQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule audit log query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const rule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, pathParams.ruleId);

    if (rule === null) {
      return c.json(
        {
          error: "Badge rule not found",
        },
        404,
      );
    }

    const versions = await listBadgeIssuanceRuleVersions(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
    });
    const versionIds = new Set(versions.map((version) => version.id));
    const requestedLimit = query.limit ?? 100;
    const logs = await listAuditLogs(db, {
      tenantId: pathParams.tenantId,
      limit: Math.min(500, requestedLimit * 5),
    });
    const filteredLogs = logs
      .filter((log) => {
        if (log.targetType === "badge_rule") {
          return log.targetId === pathParams.ruleId;
        }

        if (log.targetType === "badge_rule_version") {
          return versionIds.has(log.targetId);
        }

        return false;
      })
      .slice(0, requestedLimit);

    return c.json({
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      logs: filteredLogs,
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

    if (!roleSatisfiesMinimumRole(membershipRole, currentApprovalStep.requiredRole)) {
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

  app.post("/v1/tenants/:tenantId/badge-rules/:ruleId/evaluate", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    let request;

    try {
      request = parseEvaluateBadgeIssuanceRuleRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule evaluation payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const rule = await findBadgeIssuanceRuleById(db, pathParams.tenantId, pathParams.ruleId);

    if (rule === null) {
      return c.json(
        {
          error: "Badge rule not found",
        },
        404,
      );
    }

    const selectedVersion =
      request.versionId === undefined
        ? await findActiveBadgeIssuanceRuleVersion(db, {
            tenantId: pathParams.tenantId,
            ruleId: pathParams.ruleId,
          })
        : await findBadgeIssuanceRuleVersionById(db, {
            tenantId: pathParams.tenantId,
            ruleId: pathParams.ruleId,
            versionId: request.versionId,
          });

    if (selectedVersion === null) {
      return c.json(
        {
          error:
            request.versionId === undefined
              ? "No active rule version found. Activate an approved version first."
              : "Badge rule version not found",
        },
        404,
      );
    }

    let definition: BadgeIssuanceRuleDefinition;

    try {
      definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
        db,
        pathParams.tenantId,
        resolveRuleDefinition(selectedVersion.ruleJson),
      );
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to resolve rule value lists",
        },
        422,
      );
    }
    const nowIso = new Date().toISOString();

    let facts: BadgeIssuanceRuleEvaluationFacts;

    try {
      facts = await loadRuleFacts({
        db,
        tenantId: pathParams.tenantId,
        lmsProviderKind: rule.lmsProviderKind,
        learnerId: request.learnerId,
        recipientIdentity: request.recipientIdentity,
        recipientIdentityType: request.recipientIdentityType,
        definition,
        requestedFacts: request.facts,
        nowIso,
      });
    } catch (error) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Failed to load rule facts",
        },
        502,
      );
    }

    const evaluation = evaluateBadgeIssuanceRuleDefinition(definition, facts);
    const evaluationSummary = summarizeBadgeIssuanceRuleEvaluation(evaluation);
    const outcome = badgeRuleEvaluationOutcome(definition, evaluation);
    const dryRun = request.dryRun ?? false;
    let issuance: DirectIssueBadgeResult | null = null;

    if (evaluation.matched && !dryRun) {
      try {
        issuance = await issueBadgeForTenant(
          c,
          pathParams.tenantId,
          {
            badgeTemplateId: rule.badgeTemplateId,
            recipientIdentity: request.recipientIdentity,
            recipientIdentityType: request.recipientIdentityType,
            idempotencyKey: `rule:${rule.id}:v${String(selectedVersion.versionNumber)}:${request.learnerId}`,
          },
          session.userId,
        );
      } catch (error) {
        if (isIssueBadgeHttpError(error)) {
          return c.json(error.payload, error.statusCode);
        }

        return c.json(
          {
            error:
              error instanceof Error ? error.message : "Failed to issue badge for matched rule",
          },
          502,
        );
      }
    }

    const evaluationRecord = await createBadgeIssuanceRuleEvaluation(db, {
      tenantId: pathParams.tenantId,
      ruleId: rule.id,
      versionId: selectedVersion.id,
      learnerId: request.learnerId,
      recipientIdentity: request.recipientIdentity,
      recipientIdentityType: request.recipientIdentityType,
      matched: evaluation.matched,
      issuanceStatus:
        outcome === "review_required" && !dryRun ? "review_required" : issuance?.status,
      assertionId: issuance?.assertionId,
      evaluationJson: JSON.stringify({
        dryRun,
        outcome,
        evaluation,
        evaluationSummary,
        facts,
      }),
      ...(outcome === "review_required" && !dryRun ? { reviewStatus: "pending" as const } : {}),
      evaluatedAt: facts.nowIso,
    });

    await createAuditLog(db, {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.evaluated",
      targetType: "badge_rule",
      targetId: rule.id,
      metadata: {
        role: membershipRole,
        versionId: selectedVersion.id,
        versionNumber: selectedVersion.versionNumber,
        learnerId: request.learnerId,
        dryRun,
        matched: evaluation.matched,
        outcome,
        issuanceStatus: issuance?.status ?? null,
        assertionId: issuance?.assertionId ?? null,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      rule,
      version: selectedVersion,
      definition,
      evaluation,
      evaluationSummary,
      outcome,
      dryRun,
      issuance,
      evaluationRecord,
    });
  });
};
