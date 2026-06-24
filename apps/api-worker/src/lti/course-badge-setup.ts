import {
  createBadgeIssuanceRuleWithConnection,
  listTenantLmsConnections,
  runSqlTransaction,
  upsertLtiResourceLinkPlacement,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type BadgeTemplateRecord,
  type LtiResourceLinkPlacementRecord,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinition,
  type BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";
import type { LTISession } from "@lti-tool/core";
import { normalizeLtiIssuer } from "./lti-helpers";

export type LtiCourseBadgeSetupPreset =
  | "manual_instructor_approval"
  | "final_course_score_threshold"
  | "gradebook_item_score_threshold"
  | "assignment_submitted_or_graded"
  | "completion_percentage";

export interface LtiCourseBadgeSetupRequest {
  preset: LtiCourseBadgeSetupPreset;
  scoreThreshold?: number | undefined;
  gradebookItemId?: string | undefined;
  completionPercent?: number | undefined;
}

export interface LtiCourseBadgeSetupPresetSpec {
  value: LtiCourseBadgeSetupPreset;
  label: string;
  checkedByDefault?: boolean | undefined;
}

export const LTI_COURSE_BADGE_SETUP_PRESETS: readonly LtiCourseBadgeSetupPresetSpec[] = [
  {
    value: "manual_instructor_approval",
    label: "Manual instructor approval",
    checkedByDefault: true,
  },
  {
    value: "final_course_score_threshold",
    label: "Final course score threshold",
  },
  {
    value: "gradebook_item_score_threshold",
    label: "Gradebook item score threshold",
  },
  {
    value: "assignment_submitted_or_graded",
    label: "Assignment or assessment submitted or graded",
  },
  {
    value: "completion_percentage",
    label: "Course completion percentage",
  },
];

const isLtiCourseBadgeSetupPreset = (value: string): value is LtiCourseBadgeSetupPreset => {
  return LTI_COURSE_BADGE_SETUP_PRESETS.some((preset) => preset.value === value);
};

export const parseLtiCourseBadgeSetupPreset = (
  value: string | null | undefined,
): LtiCourseBadgeSetupPreset | null => {
  if (value === null || value === undefined) {
    return null;
  }

  const normalized = value.trim();

  if (!isLtiCourseBadgeSetupPreset(normalized)) {
    return null;
  }

  return normalized;
};

export type CreateCourseBadgePlacementRuleResult =
  | {
      ok: true;
      rule: BadgeIssuanceRuleRecord;
      version: BadgeIssuanceRuleVersionRecord;
      lmsConnection: TenantLmsConnectionRecord;
      placement: LtiResourceLinkPlacementRecord;
      definition: BadgeIssuanceRuleDefinition;
    }
  | {
      ok: false;
      reason:
        | "missing_course_context"
        | "missing_lms_connection"
        | "invalid_setup_request"
        | "unsupported_lms_connection";
      message: string;
    };

const normalizeOptionalText = (value: string | undefined): string | undefined => {
  const normalized = value?.trim();
  return normalized === undefined || normalized.length === 0 ? undefined : normalized;
};

const boundedPercent = (value: number | undefined): number | undefined => {
  if (value === undefined || !Number.isFinite(value)) {
    return undefined;
  }

  return Math.min(100, Math.max(0, value));
};

const ruleTitle = (value: string): string => {
  return value.length <= 200 ? value : `${value.slice(0, 197)}...`;
};

const ltiContextTitle = (ltiSession: LTISession): string => {
  return ltiSession.context.title.trim().length > 0
    ? ltiSession.context.title.trim()
    : ltiSession.context.id;
};

const matchingSakaiLmsConnection = (
  connections: readonly TenantLmsConnectionRecord[],
  input: {
    issuer: string;
    clientId: string;
    deploymentId: string;
  },
): TenantLmsConnectionRecord | null => {
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);

  return (
    connections.find((connection) => {
      return (
        connection.providerKind === "sakai" &&
        connection.ltiIssuer !== null &&
        normalizeLtiIssuer(connection.ltiIssuer) === normalizedIssuer &&
        connection.ltiClientId === input.clientId &&
        connection.ltiDeploymentId === input.deploymentId
      );
    }) ?? null
  );
};

export const ltiCourseBadgeSetupRuleDefinition = (
  courseId: string,
  request: LtiCourseBadgeSetupRequest,
): BadgeIssuanceRuleDefinition | null => {
  switch (request.preset) {
    case "manual_instructor_approval":
      return parseBadgeIssuanceRuleDefinition({
        conditions: {
          type: "course_completion",
          courseId,
          minCompletionPercent: 0,
        },
        options: {
          issuanceTiming: "manual",
          reviewOnMissingFacts: true,
        },
      });
    case "final_course_score_threshold": {
      const minScore = boundedPercent(request.scoreThreshold);
      if (minScore === undefined) {
        return null;
      }

      return parseBadgeIssuanceRuleDefinition({
        conditions: {
          type: "grade_threshold",
          courseId,
          scoreField: "final_score",
          minScore,
        },
        options: {
          reviewOnMissingFacts: true,
        },
      });
    }
    case "gradebook_item_score_threshold": {
      const minScore = boundedPercent(request.scoreThreshold);
      const assignmentId = normalizeOptionalText(request.gradebookItemId);
      if (minScore === undefined || assignmentId === undefined) {
        return null;
      }

      return parseBadgeIssuanceRuleDefinition({
        conditions: {
          type: "assignment_submission",
          courseId,
          assignmentId,
          requireSubmitted: true,
          minScore,
        },
        options: {
          reviewOnMissingFacts: true,
        },
      });
    }
    case "assignment_submitted_or_graded": {
      const assignmentId = normalizeOptionalText(request.gradebookItemId);
      if (assignmentId === undefined) {
        return null;
      }

      return parseBadgeIssuanceRuleDefinition({
        conditions: {
          type: "assignment_submission",
          courseId,
          assignmentId,
          requireSubmitted: true,
          workflowStates: ["submitted", "graded", "returned"],
        },
        options: {
          reviewOnMissingFacts: true,
        },
      });
    }
    case "completion_percentage": {
      const minCompletionPercent = boundedPercent(request.completionPercent);
      if (minCompletionPercent === undefined) {
        return null;
      }

      return parseBadgeIssuanceRuleDefinition({
        conditions: {
          type: "course_completion",
          courseId,
          minCompletionPercent,
        },
        options: {
          reviewOnMissingFacts: true,
        },
      });
    }
  }
};

export const createCourseBadgePlacementRule = async (input: {
  db: SqlDatabase;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  ltiSession: LTISession;
  badgeTemplate: BadgeTemplateRecord;
  contextId: string | null;
  resourceLinkId: string;
  createdByUserId: string;
  setupRequest: LtiCourseBadgeSetupRequest;
}): Promise<CreateCourseBadgePlacementRuleResult> => {
  const courseId = input.ltiSession.context.id.trim();

  if (courseId.length === 0) {
    return {
      ok: false,
      reason: "missing_course_context",
      message: "CredTrail could not identify the LMS course for this badge setup.",
    };
  }

  const connections = await listTenantLmsConnections(input.db, input.tenantId);
  const lmsConnection = matchingSakaiLmsConnection(connections, {
    issuer: input.issuer,
    clientId: input.clientId,
    deploymentId: input.deploymentId,
  });

  if (lmsConnection === null) {
    return {
      ok: false,
      reason: "missing_lms_connection",
      message:
        "CredTrail could not find a Sakai LMS connection linked to this LTI launch. Finish setup in CredTrail before placing this badge.",
    };
  }

  if (lmsConnection.providerKind !== "sakai") {
    return {
      ok: false,
      reason: "unsupported_lms_connection",
      message: "This LTI course badge setup currently supports Sakai LMS connections.",
    };
  }

  const definition = ltiCourseBadgeSetupRuleDefinition(courseId, input.setupRequest);

  if (definition === null) {
    return {
      ok: false,
      reason: "invalid_setup_request",
      message: "Choose a criterion and provide the required threshold or gradebook item.",
    };
  }

  const created = await runSqlTransaction(input.db, async (transactionDb) => {
    const rule = await createBadgeIssuanceRuleWithConnection(transactionDb, {
      tenantId: input.tenantId,
      name: ruleTitle(
        `Sakai course rule: ${ltiContextTitle(input.ltiSession)} · ${input.badgeTemplate.title}`,
      ),
      description: `Created from LTI Deep Linking for ${ltiContextTitle(input.ltiSession)}.`,
      badgeTemplateId: input.badgeTemplate.id,
      lmsProviderKind: "sakai",
      lmsConnectionId: lmsConnection.id,
      ruleJson: JSON.stringify(definition),
      changeSummary: "Created from LTI Deep Linking course badge setup.",
      createdByUserId: input.createdByUserId,
    });
    const placement = await upsertLtiResourceLinkPlacement(transactionDb, {
      tenantId: input.tenantId,
      issuer: input.issuer,
      clientId: input.clientId,
      deploymentId: input.deploymentId,
      contextId: input.contextId,
      resourceLinkId: input.resourceLinkId,
      badgeTemplateId: input.badgeTemplate.id,
      ruleId: rule.rule.id,
      createdByUserId: input.createdByUserId,
    });

    return {
      ...rule,
      placement,
    };
  });

  return {
    ok: true,
    rule: created.rule,
    version: created.version,
    lmsConnection,
    placement: created.placement,
    definition,
  };
};
