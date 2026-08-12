import {
  createLtiCourseBadgeRule,
  listTenantLmsConnections,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type BadgeTemplateRecord,
  type LtiResourceLinkPlacementRecord,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import {
  parseBadgeIssuanceRuleDefinition,
  type BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";
import type { LTISession } from "@longsightgroup/lti-tool";
import { resolveExpectedBadgeTemplateRevision } from "../badges/badge-achievement-snapshot";
import { normalizeUniqueStringList } from "../utils/value-parsers";
import { normalizeLtiIssuer } from "./lti-issuer-registry";

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
  workflowStates?: readonly string[] | undefined;
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
        | "missing_course_org_unit_parent"
        | "course_org_unit_slug_conflict"
        | "missing_lms_connection"
        | "invalid_setup_request"
        | "template_changed"
        | "template_artwork_not_immutable"
        | "template_artwork_unavailable"
        | "template_already_used"
        | "approval_policy_rejected"
        | "course_rule_already_configured"
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

export const matchingSakaiLmsConnection = (
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
      const workflowStates = normalizeUniqueStringList(request.workflowStates) ?? ["graded"];

      return parseBadgeIssuanceRuleDefinition({
        conditions: {
          type: "assignment_submission",
          courseId,
          assignmentId,
          requireSubmitted: true,
          workflowStates,
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
  store: ImmutableCredentialStore;
  publicAppOrigin: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  ltiSession: LTISession;
  badgeTemplate: BadgeTemplateRecord;
  contextId: string | null;
  resourceLinkId: string;
  createdByUserId: string;
  createdByRole: TenantMembershipRole;
  delegatedGrantId?: string | undefined;
  courseParentOrgUnitId: string;
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

  const artwork = await resolveExpectedBadgeTemplateRevision({
    store: input.store,
    publicAppOrigin: input.publicAppOrigin,
    template: input.badgeTemplate,
  });

  if (artwork.status === "storage_unavailable") {
    return {
      ok: false,
      reason: "template_artwork_unavailable",
      message: "CredTrail could not check this badge's artwork right now. Try again shortly.",
    };
  }

  if (artwork.status !== "ready") {
    return {
      ok: false,
      reason: "template_artwork_not_immutable",
      message: "Upload this badge's artwork in CredTrail before using it in an awarding rule.",
    };
  }

  const courseTitle = ltiContextTitle(input.ltiSession);
  const created = await createLtiCourseBadgeRule(input.db, {
    tenantId: input.tenantId,
    course: {
      parentOrgUnitId: input.courseParentOrgUnitId,
      externalSystemId: lmsConnection.id,
      externalCourseId: courseId,
      title: courseTitle,
    },
    rule: {
      name: ruleTitle(`Sakai course rule: ${courseTitle} · ${input.badgeTemplate.title}`),
      description: `Created from LTI Deep Linking for ${courseTitle}.`,
      badgeTemplateId: input.badgeTemplate.id,
      expectedBadgeTemplateRevision: artwork.revision,
      lmsProviderKind: "sakai",
      lmsConnectionId: lmsConnection.id,
      ruleJson: JSON.stringify(definition),
      changeSummary: "Created from LTI Deep Linking course badge setup.",
    },
    placement: {
      issuer: input.issuer,
      clientId: input.clientId,
      deploymentId: input.deploymentId,
      contextId: input.contextId,
      resourceLinkId: input.resourceLinkId,
      delegatedGrantId: input.delegatedGrantId ?? null,
    },
    actorUserId: input.createdByUserId,
    actorRole: input.createdByRole,
  });

  if (created.status === "course_org_unit_error") {
    if (created.reason === "slug_conflict") {
      return {
        ok: false,
        reason: "course_org_unit_slug_conflict",
        message:
          "CredTrail found an existing org unit with this course identifier that does not match the expected course scope.",
      };
    }

    return {
      ok: false,
      reason: "missing_course_org_unit_parent",
      message:
        "This course badge setup needs a department or program org-unit scope before CredTrail can create the course rule.",
    };
  }

  if (created.status === "authoring_failed") {
    if (created.reason === "template_changed") {
      return {
        ok: false,
        reason: "template_changed",
        message:
          "The badge template changed while this course rule was being saved. Review it and try again.",
      };
    }

    if (created.reason === "template_artwork_not_immutable") {
      return {
        ok: false,
        reason: "template_artwork_not_immutable",
        message:
          "Upload this badge's artwork in CredTrail before placing it in a course. Managed artwork keeps approved rules and issued credentials unchanged.",
      };
    }

    if (created.reason === "template_reuse_confirmation_required") {
      return {
        ok: false,
        reason: "template_already_used",
        message:
          "This badge is already used by another awarding rule. Choose a different badge template for this course.",
      };
    }

    return {
      ok: false,
      reason: "approval_policy_rejected",
      message:
        created.reason === "self_certification_required"
          ? "This course cannot create a badge rule until an approval policy permits self-certification or defines an approval chain."
          : "This course cannot create a badge rule with the institution's current approval policy.",
    };
  }

  if (created.status === "placement_conflict") {
    return {
      ok: false,
      reason: "course_rule_already_configured",
      message:
        "This Sakai placement already has a different badge rule. Change that rule in CredTrail before placing it again.",
    };
  }

  return {
    ok: true,
    rule: created.rule,
    version: created.version,
    lmsConnection,
    placement: created.placement,
    definition,
  };
};
