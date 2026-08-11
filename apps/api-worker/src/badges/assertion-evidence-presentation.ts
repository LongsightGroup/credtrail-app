import type { AssertionIssuanceProvenanceSource } from "@credtrail/db";
import { parseIssuanceEvidenceSnapshotJson } from "@credtrail/validation";
import { tenantMembershipRoleLabel } from "../admin/tenant-membership-role-labels";
import { inferLegacyIssuanceSource } from "./assertion-evidence-legacy-inference";
import type { AssertionEvidenceLoadedData } from "./assertion-evidence-payload";
import {
  flattenEvaluationTree,
  summarizeEvaluationFacts,
  type AssertionEvidenceEvaluationOutcomeRow,
} from "./assertion-evidence-evaluation-display";

export type AssertionEvidenceIssuanceSource = AssertionIssuanceProvenanceSource;

export interface AssertionEvidenceDetailRow {
  label: string;
  value: string;
}

export interface AssertionEvidenceApprovalEntry {
  occurredAt: string;
  actorLabel: string;
  actorRole: string | null;
  actionLabel: string;
  comment: string | null;
}

export interface AssertionEvidenceTimelineEntry {
  id: string;
  occurredAt: string;
  actorLabel: string;
  summary: string;
  detail: string;
}

export interface AssertionEvidenceReviewSection {
  decision: string;
  reviewerLabel: string;
  reviewedAt: string;
  comment: string | null;
}

export interface AssertionEvidencePresentation {
  assertionId: string;
  tenantId: string;
  generatedAt: string;
  summary: {
    badgeTitle: string;
    recipientIdentity: string;
    issuedAt: string;
    publicId: string | null;
    lifecycleState: string;
    attributedOrgUnitName: string | null;
  };
  issuance: {
    source: AssertionEvidenceIssuanceSource;
    sourceLabel: string;
    issuerLabel: string | null;
  };
  rule: {
    ruleId: string;
    ruleName: string;
    versionNumber: number;
    versionStatus: string;
    versionId: string;
    submittedAt: string | null;
    approvedAt: string | null;
    activatedAt: string | null;
    changeSummary: string | null;
  } | null;
  approvalEntries: readonly AssertionEvidenceApprovalEntry[];
  factsSummary: readonly string[];
  evaluationOutcomes: readonly AssertionEvidenceEvaluationOutcomeRow[];
  review: AssertionEvidenceReviewSection | null;
  changesAfterIssuance: readonly AssertionEvidenceTimelineEntry[];
  supportDetails: readonly AssertionEvidenceDetailRow[];
}

const issuanceSourceLabels: Readonly<Record<AssertionEvidenceIssuanceSource, string>> = {
  lti_roster: "Issued automatically from an active badge rule",
  rule_evaluate: "Issued after a rule evaluation matched",
  manual: "Issued manually by an administrator",
  programmatic: "Issued programmatically by the system",
};

const approvalActionLabels: Readonly<Record<string, string>> = {
  submitted: "Submitted for approval",
  approved: "Approved",
  rejected: "Rejected",
  changes_requested: "Requested changes",
};

const auditActionLabels: Readonly<Record<string, string>> = {
  "assertion.issued": "Badge issued",
  "assertion.lifecycle_transitioned": "Lifecycle changed",
  "assertion.revoked": "Badge revoked",
  "badge_rule.evaluated": "Rule evaluated",
};

const lifecycleStateLabels: Readonly<Record<string, string>> = {
  active: "Active",
  suspended: "Suspended",
  revoked: "Revoked",
  expired: "Expired",
};

const resolveActorLabel = (
  actorUserId: string | null,
  actorLabels: ReadonlyMap<string, string>,
): string => {
  if (actorUserId === null || actorUserId.length === 0) {
    return "System";
  }

  return actorLabels.get(actorUserId) ?? actorUserId;
};

const resolveIssuanceSource = (
  data: AssertionEvidenceLoadedData,
): AssertionEvidenceIssuanceSource => {
  if (data.provenance !== null) {
    return data.provenance.source;
  }

  return inferLegacyIssuanceSource(data);
};

const parsedEvaluationSnapshotFromLoadedData = (
  data: AssertionEvidenceLoadedData,
): {
  readonly facts: ReturnType<typeof parseIssuanceEvidenceSnapshotJson>["facts"];
  readonly tree: ReturnType<typeof parseIssuanceEvidenceSnapshotJson>["tree"];
} => {
  if (data.evaluation !== null) {
    return parseIssuanceEvidenceSnapshotJson(data.evaluation.evaluationJson);
  }

  return parseIssuanceEvidenceSnapshotJson(data.provenance?.provenanceJson ?? null);
};

const formatAuditDetail = (metadataJson: string | null): string => {
  if (metadataJson === null || metadataJson.trim().length === 0) {
    return "";
  }

  try {
    const metadata: unknown = JSON.parse(metadataJson);

    if (metadata === null || typeof metadata !== "object") {
      return "";
    }

    const record = metadata as Record<string, unknown>;
    const parts: string[] = [];

    if (typeof record.fromState === "string" && typeof record.toState === "string") {
      parts.push(`${record.fromState} → ${record.toState}`);
    }

    if (typeof record.reason === "string" && record.reason.length > 0) {
      parts.push(record.reason);
    }

    if (typeof record.reasonCode === "string" && record.reasonCode.length > 0) {
      parts.push(record.reasonCode.replaceAll("_", " "));
    }

    return parts.join(" · ");
  } catch {
    return "";
  }
};

const buildChangesAfterIssuance = (
  data: AssertionEvidenceLoadedData,
): AssertionEvidenceTimelineEntry[] => {
  const entries: AssertionEvidenceTimelineEntry[] = [];

  for (const event of data.lifecycleEvents) {
    entries.push({
      id: event.id,
      occurredAt: event.transitionedAt,
      actorLabel: resolveActorLabel(event.actorUserId, data.actorLabels),
      summary: `Lifecycle changed to ${lifecycleStateLabels[event.toState] ?? event.toState}`,
      detail: [event.reasonCode.replaceAll("_", " "), event.reason ?? ""]
        .filter((part) => part.length > 0)
        .join(" · "),
    });
  }

  for (const log of data.auditLogs) {
    if (log.action === "assertion.issued") {
      continue;
    }

    entries.push({
      id: log.id,
      occurredAt: log.occurredAt,
      actorLabel: resolveActorLabel(log.actorUserId, data.actorLabels),
      summary: auditActionLabels[log.action] ?? log.action.replaceAll("_", " "),
      detail: formatAuditDetail(log.metadataJson),
    });
  }

  entries.sort((left, right) => right.occurredAt.localeCompare(left.occurredAt));

  return entries;
};

export const buildAssertionEvidencePresentation = (
  data: AssertionEvidenceLoadedData,
): AssertionEvidencePresentation => {
  const issuanceSource = resolveIssuanceSource(data);
  const evaluationSnapshot = parsedEvaluationSnapshotFromLoadedData(data);
  const factsSummary =
    evaluationSnapshot.facts === null ? [] : summarizeEvaluationFacts(evaluationSnapshot.facts);

  const approvalEntries = data.approvalEvents.map((event) => ({
    occurredAt: event.occurredAt,
    actorLabel: resolveActorLabel(event.actorUserId, data.actorLabels),
    actorRole: event.actorRole === null ? null : tenantMembershipRoleLabel(event.actorRole),
    actionLabel: approvalActionLabels[event.action] ?? event.action,
    comment: event.comment,
  }));

  const review =
    data.evaluation !== null &&
    data.evaluation.reviewStatus === "resolved" &&
    data.evaluation.reviewDecision !== null &&
    data.evaluation.reviewedAt !== null
      ? {
          decision: data.evaluation.reviewDecision,
          reviewerLabel: resolveActorLabel(data.evaluation.reviewedByUserId, data.actorLabels),
          reviewedAt: data.evaluation.reviewedAt,
          comment: data.evaluation.reviewComment,
        }
      : null;

  const supportDetails: AssertionEvidenceDetailRow[] = [
    { label: "Assertion ID", value: data.assertion.id },
    { label: "Badge template ID", value: data.assertion.badgeTemplateId },
  ];

  if (data.rule !== null) {
    supportDetails.push({ label: "Rule ID", value: data.rule.id });
  }

  if (data.version !== null) {
    supportDetails.push({ label: "Rule version ID", value: data.version.id });
  }

  return {
    assertionId: data.assertion.id,
    tenantId: data.assertion.tenantId,
    generatedAt: data.generatedAt,
    summary: {
      badgeTitle: data.badgeTemplate.title,
      recipientIdentity: data.assertion.recipientIdentity,
      issuedAt: data.assertion.issuedAt,
      publicId: data.assertion.publicId,
      lifecycleState: data.lifecycle.state,
      attributedOrgUnitName: data.attributedOrgUnitName,
    },
    issuance: {
      source: issuanceSource,
      sourceLabel: issuanceSourceLabels[issuanceSource],
      issuerLabel: data.issuerLabel,
    },
    rule:
      data.rule === null || data.version === null
        ? null
        : {
            ruleId: data.rule.id,
            ruleName: data.version.snapshot.name,
            versionNumber: data.version.versionNumber,
            versionStatus: data.version.status,
            versionId: data.version.id,
            submittedAt: data.version.submittedAt,
            approvedAt: data.version.approvedAt,
            activatedAt: data.version.activatedAt,
            changeSummary: data.version.changeSummary,
          },
    approvalEntries,
    factsSummary,
    evaluationOutcomes: flattenEvaluationTree(evaluationSnapshot.tree),
    review,
    changesAfterIssuance: buildChangesAfterIssuance(data),
    supportDetails,
  };
};

export const buildAssertionEvidenceApiResponse = (
  data: AssertionEvidenceLoadedData,
): AssertionEvidencePresentation => {
  return buildAssertionEvidencePresentation(data);
};
