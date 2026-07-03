import {
  findAssertionById,
  findAssertionIssuanceProvenanceByAssertionId,
  findAssertionReportingAttributionByAssertionId,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleEvaluationByAssertionId,
  findBadgeIssuanceRuleVersionById,
  findBadgeTemplateById,
  findTenantOrgUnitById,
  findUsersByIds,
  listAssertionLifecycleEvents,
  listAuditLogsForAssertion,
  listBadgeIssuanceRuleVersionApprovalEvents,
  listBadgeIssuanceRuleVersionApprovalSteps,
  resolveAssertionLifecycleState,
  type AssertionIssuanceProvenanceRecord,
  type AssertionLifecycleEventRecord,
  type AssertionRecord,
  type AuditLogRecord,
  type BadgeIssuanceRuleApprovalEventRecord,
  type BadgeIssuanceRuleApprovalStepRecord,
  type BadgeIssuanceRuleEvaluationRecord,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type BadgeTemplateRecord,
  type ResolveAssertionLifecycleStateResult,
  type SqlDatabase,
} from "@credtrail/db";

export interface AssertionEvidenceLoadedData {
  assertion: AssertionRecord;
  badgeTemplate: BadgeTemplateRecord;
  lifecycle: ResolveAssertionLifecycleStateResult;
  lifecycleEvents: readonly AssertionLifecycleEventRecord[];
  auditLogs: readonly AuditLogRecord[];
  attributedOrgUnitName: string | null;
  issuerLabel: string | null;
  evaluation: BadgeIssuanceRuleEvaluationRecord | null;
  provenance: AssertionIssuanceProvenanceRecord | null;
  rule: BadgeIssuanceRuleRecord | null;
  version: BadgeIssuanceRuleVersionRecord | null;
  approvalEvents: readonly BadgeIssuanceRuleApprovalEventRecord[];
  approvalSteps: readonly BadgeIssuanceRuleApprovalStepRecord[];
  actorLabels: ReadonlyMap<string, string>;
  generatedAt: string;
}

const collectActorUserIds = (input: {
  assertion: AssertionRecord;
  lifecycleEvents: readonly AssertionLifecycleEventRecord[];
  auditLogs: readonly AuditLogRecord[];
  approvalEvents: readonly BadgeIssuanceRuleApprovalEventRecord[];
  evaluation: BadgeIssuanceRuleEvaluationRecord | null;
  version: BadgeIssuanceRuleVersionRecord | null;
}): string[] => {
  const actorUserIds = new Set<string>();

  if (input.assertion.issuedByUserId !== null) {
    actorUserIds.add(input.assertion.issuedByUserId);
  }

  for (const event of input.lifecycleEvents) {
    if (event.actorUserId !== null) {
      actorUserIds.add(event.actorUserId);
    }
  }

  for (const log of input.auditLogs) {
    if (log.actorUserId !== null) {
      actorUserIds.add(log.actorUserId);
    }
  }

  for (const event of input.approvalEvents) {
    if (event.actorUserId !== null) {
      actorUserIds.add(event.actorUserId);
    }
  }

  if (
    input.evaluation?.reviewedByUserId !== null &&
    input.evaluation?.reviewedByUserId !== undefined
  ) {
    actorUserIds.add(input.evaluation.reviewedByUserId);
  }

  if (input.version?.approvedByUserId !== null && input.version?.approvedByUserId !== undefined) {
    actorUserIds.add(input.version.approvedByUserId);
  }

  if (input.version?.activatedByUserId !== null && input.version?.activatedByUserId !== undefined) {
    actorUserIds.add(input.version.activatedByUserId);
  }

  if (input.version?.submittedByUserId !== null && input.version?.submittedByUserId !== undefined) {
    actorUserIds.add(input.version.submittedByUserId);
  }

  return [...actorUserIds];
};

const resolveRuleContextIds = (input: {
  evaluation: BadgeIssuanceRuleEvaluationRecord | null;
  provenance: AssertionIssuanceProvenanceRecord | null;
}): { ruleId: string | null; versionId: string | null } => {
  if (input.evaluation !== null) {
    return {
      ruleId: input.evaluation.ruleId,
      versionId: input.evaluation.versionId,
    };
  }

  if (input.provenance === null) {
    return {
      ruleId: null,
      versionId: null,
    };
  }

  return {
    ruleId: input.provenance.ruleId,
    versionId: input.provenance.versionId,
  };
};

export const loadAssertionEvidencePayload = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    assertionId: string;
  },
): Promise<AssertionEvidenceLoadedData | null> => {
  const assertion = await findAssertionById(db, input.tenantId, input.assertionId);

  if (assertion === null) {
    return null;
  }

  const [
    badgeTemplate,
    lifecycle,
    lifecycleEvents,
    auditLogs,
    attribution,
    evaluation,
    provenance,
  ] = await Promise.all([
    findBadgeTemplateById(db, input.tenantId, assertion.badgeTemplateId),
    resolveAssertionLifecycleState(db, input.tenantId, assertion.id),
    listAssertionLifecycleEvents(db, {
      tenantId: input.tenantId,
      assertionId: assertion.id,
    }),
    listAuditLogsForAssertion(db, {
      tenantId: input.tenantId,
      assertionId: assertion.id,
      limit: 100,
    }),
    findAssertionReportingAttributionByAssertionId(db, assertion.id),
    findBadgeIssuanceRuleEvaluationByAssertionId(db, {
      tenantId: input.tenantId,
      assertionId: assertion.id,
    }),
    findAssertionIssuanceProvenanceByAssertionId(db, {
      tenantId: input.tenantId,
      assertionId: assertion.id,
    }),
  ]);

  if (badgeTemplate === null || lifecycle === null) {
    return null;
  }

  const ruleContextIds = resolveRuleContextIds({ evaluation, provenance });
  const [rule, version] = await Promise.all([
    ruleContextIds.ruleId === null
      ? Promise.resolve(null)
      : findBadgeIssuanceRuleById(db, input.tenantId, ruleContextIds.ruleId),
    ruleContextIds.ruleId === null || ruleContextIds.versionId === null
      ? Promise.resolve(null)
      : findBadgeIssuanceRuleVersionById(db, {
          tenantId: input.tenantId,
          ruleId: ruleContextIds.ruleId,
          versionId: ruleContextIds.versionId,
        }),
  ]);

  const [approvalEvents, approvalSteps, attributedOrgUnit] = await Promise.all([
    rule === null || version === null
      ? Promise.resolve([])
      : listBadgeIssuanceRuleVersionApprovalEvents(db, {
          tenantId: input.tenantId,
          ruleId: rule.id,
          versionId: version.id,
        }),
    rule === null || version === null
      ? Promise.resolve([])
      : listBadgeIssuanceRuleVersionApprovalSteps(db, {
          tenantId: input.tenantId,
          ruleId: rule.id,
          versionId: version.id,
        }),
    attribution === null
      ? Promise.resolve(null)
      : findTenantOrgUnitById(db, input.tenantId, attribution.orgUnitId),
  ]);

  const actorUserIds = collectActorUserIds({
    assertion,
    lifecycleEvents,
    auditLogs,
    approvalEvents,
    evaluation,
    version,
  });
  const usersById = await findUsersByIds(db, actorUserIds);
  const actorLabels = new Map<string, string>();

  for (const actorUserId of actorUserIds) {
    const user = usersById.get(actorUserId);
    actorLabels.set(actorUserId, user?.email ?? actorUserId);
  }

  const issuerLabel =
    assertion.issuedByUserId === null
      ? null
      : (actorLabels.get(assertion.issuedByUserId) ?? assertion.issuedByUserId);

  return {
    assertion,
    badgeTemplate,
    lifecycle,
    lifecycleEvents,
    auditLogs,
    attributedOrgUnitName: attributedOrgUnit?.displayName ?? null,
    issuerLabel,
    evaluation,
    provenance,
    rule,
    version,
    approvalEvents,
    approvalSteps,
    actorLabels,
    generatedAt: new Date().toISOString(),
  };
};
