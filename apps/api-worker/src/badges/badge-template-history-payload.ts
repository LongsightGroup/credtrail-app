import {
  countBadgeTemplateImageRevisions,
  listAuditLogs,
  listBadgeTemplateOwnershipEvents,
  listTenantOrgUnits,
  type SqlDatabase,
} from "@credtrail/db";
import {
  buildBadgeTemplateHistoryTimeline,
  buildOrgUnitLabelById,
  resolveActorLabels,
  type BadgeTemplateHistoryTimelineEntry,
} from "./badge-template-history";

export const loadBadgeTemplateHistoryPayload = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    badgeTemplateId: string;
    limit: number;
  },
): Promise<{
  timeline: BadgeTemplateHistoryTimelineEntry[];
  imageRevisionCount: number;
}> => {
  const queryLimit = Math.max(1, Math.min(input.limit, 200));
  const fetchLimit = Math.min(queryLimit * 2, 200);
  const [logs, ownershipEvents, orgUnits, imageRevisionCount] = await Promise.all([
    listAuditLogs(db, {
      tenantId: input.tenantId,
      targetType: "badge_template",
      targetId: input.badgeTemplateId,
      limit: fetchLimit,
    }),
    listBadgeTemplateOwnershipEvents(db, {
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
      limit: fetchLimit,
    }),
    listTenantOrgUnits(db, {
      tenantId: input.tenantId,
      includeInactive: true,
    }),
    countBadgeTemplateImageRevisions(db, input.tenantId, input.badgeTemplateId),
  ]);
  const actorLabels = await resolveActorLabels(db, [
    ...logs.map((log) => log.actorUserId),
    ...ownershipEvents.map((event) => event.transferredByUserId),
  ]);
  const timeline = buildBadgeTemplateHistoryTimeline({
    logs,
    ownershipEvents,
    actorLabels,
    orgUnitLabelById: buildOrgUnitLabelById(orgUnits),
    limit: queryLimit,
  });

  return {
    timeline,
    imageRevisionCount,
  };
};
