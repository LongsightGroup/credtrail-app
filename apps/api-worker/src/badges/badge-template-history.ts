import {
  findUsersByIds,
  type AuditLogRecord,
  type BadgeTemplateOwnershipEventRecord,
  type BadgeTemplateOwnershipReasonCode,
  type SqlDatabase,
  type TenantOrgUnitRecord,
} from "@credtrail/db";

export interface BadgeTemplateHistoryTimelineEntry {
  id: string;
  kind: "audit" | "ownership";
  occurredAt: string;
  actorUserId: string | null;
  actorLabel: string;
  summary: string;
  detail: string;
}

const auditActionLabels: Readonly<Record<string, string>> = {
  "badge_template.created": "Created template",
  "badge_template.updated": "Updated template",
  "badge_template.image_uploaded": "Uploaded image",
  "badge_template.image_restored": "Restored previous image",
  "badge_template.image_generation_applied": "Applied generated image",
  "badge_template.image_generated": "Generated draft image",
  "badge_template.ownership_transferred": "Transferred ownership",
  "badge_template.archived_state_changed": "Changed archive state",
  "badge_template.upserted": "Updated template",
};

const auditFieldLabels: Readonly<Record<string, string>> = {
  slug: "URL key",
  title: "Title",
  description: "Description",
  criteriaUri: "Criteria URL",
  imageUri: "Image URL",
};

const ownershipReasonLabels: Readonly<Record<BadgeTemplateOwnershipReasonCode, string>> = {
  initial_assignment: "Initial assignment",
  administrative_transfer: "Administrative transfer",
  reorganization: "Reorganization",
  governance_policy_update: "Governance policy update",
  other: "Other",
};

const formatAuditValue = (value: unknown): string => {
  if (value === null || value === undefined) {
    return "(empty)";
  }

  if (typeof value === "string") {
    return value.length === 0 ? "(empty)" : value;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  return "(empty)";
};

export const formatBadgeTemplateAuditAction = (action: string): string => {
  return auditActionLabels[action] ?? action.replaceAll("_", " ");
};

export const formatBadgeTemplateAuditDetail = (metadataJson: string | null): string => {
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
    let hasFieldChanges = false;

    if (Array.isArray(record.changes)) {
      for (const change of record.changes) {
        if (change === null || typeof change !== "object") {
          continue;
        }

        const changeRecord = change as Record<string, unknown>;

        if (typeof changeRecord.field !== "string") {
          continue;
        }

        hasFieldChanges = true;
        const label = auditFieldLabels[changeRecord.field] ?? changeRecord.field;
        parts.push(
          `${label}: ${formatAuditValue(changeRecord.from)} → ${formatAuditValue(changeRecord.to)}`,
        );
      }
    }

    if (!hasFieldChanges) {
      if (typeof record.title === "string" && record.title.length > 0) {
        parts.push(`Title: ${record.title}`);
      }

      if (typeof record.slug === "string" && record.slug.length > 0) {
        parts.push(`URL key: ${record.slug}`);
      }

      if (typeof record.fileName === "string" && record.fileName.length > 0) {
        parts.push(`File: ${record.fileName}`);
      }
    }

    if (typeof record.reason === "string" && record.reason.length > 0) {
      parts.push(record.reason);
    }

    return parts.join(" · ");
  } catch {
    return "";
  }
};

const resolveOrgUnitLabel = (
  orgUnitId: string | null,
  orgUnitLabelById: ReadonlyMap<string, string>,
): string => {
  if (orgUnitId === null || orgUnitId.length === 0) {
    return "(none)";
  }

  return orgUnitLabelById.get(orgUnitId) ?? orgUnitId;
};

export const formatBadgeTemplateOwnershipSummary = (
  event: BadgeTemplateOwnershipEventRecord,
): string => {
  if (event.reasonCode === "initial_assignment") {
    return "Assigned template ownership";
  }

  return "Transferred template ownership";
};

export const formatBadgeTemplateOwnershipDetail = (
  event: BadgeTemplateOwnershipEventRecord,
  orgUnitLabelById: ReadonlyMap<string, string>,
): string => {
  const parts: string[] = [
    `${resolveOrgUnitLabel(event.fromOrgUnitId, orgUnitLabelById)} → ${resolveOrgUnitLabel(event.toOrgUnitId, orgUnitLabelById)}`,
    ownershipReasonLabels[event.reasonCode],
  ];

  if (event.reason !== null && event.reason.length > 0) {
    parts.push(event.reason);
  }

  return parts.join(" · ");
};

export const buildOrgUnitLabelById = (
  orgUnits: readonly TenantOrgUnitRecord[],
): Map<string, string> => {
  return new Map(orgUnits.map((orgUnit) => [orgUnit.id, orgUnit.displayName]));
};

export const resolveActorLabels = async (
  db: SqlDatabase,
  actorUserIds: readonly (string | null)[],
): Promise<Map<string, string>> => {
  const uniqueActorUserIds = [
    ...new Set(
      actorUserIds.filter((actorUserId): actorUserId is string => {
        return actorUserId !== null && actorUserId.length > 0;
      }),
    ),
  ];
  const usersById = await findUsersByIds(db, uniqueActorUserIds);
  const actorLabels = new Map<string, string>();

  for (const actorUserId of uniqueActorUserIds) {
    const user = usersById.get(actorUserId);
    actorLabels.set(actorUserId, user?.email ?? actorUserId);
  }

  return actorLabels;
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

export const buildBadgeTemplateHistoryTimeline = (input: {
  logs: readonly AuditLogRecord[];
  ownershipEvents: readonly BadgeTemplateOwnershipEventRecord[];
  actorLabels: ReadonlyMap<string, string>;
  orgUnitLabelById: ReadonlyMap<string, string>;
  limit?: number;
}): BadgeTemplateHistoryTimelineEntry[] => {
  const timeline: BadgeTemplateHistoryTimelineEntry[] = [];

  for (const event of input.ownershipEvents) {
    timeline.push({
      id: event.id,
      kind: "ownership",
      occurredAt: event.transferredAt,
      actorUserId: event.transferredByUserId,
      actorLabel: resolveActorLabel(event.transferredByUserId, input.actorLabels),
      summary: formatBadgeTemplateOwnershipSummary(event),
      detail: formatBadgeTemplateOwnershipDetail(event, input.orgUnitLabelById),
    });
  }

  for (const log of input.logs) {
    if (log.action === "badge_template.ownership_transferred") {
      continue;
    }

    timeline.push({
      id: log.id,
      kind: "audit",
      occurredAt: log.occurredAt,
      actorUserId: log.actorUserId,
      actorLabel: resolveActorLabel(log.actorUserId, input.actorLabels),
      summary: formatBadgeTemplateAuditAction(log.action),
      detail: formatBadgeTemplateAuditDetail(log.metadataJson),
    });
  }

  timeline.sort((left, right) => {
    const occurredAtComparison = right.occurredAt.localeCompare(left.occurredAt);

    if (occurredAtComparison !== 0) {
      return occurredAtComparison;
    }

    return right.id.localeCompare(left.id);
  });

  if (input.limit === undefined) {
    return timeline;
  }

  const queryLimit = Math.max(1, Math.min(input.limit, 200));

  return timeline.slice(0, queryLimit);
};
