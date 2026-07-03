import type { AuditLogRecord } from "./audit-logs";
import type { SqlDatabase } from "./tenant-scope";

const parseAssertionAuditMetadata = (metadataJson: string): { assertionId: string } | null => {
  try {
    const metadata: unknown = JSON.parse(metadataJson);

    if (metadata === null || typeof metadata !== "object" || !("assertionId" in metadata)) {
      return null;
    }

    const assertionId = metadata.assertionId;

    return typeof assertionId === "string" ? { assertionId } : null;
  } catch {
    return null;
  }
};

export interface ListAuditLogsForAssertionInput {
  tenantId: string;
  assertionId: string;
  limit?: number | undefined;
}

interface AuditLogRow {
  id: string;
  tenantId: string;
  actorUserId: string | null;
  action: string;
  targetType: string;
  targetId: string;
  metadataJson: string | null;
  occurredAt: string;
  createdAt: string;
}

const mapAuditLogRow = (row: AuditLogRow): AuditLogRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    actorUserId: row.actorUserId,
    action: row.action,
    targetType: row.targetType,
    targetId: row.targetId,
    metadataJson: row.metadataJson,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
  };
};

const auditLogMatchesAssertion = (log: AuditLogRecord, assertionId: string): boolean => {
  if (log.targetType === "assertion" && log.targetId === assertionId) {
    return true;
  }

  if (log.metadataJson === null || log.metadataJson.trim().length === 0) {
    return false;
  }

  return parseAssertionAuditMetadata(log.metadataJson)?.assertionId === assertionId;
};

export const listAuditLogsForAssertion = async (
  db: SqlDatabase,
  input: ListAuditLogsForAssertionInput,
): Promise<AuditLogRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 100, 200));
  const metadataPattern = `%"assertionId":"${input.assertionId}"%`;

  const result = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        actor_user_id AS actorUserId,
        action,
        target_type AS targetType,
        target_id AS targetId,
        metadata_json AS metadataJson,
        occurred_at AS occurredAt,
        created_at AS createdAt
      FROM audit_logs
      WHERE tenant_id = ?
        AND (
          (target_type = 'assertion' AND target_id = ?)
          OR (
            action = 'badge_rule.evaluated'
            AND metadata_json LIKE ?
          )
        )
      ORDER BY occurred_at DESC, created_at DESC, id DESC
      LIMIT ?
    `,
    )
    .bind(input.tenantId, input.assertionId, metadataPattern, queryLimit)
    .all<AuditLogRow>();

  return result.results
    .map(mapAuditLogRow)
    .filter((log) => auditLogMatchesAssertion(log, input.assertionId));
};
