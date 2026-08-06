import { createAuditLog, type SqlDatabase } from "@credtrail/db";
import type { TenantMemberInviteAuditEvent } from "../auth/tenant-member-invite-workflow";

/** Persists the audit event produced by the tenant-member invitation workflow. */
export const recordTenantMemberInviteAudit = async (
  db: SqlDatabase,
  event: TenantMemberInviteAuditEvent,
): Promise<void> => {
  await createAuditLog(db, {
    tenantId: event.tenantId,
    actorUserId: event.actorUserId,
    action: event.action,
    targetType: "membership",
    targetId: `${event.tenantId}:${event.userId}`,
    metadata: {
      actorRole: event.actorRole,
      userId: event.userId,
      email: event.email,
      newRole: event.role,
      role: event.role,
      inviteDeliveryStatus: event.invite.deliveryStatus,
      inviteKind: event.invite.inviteKind,
    },
  });
};
