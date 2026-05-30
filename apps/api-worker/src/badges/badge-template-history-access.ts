import {
  findBadgeTemplateById,
  countBadgeTemplateImageRevisions,
  listAuditLogs,
  listBadgeTemplateOwnershipEvents,
  listTenantOrgUnits,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { AppContext } from "../app";
import type { AuthenticatedPrincipal } from "../auth/auth-context";
import {
  buildBadgeTemplateHistoryTimeline,
  buildOrgUnitLabelById,
  resolveActorLabels,
  type BadgeTemplateHistoryTimelineEntry,
} from "./badge-template-history";

interface AuthorizeBadgeTemplateHistoryAccessInput {
  c: AppContext;
  resolveDatabase: (bindings: AppContext["env"]) => SqlDatabase;
  tenantId: string;
  badgeTemplateId: string;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        principal: AuthenticatedPrincipal;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  requireScopedOrgUnitPermission: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      orgUnitId: string;
      requiredRole: "viewer";
      allowWhenNoScopes?: boolean;
    },
  ) => Promise<Response | null>;
  issuerRoles: readonly TenantMembershipRole[];
}

export const authorizeBadgeTemplateHistoryAccess = async (
  input: AuthorizeBadgeTemplateHistoryAccessInput,
): Promise<
  | Response
  | {
      db: SqlDatabase;
      template: BadgeTemplateRecord;
    }
> => {
  const roleCheck = await input.requireTenantRole(input.c, input.tenantId, input.issuerRoles);

  if (roleCheck instanceof Response) {
    return roleCheck;
  }

  const { principal, membershipRole } = roleCheck;
  const db = input.resolveDatabase(input.c.env);
  const template = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (template === null) {
    return input.c.json(
      {
        error: "Badge template not found",
      },
      404,
    );
  }

  const scopeCheck = await input.requireScopedOrgUnitPermission(input.c, {
    db,
    tenantId: input.tenantId,
    userId: principal.userId,
    membershipRole,
    orgUnitId: template.ownerOrgUnitId,
    requiredRole: "viewer",
    allowWhenNoScopes: true,
  });

  if (scopeCheck !== null) {
    return scopeCheck;
  }

  return {
    db,
    template,
  };
};

/** Shared by JSON audit-log and history-timeline API endpoints. */
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
