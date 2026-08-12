import {
  createAuditLog,
  findAssertionById,
  findBadgeTemplateById,
  listAssertionLifecycleEvents,
  listTenantAssertionLedgerExportRows,
  listTenantAssertions,
  recordAssertionLifecycleTransition,
  resolveAssertionLifecycleState,
  type DelegatedIssuingAuthorityAction,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseAssertionLifecycleTransitionRequest,
  parseAssertionPathParams,
  parseManualIssueBadgeRequest,
  parseTenantAssertionLedgerExportQuery,
  parseTenantAssertionListQuery,
  parseTenantPathParams,
  type TenantAssertionListQuery,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";
import type {
  RequireDelegatedIssuingAuthorityPermission,
  RequireTenantRole,
  ResolveDatabase,
} from "../app/route-deps";
import { buildAssertionEvidenceApiResponse } from "../badges/assertion-evidence-presentation";
import { loadAssertionEvidencePayload } from "../badges/assertion-evidence-payload";
import { badgeAchievementSnapshotFromTemplate } from "../badges/badge-achievement-snapshot";
import type { DirectIssueBadgeOptions, DirectIssueBadgeResult } from "../badges/direct-issue";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import { buildTenantAssertionLedgerCsvExport } from "../reporting/ledger-export";
import {
  tenantAssertionLedgerExportDbInput,
  tenantAssertionListDbInput,
} from "./assertion-list-query";

interface RegisterAssertionRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  requireDelegatedIssuingAuthorityPermission: RequireDelegatedIssuingAuthorityPermission;
  assertionBelongsToTenant: (tenantId: string, assertionId: string) => boolean;
  issueBadgeForTenant: (
    c: AppContext,
    tenantId: string,
    request: DirectIssueBadgeRequest,
    issuedByUserId?: string,
    options?: DirectIssueBadgeOptions,
  ) => Promise<DirectIssueBadgeResult>;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  ISSUER_ROLES: readonly TenantMembershipRole[];
  APPROVAL_WORKSPACE_ROLES: readonly TenantMembershipRole[];
  TENANT_MEMBER_ROLES: readonly TenantMembershipRole[];
  HttpErrorResponseClass: new (
    statusCode: 400 | 404 | 409 | 422 | 500 | 502 | 503,
    payload: {
      error: string;
      did?: string | undefined;
    },
  ) => {
    payload: Record<string, unknown>;
    statusCode: 400 | 404 | 409 | 422 | 500 | 502 | 503;
  };
}

const manualIssueResponseStatus = (status: DirectIssueBadgeResult["status"]): 200 | 201 => {
  return status === "issued" ? 201 : 200;
};

export const registerAssertionRoutes = (input: RegisterAssertionRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    requireTenantRole,
    requireDelegatedIssuingAuthorityPermission,
    assertionBelongsToTenant,
    issueBadgeForTenant,
    ADMIN_ROLES,
    ISSUER_ROLES,
    APPROVAL_WORKSPACE_ROLES,
    TENANT_MEMBER_ROLES,
    HttpErrorResponseClass,
  } = input;
  const EVIDENCE_ROLES = Array.from(new Set([...ISSUER_ROLES, ...APPROVAL_WORKSPACE_ROLES]));

  const parseAssertionListQuery = (c: AppContext): TenantAssertionListQuery => {
    return parseTenantAssertionListQuery({
      issuedFrom: c.req.query("issuedFrom"),
      issuedTo: c.req.query("issuedTo"),
      badgeTemplateId: c.req.query("badgeTemplateId"),
      orgUnitId: c.req.query("orgUnitId"),
      recipientQuery: c.req.query("recipientQuery"),
      state: c.req.query("state"),
      limit: c.req.query("limit"),
    });
  };

  app.post("/v1/tenants/:tenantId/assertions/manual-issue", async (c): Promise<Response> => {
    const pathParams = parseTenantPathParams(c.req.param());
    const payload = await c.req.json<unknown>();
    const request = parseManualIssueBadgeRequest(payload);
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const template = await findBadgeTemplateById(db, pathParams.tenantId, request.badgeTemplateId);

    if (template === null) {
      return c.json(
        {
          error: "Badge template not found",
        },
        404,
      );
    }

    const delegatedPermission = await requireDelegatedIssuingAuthorityPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: session.userId,
      membershipRole,
      ownerOrgUnitId: template.ownerOrgUnitId,
      badgeTemplateId: template.id,
      requiredAction: "issue_badge",
    });

    if (delegatedPermission !== null) {
      return delegatedPermission;
    }

    try {
      const result = await issueBadgeForTenant(
        c,
        pathParams.tenantId,
        {
          achievementSource: {
            kind: "template_snapshot",
            snapshot: badgeAchievementSnapshotFromTemplate(template),
            provenance: { source: "manual" },
          },
          recipientIdentity: request.recipientIdentity,
          recipientIdentityType: request.recipientIdentityType,
          ...(request.recipientIdentifiers === undefined
            ? {}
            : { recipientIdentifiers: request.recipientIdentifiers }),
          ...(request.recipientDisplayName === undefined
            ? {}
            : { recipientDisplayName: request.recipientDisplayName }),
          ...(request.issuerImageUri === undefined
            ? {}
            : { issuerImageUri: request.issuerImageUri }),
          ...(request.idempotencyKey === undefined
            ? {}
            : { idempotencyKey: request.idempotencyKey }),
        },
        session.userId,
      );
      return c.json(result, manualIssueResponseStatus(result.status));
    } catch (error: unknown) {
      if (error instanceof HttpErrorResponseClass) {
        return c.json(error.payload, error.statusCode);
      }

      throw error;
    }
  });

  app.get("/v1/tenants/:tenantId/assertions", async (c): Promise<Response> => {
    const pathParams = parseTenantPathParams(c.req.param());
    let query;

    try {
      query = parseAssertionListQuery(c);
    } catch {
      return c.json(
        {
          error: "Invalid assertion list query parameters",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const assertions = await listTenantAssertions(
      resolveDatabase(c.env),
      tenantAssertionListDbInput(pathParams.tenantId, query),
    );

    c.header("Cache-Control", "no-store");

    return c.json({
      tenantId: pathParams.tenantId,
      count: assertions.length,
      assertions,
    });
  });

  app.get("/v1/tenants/:tenantId/assertions/ledger-export.csv", async (c): Promise<Response> => {
    const pathParams = parseTenantPathParams(c.req.param());
    let query;

    try {
      query = parseTenantAssertionLedgerExportQuery({
        issuedFrom: c.req.query("issuedFrom"),
        issuedTo: c.req.query("issuedTo"),
        badgeTemplateId: c.req.query("badgeTemplateId"),
        orgUnitId: c.req.query("orgUnitId"),
        state: c.req.query("state"),
        recipientQuery: c.req.query("recipientQuery"),
      });
    } catch {
      return c.json(
        {
          error: "Invalid assertion ledger export query parameters",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const exportResult = await listTenantAssertionLedgerExportRows(
      resolveDatabase(c.env),
      tenantAssertionLedgerExportDbInput(pathParams.tenantId, query),
    );
    const exportParts = buildTenantAssertionLedgerCsvExport(exportResult);

    if (exportParts.status === "too_large") {
      return c.json(
        {
          error: exportParts.error.error,
          rowLimit: exportParts.error.rowLimit,
          message: exportParts.error.message,
        },
        413,
      );
    }

    return new Response(exportParts.csv, {
      status: 200,
      headers: exportParts.headers,
    });
  });

  app.get(
    "/v1/tenants/:tenantId/assertions/:assertionId/lifecycle",
    async (c): Promise<Response> => {
      const pathParams = parseAssertionPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      if (!assertionBelongsToTenant(pathParams.tenantId, pathParams.assertionId)) {
        return c.json(
          {
            error: "assertionId must be a tenant-scoped identifier for the active tenant",
          },
          422,
        );
      }

      const db = resolveDatabase(c.env);
      const assertion = await findAssertionById(db, pathParams.tenantId, pathParams.assertionId);

      if (assertion === null) {
        return c.json(
          {
            error: "Assertion not found",
          },
          404,
        );
      }

      const lifecycle = await resolveAssertionLifecycleState(
        db,
        pathParams.tenantId,
        pathParams.assertionId,
      );

      if (lifecycle === null) {
        return c.json(
          {
            error: "Assertion not found",
          },
          404,
        );
      }

      const events = await listAssertionLifecycleEvents(db, {
        tenantId: pathParams.tenantId,
        assertionId: pathParams.assertionId,
      });

      c.header("Cache-Control", "no-store");

      return c.json({
        assertionId: assertion.id,
        tenantId: assertion.tenantId,
        state: lifecycle.state,
        source: lifecycle.source,
        reasonCode: lifecycle.reasonCode,
        reason: lifecycle.reason,
        transitionedAt: lifecycle.transitionedAt,
        revokedAt: lifecycle.revokedAt,
        events,
      });
    },
  );

  app.get(
    "/v1/tenants/:tenantId/assertions/:assertionId/evidence",
    async (c): Promise<Response> => {
      const pathParams = parseAssertionPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, EVIDENCE_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      if (!assertionBelongsToTenant(pathParams.tenantId, pathParams.assertionId)) {
        return c.json(
          {
            error: "assertionId must be a tenant-scoped identifier for the active tenant",
          },
          422,
        );
      }

      const db = resolveDatabase(c.env);
      const loaded = await loadAssertionEvidencePayload(db, {
        tenantId: pathParams.tenantId,
        assertionId: pathParams.assertionId,
      });

      if (loaded.status === "not_found") {
        return c.json(
          {
            error: "Assertion not found",
          },
          404,
        );
      }

      if (loaded.status === "incomplete") {
        return c.json(
          {
            error: "Assertion evidence is incomplete",
            reason: loaded.reason,
          },
          409,
        );
      }

      c.header("Cache-Control", "no-store");

      return c.json(buildAssertionEvidenceApiResponse(loaded.data));
    },
  );

  app.post(
    "/v1/tenants/:tenantId/assertions/:assertionId/lifecycle/transition",
    async (c): Promise<Response> => {
      const pathParams = parseAssertionPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;

      if (!assertionBelongsToTenant(pathParams.tenantId, pathParams.assertionId)) {
        return c.json(
          {
            error: "assertionId must be a tenant-scoped identifier for the active tenant",
          },
          422,
        );
      }

      let request;

      try {
        request = parseAssertionLifecycleTransitionRequest(await c.req.json());
      } catch {
        return c.json(
          {
            error: "Invalid lifecycle transition request payload",
          },
          400,
        );
      }

      if (request.transitionSource === "automation") {
        return c.json(
          {
            error: "Automation lifecycle transitions are only allowed via trusted internal jobs",
          },
          422,
        );
      }

      const db = resolveDatabase(c.env);
      const assertion = await findAssertionById(db, pathParams.tenantId, pathParams.assertionId);

      if (assertion === null) {
        return c.json(
          {
            error: "Assertion not found",
          },
          404,
        );
      }

      const badgeTemplate = await findBadgeTemplateById(
        db,
        pathParams.tenantId,
        assertion.badgeTemplateId,
      );

      if (badgeTemplate === null) {
        return c.json(
          {
            error: "Badge template not found",
          },
          404,
        );
      }

      const requiredAction: DelegatedIssuingAuthorityAction =
        request.toState === "revoked" ? "revoke_badge" : "manage_lifecycle";
      const delegatedPermission = await requireDelegatedIssuingAuthorityPermission(c, {
        db,
        tenantId: pathParams.tenantId,
        userId: session.userId,
        membershipRole,
        ownerOrgUnitId: badgeTemplate.ownerOrgUnitId,
        badgeTemplateId: badgeTemplate.id,
        requiredAction,
      });

      if (delegatedPermission !== null) {
        return delegatedPermission;
      }

      try {
        const transitionResult = await recordAssertionLifecycleTransition(db, {
          tenantId: pathParams.tenantId,
          assertionId: pathParams.assertionId,
          toState: request.toState,
          reasonCode: request.reasonCode,
          ...(request.reason === undefined ? {} : { reason: request.reason }),
          transitionSource: "manual",
          actorUserId: session.userId,
          transitionedAt: request.transitionedAt ?? new Date().toISOString(),
        });

        if (transitionResult.status === "invalid_transition") {
          return c.json(
            {
              error: "Lifecycle transition not allowed",
              fromState: transitionResult.fromState,
              toState: transitionResult.toState,
              currentState: transitionResult.currentState,
              message: transitionResult.message,
            },
            409,
          );
        }

        if (transitionResult.status === "already_in_state") {
          c.header("Cache-Control", "no-store");

          return c.json({
            status: transitionResult.status,
            fromState: transitionResult.fromState,
            toState: transitionResult.toState,
            currentState: transitionResult.currentState,
            message: transitionResult.message,
          });
        }

        const event = transitionResult.event;

        if (event === null) {
          throw new Error("Lifecycle transition result is missing event details");
        }

        await createAuditLog(db, {
          tenantId: pathParams.tenantId,
          actorUserId: session.userId,
          action: "assertion.lifecycle_transitioned",
          targetType: "assertion",
          targetId: pathParams.assertionId,
          metadata: {
            eventId: event.id,
            fromState: event.fromState,
            toState: event.toState,
            reasonCode: event.reasonCode,
            reason: event.reason,
            transitionSource: event.transitionSource,
            transitionedAt: event.transitionedAt,
          },
        });

        c.header("Cache-Control", "no-store");

        return c.json({
          status: transitionResult.status,
          fromState: transitionResult.fromState,
          toState: transitionResult.toState,
          currentState: transitionResult.currentState,
          message: transitionResult.message,
          event,
        });
      } catch (error: unknown) {
        if (error instanceof Error) {
          if (error.message.includes("not found for tenant")) {
            return c.json(
              {
                error: "Assertion not found",
              },
              404,
            );
          }

          if (
            error.message.includes("Manual lifecycle transitions require actorUserId") ||
            error.message.includes("Automated lifecycle transitions must not set actorUserId") ||
            error.message.includes("transitionedAt must be a valid ISO timestamp")
          ) {
            return c.json(
              {
                error: error.message,
              },
              422,
            );
          }
        }

        throw error;
      }
    },
  );
};
