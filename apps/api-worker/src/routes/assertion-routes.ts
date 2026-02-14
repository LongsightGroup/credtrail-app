import type { JsonObject } from '@credtrail/core-domain';
import {
  createAuditLog,
  findAssertionById,
  findBadgeTemplateById,
  listAssertionLifecycleEvents,
  recordAssertionLifecycleTransition,
  resolveAssertionLifecycleState,
  type DelegatedIssuingAuthorityAction,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from '@credtrail/db';
import type { Hono } from 'hono';
import {
  parseAssertionLifecycleTransitionRequest,
  parseAssertionPathParams,
  parseManualIssueBadgeRequest,
  parseTenantPathParams,
  type ManualIssueBadgeRequest,
} from '@credtrail/validation';
import type { AppBindings, AppContext, AppEnv } from '../app';

type DirectIssueBadgeRequest = Pick<
  ManualIssueBadgeRequest,
  | 'badgeTemplateId'
  | 'recipientIdentity'
  | 'recipientIdentityType'
  | 'recipientIdentifiers'
  | 'idempotencyKey'
>;

interface DirectIssueBadgeOptions {
  recipientDisplayName?: string;
  issuerName?: string;
  issuerUrl?: string;
}

interface DirectIssueBadgeResult {
  status: 'issued' | 'already_issued';
  tenantId: string;
  assertionId: string;
  idempotencyKey: string;
  vcR2Key: string;
  credential: JsonObject;
}

interface RegisterAssertionRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  requireDelegatedIssuingAuthorityPermission: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      ownerOrgUnitId: string;
      badgeTemplateId: string;
      requiredAction: DelegatedIssuingAuthorityAction;
    },
  ) => Promise<Response | null>;
  assertionBelongsToTenant: (tenantId: string, assertionId: string) => boolean;
  issueBadgeForTenant: (
    c: AppContext,
    tenantId: string,
    request: DirectIssueBadgeRequest,
    issuedByUserId?: string,
    options?: DirectIssueBadgeOptions,
  ) => Promise<DirectIssueBadgeResult>;
  ISSUER_ROLES: readonly TenantMembershipRole[];
  TENANT_MEMBER_ROLES: readonly TenantMembershipRole[];
  HttpErrorResponseClass: new (
    statusCode: 400 | 404 | 409 | 422 | 500 | 502,
    payload: {
      error: string;
      did?: string | undefined;
    },
  ) => {
    payload: Record<string, unknown>;
    statusCode: 400 | 404 | 409 | 422 | 500 | 502;
  };
}

const manualIssueResponseStatus = (status: DirectIssueBadgeResult['status']): 200 | 201 => {
  return status === 'issued' ? 201 : 200;
};

export const registerAssertionRoutes = (input: RegisterAssertionRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    requireTenantRole,
    requireDelegatedIssuingAuthorityPermission,
    assertionBelongsToTenant,
    issueBadgeForTenant,
    ISSUER_ROLES,
    TENANT_MEMBER_ROLES,
    HttpErrorResponseClass,
  } = input;

  app.post('/v1/tenants/:tenantId/assertions/manual-issue', async (c): Promise<Response> => {
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
          error: 'Badge template not found',
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
      requiredAction: 'issue_badge',
    });

    if (delegatedPermission !== null) {
      return delegatedPermission;
    }

    try {
      const result = await issueBadgeForTenant(c, pathParams.tenantId, request, session.userId);
      return c.json(result, manualIssueResponseStatus(result.status));
    } catch (error: unknown) {
      if (error instanceof HttpErrorResponseClass) {
        return c.json(error.payload, error.statusCode);
      }

      throw error;
    }
  });

  app.get('/v1/tenants/:tenantId/assertions/:assertionId/lifecycle', async (c): Promise<Response> => {
    const pathParams = parseAssertionPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    if (!assertionBelongsToTenant(pathParams.tenantId, pathParams.assertionId)) {
      return c.json(
        {
          error: 'assertionId must be a tenant-scoped identifier for the active tenant',
        },
        422,
      );
    }

    const db = resolveDatabase(c.env);
    const assertion = await findAssertionById(db, pathParams.tenantId, pathParams.assertionId);

    if (assertion === null) {
      return c.json(
        {
          error: 'Assertion not found',
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
          error: 'Assertion not found',
        },
        404,
      );
    }

    const events = await listAssertionLifecycleEvents(db, {
      tenantId: pathParams.tenantId,
      assertionId: pathParams.assertionId,
    });

    c.header('Cache-Control', 'no-store');

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
  });

  app.post(
    '/v1/tenants/:tenantId/assertions/:assertionId/lifecycle/transition',
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
            error: 'assertionId must be a tenant-scoped identifier for the active tenant',
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
            error: 'Invalid lifecycle transition request payload',
          },
          400,
        );
      }

      if (request.transitionSource === 'automation') {
        return c.json(
          {
            error: 'Automation lifecycle transitions are only allowed via trusted internal jobs',
          },
          422,
        );
      }

      const db = resolveDatabase(c.env);
      const assertion = await findAssertionById(db, pathParams.tenantId, pathParams.assertionId);

      if (assertion === null) {
        return c.json(
          {
            error: 'Assertion not found',
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
            error: 'Badge template not found',
          },
          404,
        );
      }

      const requiredAction: DelegatedIssuingAuthorityAction =
        request.toState === 'revoked' ? 'revoke_badge' : 'manage_lifecycle';
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
          transitionSource: 'manual',
          actorUserId: session.userId,
          transitionedAt: request.transitionedAt ?? new Date().toISOString(),
        });

        if (transitionResult.status === 'invalid_transition') {
          return c.json(
            {
              error: 'Lifecycle transition not allowed',
              fromState: transitionResult.fromState,
              toState: transitionResult.toState,
              currentState: transitionResult.currentState,
              message: transitionResult.message,
            },
            409,
          );
        }

        if (transitionResult.status === 'already_in_state') {
          c.header('Cache-Control', 'no-store');

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
          throw new Error('Lifecycle transition result is missing event details');
        }

        await createAuditLog(db, {
          tenantId: pathParams.tenantId,
          actorUserId: session.userId,
          action: 'assertion.lifecycle_transitioned',
          targetType: 'assertion',
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

        c.header('Cache-Control', 'no-store');

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
          if (error.message.includes('not found for tenant')) {
            return c.json(
              {
                error: 'Assertion not found',
              },
              404,
            );
          }

          if (
            error.message.includes('Manual lifecycle transitions require actorUserId') ||
            error.message.includes('Automated lifecycle transitions must not set actorUserId') ||
            error.message.includes('transitionedAt must be a valid ISO timestamp')
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
