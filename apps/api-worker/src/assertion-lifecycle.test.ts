import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    createAuditLog: vi.fn(),
    findActiveDelegatedIssuingAuthorityGrantForAction: vi.fn(),
    findActiveSessionByHash: vi.fn(),
    findAssertionById: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findTenantMembership: vi.fn(),
    findUserById: vi.fn(),
    hasTenantMembershipOrgUnitAccess: vi.fn(),
    hasTenantMembershipOrgUnitScopeAssignments: vi.fn(),
    listAssertionLifecycleEvents: vi.fn(),
    recordAssertionLifecycleTransition: vi.fn(),
    resolveAssertionLifecycleState: vi.fn(),
    touchSession: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  createAuditLog,
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findActiveSessionByHash,
  findAssertionById,
  findBadgeTemplateById,
  findTenantMembership,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  listAssertionLifecycleEvents,
  recordAssertionLifecycleTransition,
  resolveAssertionLifecycleState,
  touchSession,
  type AssertionRecord,
  type AuditLogRecord,
  type BadgeTemplateRecord,
  type DelegatedIssuingAuthorityGrantRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedFindActiveDelegatedIssuingAuthorityGrantForAction = vi.mocked(
  findActiveDelegatedIssuingAuthorityGrantForAction,
);
const mockedFindActiveSessionByHash = vi.mocked(findActiveSessionByHash);
const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedHasTenantMembershipOrgUnitAccess = vi.mocked(hasTenantMembershipOrgUnitAccess);
const mockedHasTenantMembershipOrgUnitScopeAssignments = vi.mocked(
  hasTenantMembershipOrgUnitScopeAssignments,
);
const mockedListAssertionLifecycleEvents = vi.mocked(listAssertionLifecycleEvents);
const mockedRecordAssertionLifecycleTransition = vi.mocked(recordAssertionLifecycleTransition);
const mockedResolveAssertionLifecycleState = vi.mocked(resolveAssertionLifecycleState);
const mockedTouchSession = vi.mocked(touchSession);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
} => {
  return {
    APP_ENV: 'test',
    DATABASE_URL: 'postgres://credtrail-test.local/db',
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: 'credtrail.test',
  };
};

const sampleAssertion = (overrides?: {
  revokedAt?: string | null;
  statusListIndex?: number | null;
}): AssertionRecord => {
  return {
    id: 'tenant_123:assertion_456',
    tenantId: 'tenant_123',
    publicId: '40a6dc92-85ec-4cb0-8a50-afb2ae700e22',
    learnerProfileId: 'lpr_123',
    badgeTemplateId: 'badge_template_001',
    recipientIdentity: 'learner@example.edu',
    recipientIdentityType: 'email',
    vcR2Key: 'tenants/tenant_123/assertions/tenant_123%3Aassertion_456.jsonld',
    statusListIndex: overrides?.statusListIndex === undefined ? 0 : overrides.statusListIndex,
    idempotencyKey: 'idem_abc',
    issuedAt: '2026-02-10T22:00:00.000Z',
    issuedByUserId: 'usr_123',
    revokedAt: overrides?.revokedAt ?? null,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
  };
};

const sampleSession = (overrides?: { tenantId?: string; userId?: string }): SessionRecord => {
  return {
    id: 'ses_123',
    tenantId: overrides?.tenantId ?? 'tenant_123',
    userId: overrides?.userId ?? 'usr_123',
    sessionTokenHash: 'session-hash',
    expiresAt: '2026-02-11T22:00:00.000Z',
    lastSeenAt: '2026-02-10T22:00:00.000Z',
    revokedAt: null,
    createdAt: '2026-02-10T22:00:00.000Z',
  };
};

const sampleBadgeTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: 'badge_template_001',
    tenantId: 'tenant_123',
    slug: 'typescript-foundations',
    title: 'TypeScript Foundations',
    description: 'Awarded for completing TS basics.',
    criteriaUri: null,
    imageUri: null,
    createdByUserId: 'usr_issuer',
    ownerOrgUnitId: 'tenant_123:org:institution',
    governanceMetadataJson: '{"stability":"institution_registry"}',
    isArchived: false,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

const sampleTenantMembership = (
  overrides?: Partial<TenantMembershipRecord>,
): TenantMembershipRecord => {
  return {
    tenantId: 'tenant_123',
    userId: 'usr_123',
    role: 'issuer',
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

const sampleDelegatedIssuingAuthorityGrant = (
  overrides?: Partial<DelegatedIssuingAuthorityGrantRecord>,
): DelegatedIssuingAuthorityGrantRecord => {
  return {
    id: 'dag_123',
    tenantId: 'tenant_123',
    delegateUserId: 'usr_delegate',
    delegatedByUserId: 'usr_admin',
    orgUnitId: 'tenant_123:org:department-math',
    allowedActions: ['issue_badge'],
    badgeTemplateIds: ['badge_template_001'],
    startsAt: '2026-02-13T00:00:00.000Z',
    endsAt: '2026-03-13T00:00:00.000Z',
    revokedAt: null,
    revokedByUserId: null,
    revokedReason: null,
    status: 'active',
    createdAt: '2026-02-13T00:00:00.000Z',
    updatedAt: '2026-02-13T00:00:00.000Z',
    ...overrides,
  };
};

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    ...overrides,
    id: 'aud_123',
    tenantId: 'tenant_123',
    actorUserId: 'usr_123',
    action: 'assertion.issued',
    targetType: 'assertion',
    targetId: 'tenant_123:assertion_456',
    metadataJson: null,
    occurredAt: '2026-02-10T22:00:00.000Z',
    createdAt: '2026-02-10T22:00:00.000Z',
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
});

describe('assertion lifecycle endpoints', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedFindAssertionById.mockReset();
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedFindBadgeTemplateById.mockReset();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindTenantMembership.mockReset();
    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
    mockedHasTenantMembershipOrgUnitScopeAssignments.mockReset();
    mockedHasTenantMembershipOrgUnitScopeAssignments.mockResolvedValue(false);
    mockedHasTenantMembershipOrgUnitAccess.mockReset();
    mockedHasTenantMembershipOrgUnitAccess.mockResolvedValue(false);
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockReset();
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(null);
    mockedResolveAssertionLifecycleState.mockReset();
    mockedListAssertionLifecycleEvents.mockReset();
    mockedRecordAssertionLifecycleTransition.mockReset();
    mockedCreateAuditLog.mockClear();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
  });

  it('returns assertion lifecycle state and history for issuer roles', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedResolveAssertionLifecycleState.mockResolvedValue({
      state: 'suspended',
      source: 'lifecycle_event',
      reasonCode: 'administrative_hold',
      reason: 'Pending registrar review',
      transitionedAt: '2026-02-12T23:10:00.000Z',
      revokedAt: null,
    });
    mockedListAssertionLifecycleEvents.mockResolvedValue([
      {
        id: 'ale_123',
        tenantId: 'tenant_123',
        assertionId: 'tenant_123:assertion_456',
        fromState: 'active',
        toState: 'suspended',
        reasonCode: 'administrative_hold',
        reason: 'Pending registrar review',
        transitionSource: 'manual',
        actorUserId: 'usr_123',
        transitionedAt: '2026-02-12T23:10:00.000Z',
        createdAt: '2026-02-12T23:10:00.000Z',
      },
    ]);

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/tenant_123%3Aassertion_456/lifecycle',
      {
        method: 'GET',
        headers: {
          Cookie: 'credtrail_session=session-token',
        },
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(body.state).toBe('suspended');
    expect(body.reasonCode).toBe('administrative_hold');
    expect(Array.isArray(body.events)).toBe(true);
    expect(mockedResolveAssertionLifecycleState).toHaveBeenCalledWith(
      fakeDb,
      'tenant_123',
      'tenant_123:assertion_456',
    );
  });

  it('applies manual lifecycle transition and writes audit log', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedRecordAssertionLifecycleTransition.mockResolvedValue({
      status: 'transitioned',
      fromState: 'active',
      toState: 'suspended',
      currentState: 'suspended',
      message: null,
      event: {
        id: 'ale_456',
        tenantId: 'tenant_123',
        assertionId: 'tenant_123:assertion_456',
        fromState: 'active',
        toState: 'suspended',
        reasonCode: 'administrative_hold',
        reason: 'Registrar hold',
        transitionSource: 'manual',
        actorUserId: 'usr_123',
        transitionedAt: '2026-02-12T23:15:00.000Z',
        createdAt: '2026-02-12T23:15:00.000Z',
      },
    });

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/tenant_123%3Aassertion_456/lifecycle/transition',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          toState: 'suspended',
          reasonCode: 'administrative_hold',
          reason: 'Registrar hold',
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(body.status).toBe('transitioned');
    expect(mockedRecordAssertionLifecycleTransition).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        assertionId: 'tenant_123:assertion_456',
        toState: 'suspended',
        reasonCode: 'administrative_hold',
        transitionSource: 'manual',
        actorUserId: 'usr_123',
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        action: 'assertion.lifecycle_transitioned',
        targetType: 'assertion',
        targetId: 'tenant_123:assertion_456',
      }),
    );
  });

  it('allows viewer lifecycle revocation when delegated authority grant is active', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedFindTenantMembership.mockResolvedValue(
      sampleTenantMembership({
        role: 'viewer',
      }),
    );
    mockedTouchSession.mockResolvedValue();
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant({
        delegateUserId: 'usr_123',
        allowedActions: ['revoke_badge'],
        badgeTemplateIds: ['badge_template_001'],
      }),
    );
    mockedRecordAssertionLifecycleTransition.mockResolvedValue({
      status: 'transitioned',
      fromState: 'active',
      toState: 'revoked',
      currentState: 'revoked',
      message: null,
      event: {
        id: 'ale_rev_123',
        tenantId: 'tenant_123',
        assertionId: 'tenant_123:assertion_456',
        fromState: 'active',
        toState: 'revoked',
        reasonCode: 'policy_violation',
        reason: 'Integrity failure',
        transitionSource: 'manual',
        actorUserId: 'usr_123',
        transitionedAt: '2026-02-12T23:15:00.000Z',
        createdAt: '2026-02-12T23:15:00.000Z',
      },
    });

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/tenant_123%3Aassertion_456/lifecycle/transition',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          toState: 'revoked',
          reasonCode: 'policy_violation',
          reason: 'Integrity failure',
        }),
      },
      env,
    );

    expect(response.status).toBe(200);
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        userId: 'usr_123',
        badgeTemplateId: 'badge_template_001',
        requiredAction: 'revoke_badge',
      }),
    );
    expect(mockedRecordAssertionLifecycleTransition).toHaveBeenCalledTimes(1);
  });

  it('returns 422 when caller attempts automation transition source', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/tenant_123%3Aassertion_456/lifecycle/transition',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          toState: 'expired',
          reasonCode: 'credential_expired',
          transitionSource: 'automation',
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(422);
    expect(body.error).toBe(
      'Automation lifecycle transitions are only allowed via trusted internal jobs',
    );
    expect(mockedRecordAssertionLifecycleTransition).not.toHaveBeenCalled();
    expect(mockedCreateAuditLog).not.toHaveBeenCalled();
  });

  it('returns 409 when lifecycle transition is not allowed', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedRecordAssertionLifecycleTransition.mockResolvedValue({
      status: 'invalid_transition',
      fromState: 'revoked',
      toState: 'active',
      currentState: 'revoked',
      event: null,
      message: 'transition from revoked to active is not allowed',
    });

    const response = await app.request(
      '/v1/tenants/tenant_123/assertions/tenant_123%3Aassertion_456/lifecycle/transition',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          toState: 'active',
          reasonCode: 'appeal_resolved',
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(409);
    expect(body.error).toBe('Lifecycle transition not allowed');
    expect(mockedCreateAuditLog).not.toHaveBeenCalled();
  });
});
