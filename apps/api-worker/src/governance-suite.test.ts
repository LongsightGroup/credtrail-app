import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    createAuditLog: vi.fn(),
    createDelegatedIssuingAuthorityGrant: vi.fn(),
    createTenantApiKey: vi.fn(),
    createTenantOrgUnit: vi.fn(),
    deleteTenantSsoSamlConfiguration: vi.fn(),
    findActiveDelegatedIssuingAuthorityGrantForAction: vi.fn(),
    findActiveSessionByHash: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findDelegatedIssuingAuthorityGrantById: vi.fn(),
    findTenantMembership: vi.fn(),
    findTenantById: vi.fn(),
    findTenantSsoSamlConfiguration: vi.fn(),
    findUserById: vi.fn(),
    hasTenantMembershipOrgUnitAccess: vi.fn(),
    hasTenantMembershipOrgUnitScopeAssignments: vi.fn(),
    listBadgeTemplateOwnershipEvents: vi.fn(),
    listDelegatedIssuingAuthorityGrantEvents: vi.fn(),
    listDelegatedIssuingAuthorityGrants: vi.fn(),
    listTenantMembershipOrgUnitScopes: vi.fn(),
    listTenantOrgUnits: vi.fn(),
    listTenantApiKeys: vi.fn(),
    removeTenantMembershipOrgUnitScope: vi.fn(),
    revokeTenantApiKey: vi.fn(),
    revokeDelegatedIssuingAuthorityGrant: vi.fn(),
    touchSession: vi.fn(),
    transferBadgeTemplateOwnership: vi.fn(),
    upsertTenantSsoSamlConfiguration: vi.fn(),
    upsertTenantMembershipOrgUnitScope: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  createAuditLog,
  createDelegatedIssuingAuthorityGrant,
  createTenantApiKey,
  createTenantOrgUnit,
  deleteTenantSsoSamlConfiguration,
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findActiveSessionByHash,
  findBadgeTemplateById,
  findDelegatedIssuingAuthorityGrantById,
  findTenantMembership,
  findTenantById,
  findTenantSsoSamlConfiguration,
  findUserById,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  listBadgeTemplateOwnershipEvents,
  listDelegatedIssuingAuthorityGrantEvents,
  listDelegatedIssuingAuthorityGrants,
  listTenantApiKeys,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  removeTenantMembershipOrgUnitScope,
  revokeTenantApiKey,
  revokeDelegatedIssuingAuthorityGrant,
  touchSession,
  transferBadgeTemplateOwnership,
  upsertTenantSsoSamlConfiguration,
  upsertTenantMembershipOrgUnitScope,
  type TenantApiKeyRecord,
  type AuditLogRecord,
  type BadgeTemplateOwnershipEventRecord,
  type BadgeTemplateRecord,
  type DelegatedIssuingAuthorityGrantEventRecord,
  type DelegatedIssuingAuthorityGrantRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantRecord,
  type TenantMembershipOrgUnitScopeRecord,
  type TenantMembershipRecord,
  type TenantOrgUnitRecord,
  type TenantSsoSamlConfigurationRecord,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

interface ErrorResponse {
  error: string;
}

const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedCreateDelegatedIssuingAuthorityGrant = vi.mocked(createDelegatedIssuingAuthorityGrant);
const mockedCreateTenantApiKey = vi.mocked(createTenantApiKey);
const mockedCreateTenantOrgUnit = vi.mocked(createTenantOrgUnit);
const mockedDeleteTenantSsoSamlConfiguration = vi.mocked(deleteTenantSsoSamlConfiguration);
const mockedFindActiveDelegatedIssuingAuthorityGrantForAction = vi.mocked(
  findActiveDelegatedIssuingAuthorityGrantForAction,
);
const mockedFindActiveSessionByHash = vi.mocked(findActiveSessionByHash);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindDelegatedIssuingAuthorityGrantById = vi.mocked(
  findDelegatedIssuingAuthorityGrantById,
);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedFindTenantById = vi.mocked(findTenantById);
const mockedFindTenantSsoSamlConfiguration = vi.mocked(findTenantSsoSamlConfiguration);
const mockedFindUserById = vi.mocked(findUserById);
const mockedHasTenantMembershipOrgUnitAccess = vi.mocked(hasTenantMembershipOrgUnitAccess);
const mockedHasTenantMembershipOrgUnitScopeAssignments = vi.mocked(
  hasTenantMembershipOrgUnitScopeAssignments,
);
const mockedListBadgeTemplateOwnershipEvents = vi.mocked(listBadgeTemplateOwnershipEvents);
const mockedListDelegatedIssuingAuthorityGrantEvents = vi.mocked(
  listDelegatedIssuingAuthorityGrantEvents,
);
const mockedListDelegatedIssuingAuthorityGrants = vi.mocked(listDelegatedIssuingAuthorityGrants);
const mockedListTenantApiKeys = vi.mocked(listTenantApiKeys);
const mockedListTenantMembershipOrgUnitScopes = vi.mocked(listTenantMembershipOrgUnitScopes);
const mockedListTenantOrgUnits = vi.mocked(listTenantOrgUnits);
const mockedRemoveTenantMembershipOrgUnitScope = vi.mocked(removeTenantMembershipOrgUnitScope);
const mockedRevokeTenantApiKey = vi.mocked(revokeTenantApiKey);
const mockedRevokeDelegatedIssuingAuthorityGrant = vi.mocked(revokeDelegatedIssuingAuthorityGrant);
const mockedTouchSession = vi.mocked(touchSession);
const mockedTransferBadgeTemplateOwnership = vi.mocked(transferBadgeTemplateOwnership);
const mockedUpsertTenantSsoSamlConfiguration = vi.mocked(upsertTenantSsoSamlConfiguration);
const mockedUpsertTenantMembershipOrgUnitScope = vi.mocked(upsertTenantMembershipOrgUnitScope);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  MARKETING_SITE_ORIGIN?: string;
  TENANT_SIGNING_KEY_HISTORY_JSON?: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
  JOB_PROCESSOR_TOKEN?: string;
  BOOTSTRAP_ADMIN_TOKEN?: string;
  LTI_ISSUER_REGISTRY_JSON?: string;
  LTI_STATE_SIGNING_SECRET?: string;
} => {
  return {
    APP_ENV: 'test',
    DATABASE_URL: 'postgres://credtrail-test.local/db',
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: 'credtrail.test',
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
  mockedFindTenantById.mockReset();
  mockedFindTenantById.mockResolvedValue(sampleTenant());
  mockedFindTenantSsoSamlConfiguration.mockReset();
  mockedFindTenantSsoSamlConfiguration.mockResolvedValue(null);
  mockedFindUserById.mockReset();
  mockedFindUserById.mockResolvedValue({
    id: 'usr_123',
    email: 'learner@example.edu',
  });
  mockedFindDelegatedIssuingAuthorityGrantById.mockReset();
  mockedFindDelegatedIssuingAuthorityGrantById.mockResolvedValue(null);
  mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockReset();
  mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(null);
  mockedHasTenantMembershipOrgUnitAccess.mockReset();
  mockedHasTenantMembershipOrgUnitAccess.mockResolvedValue(false);
  mockedHasTenantMembershipOrgUnitScopeAssignments.mockReset();
  mockedHasTenantMembershipOrgUnitScopeAssignments.mockResolvedValue(false);
  mockedListBadgeTemplateOwnershipEvents.mockReset();
  mockedListBadgeTemplateOwnershipEvents.mockResolvedValue([]);
  mockedListDelegatedIssuingAuthorityGrantEvents.mockReset();
  mockedListDelegatedIssuingAuthorityGrantEvents.mockResolvedValue([]);
  mockedListDelegatedIssuingAuthorityGrants.mockReset();
  mockedListDelegatedIssuingAuthorityGrants.mockResolvedValue([]);
  mockedListTenantApiKeys.mockReset();
  mockedListTenantApiKeys.mockResolvedValue([]);
  mockedListTenantMembershipOrgUnitScopes.mockReset();
  mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([]);
  mockedListTenantOrgUnits.mockReset();
  mockedListTenantOrgUnits.mockResolvedValue([]);
  mockedCreateTenantOrgUnit.mockReset();
  mockedCreateTenantApiKey.mockReset();
  mockedCreateTenantApiKey.mockResolvedValue(sampleTenantApiKey());
  mockedDeleteTenantSsoSamlConfiguration.mockReset();
  mockedDeleteTenantSsoSamlConfiguration.mockResolvedValue(false);
  mockedTransferBadgeTemplateOwnership.mockReset();
  mockedUpsertTenantSsoSamlConfiguration.mockReset();
  mockedUpsertTenantSsoSamlConfiguration.mockResolvedValue(sampleTenantSsoSamlConfiguration());
  mockedUpsertTenantMembershipOrgUnitScope.mockReset();
  mockedRemoveTenantMembershipOrgUnitScope.mockReset();
  mockedRemoveTenantMembershipOrgUnitScope.mockResolvedValue(false);
  mockedRevokeTenantApiKey.mockReset();
  mockedRevokeTenantApiKey.mockResolvedValue(false);
  mockedCreateDelegatedIssuingAuthorityGrant.mockReset();
  mockedRevokeDelegatedIssuingAuthorityGrant.mockReset();
  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
});

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

const sampleTenant = (overrides?: Partial<TenantRecord>): TenantRecord => {
  return {
    id: 'tenant_123',
    slug: 'tenant-123',
    displayName: 'Tenant 123',
    planTier: 'enterprise',
    issuerDomain: 'tenant-123.credtrail.test',
    didWeb: 'did:web:credtrail.test:tenant_123',
    isActive: true,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

const sampleTenantApiKey = (overrides?: Partial<TenantApiKeyRecord>): TenantApiKeyRecord => {
  return {
    id: 'tak_123',
    tenantId: 'tenant_123',
    label: 'Integration key',
    keyPrefix: 'ctak_abc12345',
    keyHash: 'hash_123',
    scopesJson: '["queue.issue","queue.revoke"]',
    createdByUserId: 'usr_123',
    expiresAt: null,
    lastUsedAt: null,
    revokedAt: null,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

const sampleTenantSsoSamlConfiguration = (
  overrides?: Partial<TenantSsoSamlConfigurationRecord>,
): TenantSsoSamlConfigurationRecord => {
  return {
    tenantId: 'tenant_123',
    idpEntityId: 'https://idp.example.edu/entity',
    ssoLoginUrl: 'https://idp.example.edu/sso/login',
    idpCertificatePem: '-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----',
    idpMetadataUrl: 'https://idp.example.edu/metadata',
    spEntityId: 'https://credtrail.test/saml/sp',
    assertionConsumerServiceUrl: 'https://credtrail.test/saml/acs',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    enforced: true,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
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

const sampleTenantOrgUnit = (overrides?: Partial<TenantOrgUnitRecord>): TenantOrgUnitRecord => {
  return {
    id: 'tenant_123:org:institution',
    tenantId: 'tenant_123',
    unitType: 'institution',
    slug: 'institution',
    displayName: 'Tenant 123 Institution',
    parentOrgUnitId: null,
    createdByUserId: 'usr_123',
    isActive: true,
    createdAt: '2026-02-10T22:00:00.000Z',
    updatedAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

const sampleTenantMembershipOrgUnitScope = (
  overrides?: Partial<TenantMembershipOrgUnitScopeRecord>,
): TenantMembershipOrgUnitScopeRecord => {
  return {
    tenantId: 'tenant_123',
    userId: 'usr_123',
    orgUnitId: 'tenant_123:org:department-math',
    role: 'issuer',
    createdByUserId: 'usr_admin',
    createdAt: '2026-02-13T00:00:00.000Z',
    updatedAt: '2026-02-13T00:00:00.000Z',
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

const sampleDelegatedIssuingAuthorityGrantEvent = (
  overrides?: Partial<DelegatedIssuingAuthorityGrantEventRecord>,
): DelegatedIssuingAuthorityGrantEventRecord => {
  return {
    id: 'dage_123',
    tenantId: 'tenant_123',
    grantId: 'dag_123',
    eventType: 'granted',
    actorUserId: 'usr_admin',
    detailsJson: '{"reason":"Spring delegation"}',
    occurredAt: '2026-02-13T00:00:00.000Z',
    createdAt: '2026-02-13T00:00:00.000Z',
    ...overrides,
  };
};

const sampleBadgeTemplateOwnershipEvent = (
  overrides?: Partial<BadgeTemplateOwnershipEventRecord>,
): BadgeTemplateOwnershipEventRecord => {
  return {
    id: 'btoe_123',
    tenantId: 'tenant_123',
    badgeTemplateId: 'badge_template_001',
    fromOrgUnitId: 'tenant_123:org:institution',
    toOrgUnitId: 'tenant_123:org:department-math',
    reasonCode: 'administrative_transfer',
    reason: 'Moved to Math governance',
    governanceMetadataJson: '{"governancePolicyVersion":"2026-02-13"}',
    transferredByUserId: 'usr_123',
    transferredAt: '2026-02-13T00:00:00.000Z',
    createdAt: '2026-02-13T00:00:00.000Z',
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

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: 'aud_123',
    tenantId: 'tenant_123',
    actorUserId: 'usr_123',
    action: 'assertion.issued',
    targetType: 'assertion',
    targetId: 'tenant_123:assertion_456',
    metadataJson: null,
    occurredAt: '2026-02-10T22:00:00.000Z',
    createdAt: '2026-02-10T22:00:00.000Z',
    ...overrides,
  };
};

describe('org unit and badge ownership governance endpoints', () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedCreateTenantOrgUnit.mockReset();
    mockedListTenantOrgUnits.mockReset();
    mockedListBadgeTemplateOwnershipEvents.mockReset();
    mockedTransferBadgeTemplateOwnership.mockReset();
    mockedFindBadgeTemplateById.mockReset();
    mockedFindDelegatedIssuingAuthorityGrantById.mockReset();
    mockedFindDelegatedIssuingAuthorityGrantById.mockResolvedValue(null);
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockReset();
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(null);
    mockedCreateAuditLog.mockClear();
  });

  it('lists tenant org units for issuer roles', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedListTenantOrgUnits.mockResolvedValue([
      sampleTenantOrgUnit(),
      sampleTenantOrgUnit({
        id: 'tenant_123:org:department-math',
        unitType: 'department',
        slug: 'math',
        displayName: 'Department of Mathematics',
      }),
    ]);

    const response = await app.request(
      '/v1/tenants/tenant_123/org-units',
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
    expect(body.tenantId).toBe('tenant_123');
    expect(Array.isArray(body.orgUnits)).toBe(true);
    expect(mockedListTenantOrgUnits).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      includeInactive: false,
    });
  });

  it('creates a tenant org unit for admin roles and writes audit log', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedCreateTenantOrgUnit.mockResolvedValue(
      sampleTenantOrgUnit({
        id: 'ou_department_math',
        unitType: 'department',
        slug: 'math',
        displayName: 'Department of Mathematics',
      }),
    );

    const response = await app.request(
      '/v1/tenants/tenant_123/org-units',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          unitType: 'department',
          slug: 'math',
          displayName: 'Department of Mathematics',
          parentOrgUnitId: 'tenant_123:org:institution',
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.tenantId).toBe('tenant_123');
    expect(mockedCreateTenantOrgUnit).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        unitType: 'department',
        slug: 'math',
        displayName: 'Department of Mathematics',
        parentOrgUnitId: 'tenant_123:org:institution',
        createdByUserId: 'usr_123',
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        action: 'tenant.org_unit_created',
        targetType: 'org_unit',
      }),
    );
  });

  it('upserts enterprise tenant SAML SSO configuration and writes audit log', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindTenantById.mockResolvedValue(sampleTenant({ planTier: 'enterprise' }));
    mockedUpsertTenantSsoSamlConfiguration.mockResolvedValue(sampleTenantSsoSamlConfiguration());

    const response = await app.request(
      '/v1/tenants/tenant_123/sso/saml',
      {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          idpEntityId: 'https://idp.example.edu/entity',
          ssoLoginUrl: 'https://idp.example.edu/sso/login',
          idpCertificatePem: '-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----',
          idpMetadataUrl: 'https://idp.example.edu/metadata',
          spEntityId: 'https://credtrail.test/saml/sp',
          assertionConsumerServiceUrl: 'https://credtrail.test/saml/acs',
          nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
          enforced: true,
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.tenantId).toBe('tenant_123');
    expect(mockedUpsertTenantSsoSamlConfiguration).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        idpEntityId: 'https://idp.example.edu/entity',
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: 'tenant.sso_saml_configuration_upserted',
      }),
    );
  });

  it('returns 403 for SAML SSO configuration on non-enterprise plans', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindTenantById.mockResolvedValue(sampleTenant({ planTier: 'team' }));

    const response = await app.request(
      '/v1/tenants/tenant_123/sso/saml',
      {
        method: 'GET',
        headers: {
          Cookie: 'credtrail_session=session-token',
        },
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toContain('enterprise');
  });

  it('creates tenant API keys for admin roles and writes audit log', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedCreateTenantApiKey.mockResolvedValue(sampleTenantApiKey());

    const response = await app.request(
      '/v1/tenants/tenant_123/api-keys',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          label: 'Integration key',
          scopes: ['queue.issue', 'queue.revoke'],
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.tenantId).toBe('tenant_123');
    expect(typeof body.apiKey).toBe('string');
    expect(mockedCreateTenantApiKey).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        label: 'Integration key',
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: 'tenant.api_key_created',
      }),
    );
  });

  it('lists and revokes tenant API keys for admin roles', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedListTenantApiKeys.mockResolvedValue([sampleTenantApiKey()]);
    mockedRevokeTenantApiKey.mockResolvedValue(true);

    const listResponse = await app.request(
      '/v1/tenants/tenant_123/api-keys?includeRevoked=true',
      {
        method: 'GET',
        headers: {
          Cookie: 'credtrail_session=session-token',
        },
      },
      env,
    );
    const listBody = await listResponse.json<Record<string, unknown>>();

    expect(listResponse.status).toBe(200);
    expect(Array.isArray(listBody.keys)).toBe(true);
    expect(mockedListTenantApiKeys).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      includeRevoked: true,
    });

    const revokeResponse = await app.request(
      '/v1/tenants/tenant_123/api-keys/tak_123/revoke',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          revokedAt: '2026-02-20T00:00:00.000Z',
        }),
      },
      env,
    );
    const revokeBody = await revokeResponse.json<Record<string, unknown>>();

    expect(revokeResponse.status).toBe(200);
    expect(revokeBody.revoked).toBe(true);
    expect(mockedRevokeTenantApiKey).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      apiKeyId: 'tak_123',
      revokedAt: '2026-02-20T00:00:00.000Z',
    });
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: 'tenant.api_key_revoked',
      }),
    );
  });

  it('returns badge template ownership history', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedListBadgeTemplateOwnershipEvents.mockResolvedValue([sampleBadgeTemplateOwnershipEvent()]);

    const response = await app.request(
      '/v1/tenants/tenant_123/badge-templates/badge_template_001/ownership-history',
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
    expect(body.tenantId).toBe('tenant_123');
    expect(Array.isArray(body.events)).toBe(true);
    expect(mockedListBadgeTemplateOwnershipEvents).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      badgeTemplateId: 'badge_template_001',
    });
  });

  it('transfers badge template ownership and writes audit log', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedTransferBadgeTemplateOwnership.mockResolvedValue({
      status: 'transferred',
      template: sampleBadgeTemplate({
        ownerOrgUnitId: 'tenant_123:org:department-math',
        governanceMetadataJson: '{"governancePolicyVersion":"2026-02-13"}',
      }),
      event: sampleBadgeTemplateOwnershipEvent(),
    });

    const response = await app.request(
      '/v1/tenants/tenant_123/badge-templates/badge_template_001/ownership-transfer',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          toOrgUnitId: 'tenant_123:org:department-math',
          reasonCode: 'administrative_transfer',
          reason: 'Moved to Math governance',
          governanceMetadata: {
            governancePolicyVersion: '2026-02-13',
          },
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.status).toBe('transferred');
    expect(mockedTransferBadgeTemplateOwnership).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        badgeTemplateId: 'badge_template_001',
        toOrgUnitId: 'tenant_123:org:department-math',
        reasonCode: 'administrative_transfer',
        transferredByUserId: 'usr_123',
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        action: 'badge_template.ownership_transferred',
        targetType: 'badge_template',
      }),
    );
  });

  it('lists scoped org-unit grants for a tenant user', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([
      sampleTenantMembershipOrgUnitScope({ userId: 'usr_issuer' }),
    ]);

    const response = await app.request(
      '/v1/tenants/tenant_123/users/usr_issuer/org-unit-scopes',
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
    expect(body.userId).toBe('usr_issuer');
    expect(Array.isArray(body.scopes)).toBe(true);
    expect(mockedListTenantMembershipOrgUnitScopes).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      userId: 'usr_issuer',
    });
  });

  it('upserts scoped org-unit grants for a tenant user', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedUpsertTenantMembershipOrgUnitScope.mockResolvedValue({
      scope: sampleTenantMembershipOrgUnitScope({
        userId: 'usr_issuer',
        orgUnitId: 'tenant_123:org:department-math',
        role: 'issuer',
      }),
      previousRole: null,
      changed: true,
    });

    const response = await app.request(
      '/v1/tenants/tenant_123/users/usr_issuer/org-unit-scopes/tenant_123:org:department-math',
      {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          role: 'issuer',
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.changed).toBe(true);
    expect(mockedUpsertTenantMembershipOrgUnitScope).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        userId: 'usr_issuer',
        orgUnitId: 'tenant_123:org:department-math',
        role: 'issuer',
        createdByUserId: 'usr_123',
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: 'membership.org_scope_assigned',
        targetType: 'membership_org_scope',
      }),
    );
  });

  it('deletes scoped org-unit grants for a tenant user', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedRemoveTenantMembershipOrgUnitScope.mockResolvedValue(true);

    const response = await app.request(
      '/v1/tenants/tenant_123/users/usr_issuer/org-unit-scopes/tenant_123:org:department-math',
      {
        method: 'DELETE',
        headers: {
          Cookie: 'credtrail_session=session-token',
        },
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.removed).toBe(true);
    expect(mockedRemoveTenantMembershipOrgUnitScope).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      userId: 'usr_issuer',
      orgUnitId: 'tenant_123:org:department-math',
    });
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: 'membership.org_scope_removed',
        targetType: 'membership_org_scope',
      }),
    );
  });

  it('lists delegated issuing authority grants for a tenant user', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedListDelegatedIssuingAuthorityGrants.mockResolvedValue([
      sampleDelegatedIssuingAuthorityGrant({ delegateUserId: 'usr_issuer' }),
    ]);

    const response = await app.request(
      '/v1/tenants/tenant_123/users/usr_issuer/issuing-authority-grants?includeRevoked=true',
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
    expect(body.userId).toBe('usr_issuer');
    expect(Array.isArray(body.grants)).toBe(true);
    expect(mockedListDelegatedIssuingAuthorityGrants).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      delegateUserId: 'usr_issuer',
      includeRevoked: true,
      includeExpired: false,
    });
  });

  it('creates delegated issuing authority grants and writes audit logs', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedCreateDelegatedIssuingAuthorityGrant.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant({
        id: 'dag_new',
        delegateUserId: 'usr_issuer',
        allowedActions: ['issue_badge', 'revoke_badge'],
      }),
    );

    const response = await app.request(
      '/v1/tenants/tenant_123/users/usr_issuer/issuing-authority-grants',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          orgUnitId: 'tenant_123:org:department-math',
          badgeTemplateIds: ['badge_template_001'],
          allowedActions: ['issue_badge', 'revoke_badge'],
          endsAt: '2026-03-13T00:00:00.000Z',
          reason: 'Spring term authority',
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(201);
    expect(body.userId).toBe('usr_issuer');
    expect(mockedCreateDelegatedIssuingAuthorityGrant).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        delegateUserId: 'usr_issuer',
        delegatedByUserId: 'usr_123',
        orgUnitId: 'tenant_123:org:department-math',
        allowedActions: ['issue_badge', 'revoke_badge'],
        badgeTemplateIds: ['badge_template_001'],
        endsAt: '2026-03-13T00:00:00.000Z',
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: 'delegated_issuing_authority.granted',
        targetType: 'delegated_issuing_authority_grant',
      }),
    );
  });

  it('revokes delegated issuing authority grants and writes audit logs', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindDelegatedIssuingAuthorityGrantById.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant({
        id: 'dag_123',
        delegateUserId: 'usr_issuer',
      }),
    );
    mockedRevokeDelegatedIssuingAuthorityGrant.mockResolvedValue({
      status: 'revoked',
      grant: sampleDelegatedIssuingAuthorityGrant({
        id: 'dag_123',
        delegateUserId: 'usr_issuer',
        revokedAt: '2026-02-20T00:00:00.000Z',
        revokedByUserId: 'usr_123',
        revokedReason: 'Policy update',
        status: 'revoked',
      }),
    });

    const response = await app.request(
      '/v1/tenants/tenant_123/users/usr_issuer/issuing-authority-grants/dag_123/revoke',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: 'credtrail_session=session-token',
        },
        body: JSON.stringify({
          reason: 'Policy update',
          revokedAt: '2026-02-20T00:00:00.000Z',
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.status).toBe('revoked');
    expect(mockedRevokeDelegatedIssuingAuthorityGrant).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        grantId: 'dag_123',
        revokedByUserId: 'usr_123',
        revokedReason: 'Policy update',
        revokedAt: '2026-02-20T00:00:00.000Z',
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: 'delegated_issuing_authority.revoked',
        targetType: 'delegated_issuing_authority_grant',
      }),
    );
  });

  it('returns delegated issuing authority grant lifecycle events', async () => {
    const env = createEnv();

    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership({ role: 'admin' }));
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindDelegatedIssuingAuthorityGrantById.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant({
        id: 'dag_123',
        delegateUserId: 'usr_issuer',
      }),
    );
    mockedListDelegatedIssuingAuthorityGrantEvents.mockResolvedValue([
      sampleDelegatedIssuingAuthorityGrantEvent({
        grantId: 'dag_123',
      }),
    ]);

    const response = await app.request(
      '/v1/tenants/tenant_123/users/usr_issuer/issuing-authority-grants/dag_123/events?limit=25',
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
    expect(Array.isArray(body.events)).toBe(true);
    expect(mockedListDelegatedIssuingAuthorityGrantEvents).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'tenant_123',
      grantId: 'dag_123',
      limit: 25,
    });
  });

  it('rejects ownership history when issuer lacks scoped viewer access', async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedHasTenantMembershipOrgUnitScopeAssignments.mockResolvedValue(true);
    mockedHasTenantMembershipOrgUnitAccess.mockResolvedValue(false);

    const response = await app.request(
      '/v1/tenants/tenant_123/badge-templates/badge_template_001/ownership-history',
      {
        method: 'GET',
        headers: {
          Cookie: 'credtrail_session=session-token',
        },
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toContain('Insufficient org-unit scope');
  });
});
