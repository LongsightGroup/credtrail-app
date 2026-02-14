import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    enqueueJobQueueMessage: vi.fn(),
    findActiveSessionByHash: vi.fn(),
    findLearnerProfileByIdentity: vi.fn(),
    findTenantMembership: vi.fn(),
    listBadgeTemplates: vi.fn(),
    touchSession: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  enqueueJobQueueMessage,
  findLearnerProfileByIdentity,
  findActiveSessionByHash,
  findTenantMembership,
  listBadgeTemplates,
  touchSession,
  type BadgeTemplateRecord,
  type LearnerProfileRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedFindActiveSessionByHash = vi.mocked(findActiveSessionByHash);
const mockedEnqueueJobQueueMessage = vi.mocked(enqueueJobQueueMessage);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedListBadgeTemplates = vi.mocked(listBadgeTemplates);
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

const sampleSession = (): SessionRecord => {
  return {
    id: 'ses_123',
    tenantId: 'tenant_123',
    userId: 'usr_123',
    sessionTokenHash: 'session_hash',
    expiresAt: '2026-03-01T00:00:00.000Z',
    lastSeenAt: '2026-02-14T12:00:00.000Z',
    revokedAt: null,
    createdAt: '2026-02-14T12:00:00.000Z',
  };
};

const sampleMembership = (): TenantMembershipRecord => {
  return {
    tenantId: 'tenant_123',
    userId: 'usr_123',
    role: 'issuer',
    createdAt: '2026-02-14T12:00:00.000Z',
    updatedAt: '2026-02-14T12:00:00.000Z',
  };
};

const sampleTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: 'badge_template_123',
    tenantId: 'tenant_123',
    slug: 'migration-foundations',
    title: 'Migration Foundations',
    description: 'Old description',
    criteriaUri: 'https://issuer.test/badges/old-criteria',
    imageUri: 'https://issuer.test/badges/old-image',
    createdByUserId: 'usr_123',
    ownerOrgUnitId: 'tenant_123:org:institution',
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: '2026-02-14T12:00:00.000Z',
    updatedAt: '2026-02-14T12:00:00.000Z',
    ...overrides,
  };
};

const sampleLearnerProfile = (): LearnerProfileRecord => {
  return {
    id: 'lpr_123',
    tenantId: 'tenant_123',
    subjectId: 'did:key:z6Mkexample',
    displayName: 'Learner',
    createdAt: '2026-02-14T12:00:00.000Z',
    updatedAt: '2026-02-14T12:00:00.000Z',
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedEnqueueJobQueueMessage.mockReset();
  mockedEnqueueJobQueueMessage.mockResolvedValue({
    id: 'job_123',
    tenantId: 'tenant_123',
    jobType: 'import_migration_batch',
    payloadJson: '{}',
    idempotencyKey: 'idem_123',
    attemptCount: 0,
    maxAttempts: 8,
    availableAt: '2026-02-14T12:00:00.000Z',
    leasedUntil: null,
    leaseToken: null,
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: 'pending',
    createdAt: '2026-02-14T12:00:00.000Z',
    updatedAt: '2026-02-14T12:00:00.000Z',
  });
  mockedFindActiveSessionByHash.mockReset();
  mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
  mockedFindLearnerProfileByIdentity.mockReset();
  mockedFindLearnerProfileByIdentity.mockResolvedValue(null);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleMembership());
  mockedListBadgeTemplates.mockReset();
  mockedListBadgeTemplates.mockResolvedValue([]);
  mockedTouchSession.mockReset();
  mockedTouchSession.mockResolvedValue();
});

describe('POST /v1/tenants/:tenantId/migrations/ob2/convert', () => {
  it('converts OB2 assertion payloads into normalized import candidates', async () => {
    const env = createEnv();

    const response = await app.request(
      '/v1/tenants/tenant_123/migrations/ob2/convert',
      {
        method: 'POST',
        headers: {
          cookie: 'credtrail_session=test-session-token',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          ob2Assertion: {
            '@context': 'https://w3id.org/openbadges/v2',
            type: 'Assertion',
            recipient: {
              type: 'email',
              identity: 'learner@example.edu',
            },
            badge: {
              type: 'BadgeClass',
              id: 'https://issuer.test/badges/24',
              name: 'Migration Foundations',
              criteria: {
                id: 'https://issuer.test/badges/24/criteria',
              },
              image: {
                id: 'https://issuer.test/badges/24/image',
              },
              issuer: {
                id: 'https://issuer.test/issuers/1',
                name: 'Issuer Test',
                url: 'https://issuer.test',
              },
            },
            issuedOn: '2025-10-01T12:00:00Z',
          },
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.tenantId).toBe('tenant_123');

    const conversion = body.conversion as Record<string, unknown>;
    expect(conversion).toBeDefined();

    const createBadgeTemplateRequest = conversion
      .createBadgeTemplateRequest as Record<string, unknown>;
    const manualIssueRequest = conversion.manualIssueRequest as Record<string, unknown>;

    expect(createBadgeTemplateRequest.title).toBe('Migration Foundations');
    expect(manualIssueRequest.recipientIdentity).toBe('learner@example.edu');
    expect(manualIssueRequest.recipientIdentityType).toBe('email');
  });

  it('requires tenant authentication', async () => {
    const env = createEnv();

    const response = await app.request(
      '/v1/tenants/tenant_123/migrations/ob2/convert',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          ob2Assertion: {
            type: 'Assertion',
          },
        }),
      },
      env,
    );

    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(401);
    expect(body.error).toBe('Not authenticated');
  });
});

describe('POST /v1/tenants/:tenantId/migrations/ob2/dry-run', () => {
  it('returns dry-run validation report with diff preview for valid payloads', async () => {
    const env = createEnv();
    mockedListBadgeTemplates.mockResolvedValue([
      sampleTemplate({
        slug: 'migration-foundations',
      }),
    ]);
    mockedFindLearnerProfileByIdentity.mockResolvedValue(sampleLearnerProfile());

    const response = await app.request(
      '/v1/tenants/tenant_123/migrations/ob2/dry-run',
      {
        method: 'POST',
        headers: {
          cookie: 'credtrail_session=test-session-token',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          ob2Assertion: {
            '@context': 'https://w3id.org/openbadges/v2',
            type: 'Assertion',
            recipient: {
              type: 'email',
              identity: 'learner@example.edu',
            },
            badge: {
              type: 'BadgeClass',
              id: 'https://issuer.test/badges/24',
              name: 'Migration Foundations',
              description: 'New description',
              criteria: {
                id: 'https://issuer.test/badges/24/criteria',
              },
              image: {
                id: 'https://issuer.test/badges/24/image',
              },
              issuer: {
                id: 'https://issuer.test/issuers/1',
                name: 'Issuer Test',
                url: 'https://issuer.test',
              },
            },
            issuedOn: '2025-10-01T12:00:00Z',
          },
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.status).toBe('valid');

    const validationReport = body.validationReport as Record<string, unknown>;
    const diffPreview = validationReport.diffPreview as Record<string, unknown>;
    const badgeTemplate = diffPreview.badgeTemplate as Record<string, unknown>;
    const learnerProfile = diffPreview.learnerProfile as Record<string, unknown>;
    const summary = diffPreview.summary as Record<string, unknown>;

    expect((validationReport.errors as unknown[]).length).toBe(0);
    expect(badgeTemplate.operation).toBe('update');
    expect((badgeTemplate.changedFields as unknown[]).length).toBeGreaterThan(0);
    expect(learnerProfile.operation).toBe('reuse');
    expect(summary.updates).toBe(1);
  });

  it('returns invalid status with parser errors for malformed payload', async () => {
    const env = createEnv();

    const response = await app.request(
      '/v1/tenants/tenant_123/migrations/ob2/dry-run',
      {
        method: 'POST',
        headers: {
          cookie: 'credtrail_session=test-session-token',
          'content-type': 'application/json',
        },
        body: JSON.stringify({}),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.status).toBe('invalid');

    const validationReport = body.validationReport as Record<string, unknown>;
    expect((validationReport.errors as unknown[]).length).toBeGreaterThan(0);
    expect(validationReport.diffPreview).toBeNull();
  });
});

describe('POST /v1/tenants/:tenantId/migrations/ob2/batch-upload', () => {
  it('parses uploaded JSON file and returns row validation summaries in dry-run mode', async () => {
    const env = createEnv();
    const formData = new FormData();
    formData.append(
      'file',
      new Blob(
        [
          JSON.stringify([
            {
              ob2Assertion: {
                '@context': 'https://w3id.org/openbadges/v2',
                type: 'Assertion',
                recipient: {
                  type: 'email',
                  identity: 'learner@example.edu',
                },
                badge: {
                  type: 'BadgeClass',
                  name: 'Batch JSON Badge',
                  issuer: {
                    id: 'https://issuer.test/issuers/1',
                    name: 'Issuer Test',
                    url: 'https://issuer.test',
                  },
                },
                issuedOn: '2025-10-01T12:00:00Z',
              },
            },
            {
              ob2Assertion: {
                type: 'Assertion',
              },
            },
          ]),
        ],
        {
          type: 'application/json',
        },
      ),
      'migration.json',
    );

    const response = await app.request(
      '/v1/tenants/tenant_123/migrations/ob2/batch-upload?dryRun=true',
      {
        method: 'POST',
        headers: {
          cookie: 'credtrail_session=test-session-token',
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.dryRun).toBe(true);
    expect(body.totalRows).toBe(2);
    expect(body.validRows).toBe(1);
    expect(body.invalidRows).toBe(1);
    expect(body.queuedRows).toBe(0);
    expect(mockedEnqueueJobQueueMessage).not.toHaveBeenCalled();

    const rows = body.rows as Record<string, unknown>[];
    expect(rows[0]?.status).toBe('valid');
    expect(rows[1]?.status).toBe('invalid');
  });

  it('queues valid rows when dryRun=false for CSV upload', async () => {
    const env = createEnv();
    const formData = new FormData();
    const csvCell = (value: string): string => {
      return `"${value.replaceAll('"', '""')}"`;
    };
    const csvRow = [
      csvCell(
        JSON.stringify({
          type: 'Assertion',
          recipient: {
            type: 'email',
            identity: 'learner@example.edu',
          },
          badge: 'https://issuer.test/badges/1',
          issuedOn: '2025-10-01T12:00:00Z',
        }),
      ),
      csvCell(
        JSON.stringify({
          type: 'BadgeClass',
          id: 'https://issuer.test/badges/1',
          name: 'Batch CSV Badge',
          issuer: 'https://issuer.test/issuers/1',
        }),
      ),
      csvCell(
        JSON.stringify({
          type: 'Issuer',
          id: 'https://issuer.test/issuers/1',
          name: 'Issuer Test',
          url: 'https://issuer.test',
        }),
      ),
    ].join(',');
    const csv = [
      'ob2Assertion,ob2BadgeClass,ob2Issuer',
      csvRow,
    ].join('\n');
    formData.append(
      'file',
      new Blob([csv], {
        type: 'text/csv',
      }),
      'migration.csv',
    );

    const response = await app.request(
      '/v1/tenants/tenant_123/migrations/ob2/batch-upload?dryRun=false',
      {
        method: 'POST',
        headers: {
          cookie: 'credtrail_session=test-session-token',
        },
        body: formData,
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(body.dryRun).toBe(false);
    expect(body.totalRows).toBe(1);
    expect(body.validRows).toBe(1);
    expect(body.invalidRows).toBe(0);
    expect(body.queuedRows).toBe(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledTimes(1);
    expect(mockedEnqueueJobQueueMessage).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: 'tenant_123',
        jobType: 'import_migration_batch',
      }),
    );
  });
});
