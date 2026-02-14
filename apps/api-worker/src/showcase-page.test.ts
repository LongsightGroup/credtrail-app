import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@credtrail/db', async () => {
  const actual = await vi.importActual<typeof import('@credtrail/db')>('@credtrail/db');

  return {
    ...actual,
    findUserById: vi.fn(),
    listPublicBadgeWallEntries: vi.fn(),
  };
});

vi.mock('@credtrail/db/postgres', () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  listPublicBadgeWallEntries,
  type PublicBadgeWallEntryRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { createPostgresDatabase } from '@credtrail/db/postgres';

import { app } from './index';

const mockedListPublicBadgeWallEntries = vi.mocked(listPublicBadgeWallEntries);
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

const samplePublicBadgeWallEntry = (
  overrides?: Partial<PublicBadgeWallEntryRecord>,
): PublicBadgeWallEntryRecord => {
  return {
    assertionId: 'sakai:assertion_001',
    assertionPublicId: 'a77ab5e5-bd08-40c3-accd-cf29ed1fdbbf',
    tenantId: 'sakai',
    badgeTemplateId: 'badge_template_sakai_1000',
    badgeTitle: 'Sakai 1000+ Commits Contributor',
    badgeDescription: 'Awarded for 1000+ commits.',
    badgeImageUri: null,
    recipientIdentity: 'https://github.com/ottenhoff',
    recipientIdentityType: 'url',
    issuedAt: '2026-02-11T16:29:14.571Z',
    revokedAt: null,
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
});

describe('GET /showcase/:tenantId', () => {
  beforeEach(() => {
    mockedListPublicBadgeWallEntries.mockReset();
  });

  it('renders public tenant badge wall entries with badge URLs', async () => {
    const env = createEnv();
    mockedListPublicBadgeWallEntries.mockResolvedValue([
      samplePublicBadgeWallEntry(),
      samplePublicBadgeWallEntry({
        assertionPublicId: '620b51c5-c6f8-4506-8a5c-2daaa2eb6f04',
        recipientIdentity: 'https://github.com/steveswinsburg',
        badgeTitle: 'Sakai Distinguished Contributor',
      }),
    ]);

    const response = await app.request('/showcase/sakai', undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(body).toContain('Badge Wall · sakai');
    expect(body).toContain('2 issued badges');
    expect(body).toContain('/badges/a77ab5e5-bd08-40c3-accd-cf29ed1fdbbf');
    expect(body).toContain('/badges/620b51c5-c6f8-4506-8a5c-2daaa2eb6f04');
    expect(body).toContain('http://localhost/badges/a77ab5e5-bd08-40c3-accd-cf29ed1fdbbf');
    expect(body).toContain('@ottenhoff');
    expect(body).toContain('Sakai 1000+ Commits Contributor');
    expect(body).toContain('Sakai Distinguished Contributor');
    expect(body).toContain('github.com/ottenhoff.png');
    expect(mockedListPublicBadgeWallEntries).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'sakai',
      badgeTemplateId: 'badge_template_sakai_1000',
    });
  });

  it('applies badgeTemplateId filter when provided', async () => {
    const env = createEnv();
    mockedListPublicBadgeWallEntries.mockResolvedValue([]);

    const response = await app.request(
      '/showcase/sakai?badgeTemplateId=badge_template_sakai_1000',
      undefined,
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('badge template &quot;badge_template_sakai_1000&quot;');
    expect(mockedListPublicBadgeWallEntries).toHaveBeenCalledWith(fakeDb, {
      tenantId: 'sakai',
      badgeTemplateId: 'badge_template_sakai_1000',
    });
  });

  it('renders empty state when no badges are present', async () => {
    const env = createEnv();
    mockedListPublicBadgeWallEntries.mockResolvedValue([]);

    const response = await app.request('/showcase/sakai', undefined, env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('0 issued badges');
    expect(body).toContain('No public badges found for this showcase.');
  });
});
