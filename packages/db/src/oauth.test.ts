import { describe, expect, it } from 'vitest';

import {
  consumeOAuthAuthorizationCode,
  type SqlDatabase,
  type SqlPreparedStatement,
  type SqlQueryResult,
  type SqlRunResult,
} from './index';

class FakeConsumeStatement implements SqlPreparedStatement {
  private boundParams: unknown[] = [];
  private readonly db: FakeOAuthConsumeDatabase;
  private readonly sql: string;

  constructor(db: FakeOAuthConsumeDatabase, sql: string) {
    this.db = db;
    this.sql = sql;
  }

  bind(...params: unknown[]): SqlPreparedStatement {
    this.boundParams = params;
    return this;
  }

  first<T>(): Promise<T | null> {
    return Promise.resolve(this.db.consumeOnce(this.sql, this.boundParams) as T | null);
  }

  all<T>(): Promise<SqlQueryResult<T>> {
    throw new Error('all() is not implemented in FakeConsumeStatement');
  }

  run(): Promise<SqlRunResult> {
    throw new Error('run() is not implemented in FakeConsumeStatement');
  }
}

class FakeOAuthConsumeDatabase implements SqlDatabase {
  private readonly expectedClientId: string;
  private readonly expectedCodeHash: string;
  private readonly expectedRedirectUri: string;
  private readonly expiresAt: string;
  private consumed = false;
  public readonly observedSql: string[] = [];

  constructor(input: {
    clientId: string;
    codeHash: string;
    redirectUri: string;
    expiresAt: string;
  }) {
    this.expectedClientId = input.clientId;
    this.expectedCodeHash = input.codeHash;
    this.expectedRedirectUri = input.redirectUri;
    this.expiresAt = input.expiresAt;
  }

  prepare(sql: string): SqlPreparedStatement {
    this.observedSql.push(sql.replace(/\s+/g, ' ').trim());
    return new FakeConsumeStatement(this, sql);
  }

  consumeOnce(sql: string, params: unknown[]): Record<string, unknown> | null {
    const normalizedSql = sql.replace(/\s+/g, ' ').trim();

    if (
      !normalizedSql.includes('UPDATE oauth_authorization_codes') ||
      !normalizedSql.includes('RETURNING')
    ) {
      throw new Error('Expected an atomic UPDATE ... RETURNING statement');
    }

    const [usedAt, clientId, codeHash, redirectUri, nowIso] = params;

    if (
      typeof usedAt !== 'string' ||
      typeof clientId !== 'string' ||
      typeof codeHash !== 'string' ||
      typeof redirectUri !== 'string' ||
      typeof nowIso !== 'string'
    ) {
      throw new Error('Invalid bind parameters for OAuth authorization code consumption');
    }

    if (
      clientId !== this.expectedClientId ||
      codeHash !== this.expectedCodeHash ||
      redirectUri !== this.expectedRedirectUri ||
      nowIso !== usedAt ||
      this.expiresAt <= nowIso ||
      this.consumed
    ) {
      return null;
    }

    this.consumed = true;

    return {
      id: 'oac_123',
      clientId: this.expectedClientId,
      userId: 'usr_123',
      tenantId: 'tenant_123',
      codeHash: this.expectedCodeHash,
      redirectUri: this.expectedRedirectUri,
      scope: 'https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly',
      codeChallenge: 'abcdefghijabcdefghijabcdefghijabcdefghijabc',
      codeChallengeMethod: 'S256',
      expiresAt: this.expiresAt,
      usedAt,
      createdAt: '2026-02-11T20:00:00.000Z',
    };
  }
}

describe('consumeOAuthAuthorizationCode', () => {
  it('consumes an authorization code once using a single atomic statement', async () => {
    const input = {
      clientId: 'oc_client_123',
      codeHash: 'code-hash-123',
      redirectUri: 'https://client.example/callback',
      nowIso: '2026-02-11T20:01:00.000Z',
    };
    const db = new FakeOAuthConsumeDatabase({
      clientId: input.clientId,
      codeHash: input.codeHash,
      redirectUri: input.redirectUri,
      expiresAt: '2026-02-11T20:05:00.000Z',
    });

    const firstConsume = await consumeOAuthAuthorizationCode(db, input);
    const secondConsume = await consumeOAuthAuthorizationCode(db, input);

    expect(firstConsume).not.toBeNull();
    expect(firstConsume?.usedAt).toBe(input.nowIso);
    expect(secondConsume).toBeNull();
    expect(db.observedSql.some((sql) => sql.includes('UPDATE oauth_authorization_codes'))).toBe(true);
    expect(db.observedSql.some((sql) => sql.includes('RETURNING'))).toBe(true);
  });
});
