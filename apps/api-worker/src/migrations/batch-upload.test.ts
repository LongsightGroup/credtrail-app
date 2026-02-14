import { describe, expect, it } from 'vitest';
import { parseMigrationBatchUploadFile } from './batch-upload';

describe('parseMigrationBatchUploadFile', () => {
  it('parses JSON batch uploads with OB2 row payloads', () => {
    const result = parseMigrationBatchUploadFile({
      fileName: 'migration.json',
      mimeType: 'application/json',
      content: JSON.stringify([
        {
          ob2Assertion: {
            type: 'Assertion',
            recipient: {
              type: 'email',
              identity: 'learner@example.edu',
            },
            badge: {
              type: 'BadgeClass',
              name: 'Migration Badge',
            },
          },
        },
      ]),
    });

    expect(result.format).toBe('json');
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]?.candidate.ob2Assertion).toBeDefined();
  });

  it('parses CSV uploads and decodes JSON columns', () => {
    const csv = [
      'ob2Assertion,ob2BadgeClass,ob2Issuer,bakedBadgeImage',
      '"{""type"":""Assertion"",""recipient"":{""type"":""email"",""identity"":""learner@example.edu""},""badge"":""https://issuer.test/badges/1""}","{""type"":""BadgeClass"",""id"":""https://issuer.test/badges/1"",""name"":""CSV Badge""}","{""type"":""Issuer"",""id"":""https://issuer.test/issuers/1""}",',
    ].join('\n');

    const result = parseMigrationBatchUploadFile({
      fileName: 'migration.csv',
      mimeType: 'text/csv',
      content: csv,
    });

    expect(result.format).toBe('csv');
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]?.candidate.ob2Assertion).toBeTypeOf('object');
    expect(result.rows[0]?.candidate.ob2BadgeClass).toBeTypeOf('object');
    expect(result.rows[0]?.candidate.ob2Issuer).toBeTypeOf('object');
  });

  it('rejects CSV files without supported headers', () => {
    expect(() => {
      parseMigrationBatchUploadFile({
        fileName: 'invalid.csv',
        mimeType: 'text/csv',
        content: 'name,value\nfoo,bar',
      });
    }).toThrowError();
  });
});
