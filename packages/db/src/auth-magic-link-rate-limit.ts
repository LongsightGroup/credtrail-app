import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase } from "./tenant-scope";

export type AuthMagicLinkRateLimitDimension = "ip" | "tenant" | "email" | "tenant_email";

export interface RecordAuthMagicLinkRateLimitAttemptInput {
  dimensionType: AuthMagicLinkRateLimitDimension;
  dimensionHash: string;
  occurredAt: string;
}

export interface CountAuthMagicLinkRateLimitAttemptsInput {
  dimensionType: AuthMagicLinkRateLimitDimension;
  dimensionHash: string;
  sinceIso: string;
}

export const recordAuthMagicLinkRateLimitAttempt = async (
  db: SqlDatabase,
  input: RecordAuthMagicLinkRateLimitAttemptInput,
): Promise<void> => {
  await db
    .prepare(
      `
      INSERT INTO auth_magic_link_rate_limit_attempts (
        id,
        dimension_type,
        dimension_hash,
        occurred_at
      )
      VALUES (?, ?, ?, ?)
    `,
    )
    .bind(createPrefixedId("amlrl"), input.dimensionType, input.dimensionHash, input.occurredAt)
    .run();
};

export const countAuthMagicLinkRateLimitAttempts = async (
  db: SqlDatabase,
  input: CountAuthMagicLinkRateLimitAttemptsInput,
): Promise<number> => {
  const row = await db
    .prepare(
      `
      SELECT COUNT(*) AS count
      FROM auth_magic_link_rate_limit_attempts
      WHERE dimension_type = ?
        AND dimension_hash = ?
        AND occurred_at >= ?
    `,
    )
    .bind(input.dimensionType, input.dimensionHash, input.sinceIso)
    .first<{ count: number | string }>();

  if (row === null) {
    return 0;
  }

  const count = typeof row.count === "number" ? row.count : Number.parseInt(row.count, 10);
  return Number.isFinite(count) ? count : 0;
};

export const pruneAuthMagicLinkRateLimitAttempts = async (
  db: SqlDatabase,
  beforeIso: string,
): Promise<void> => {
  await db
    .prepare(
      `
      DELETE FROM auth_magic_link_rate_limit_attempts
      WHERE occurred_at < ?
    `,
    )
    .bind(beforeIso)
    .run();
};
