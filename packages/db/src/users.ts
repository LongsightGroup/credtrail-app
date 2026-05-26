import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase } from "./tenant-scope";

export interface UserRecord {
  id: string;
  email: string;
}

export interface AuthIdentityLinkRecord {
  id: string;
  authSystem: string;
  authUserId: string;
  authAccountId: string | null;
  credtrailUserId: string;
  emailSnapshot: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateAuthIdentityLinkInput {
  authSystem: string;
  authUserId: string;
  authAccountId?: string | null | undefined;
  credtrailUserId: string;
  emailSnapshot?: string | null | undefined;
}
export const normalizeEmail = (email: string): string => {
  return email.trim().toLowerCase();
};

export const upsertUserByEmail = async (db: SqlDatabase, email: string): Promise<UserRecord> => {
  const normalizedEmail = normalizeEmail(email);
  const createdUserId = createPrefixedId("usr");

  await db
    .prepare(
      `
      INSERT INTO users (id, email)
      VALUES (?, ?)
      ON CONFLICT DO NOTHING
    `,
    )
    .bind(createdUserId, normalizedEmail)
    .run();

  const user = await db
    .prepare(
      `
      SELECT id, email
      FROM users
      WHERE email = ?
      LIMIT 1
    `,
    )
    .bind(normalizedEmail)
    .first<UserRecord>();

  if (user === null) {
    throw new Error(`Unable to upsert user for email "${normalizedEmail}"`);
  }

  return user;
};

export const findUserByEmail = async (
  db: SqlDatabase,
  email: string,
): Promise<UserRecord | null> => {
  const normalizedEmail = normalizeEmail(email);
  const user = await db
    .prepare(
      `
      SELECT id, email
      FROM users
      WHERE email = ?
      LIMIT 1
    `,
    )
    .bind(normalizedEmail)
    .first<UserRecord>();

  return user;
};

export const findUserById = async (db: SqlDatabase, userId: string): Promise<UserRecord | null> => {
  const user = await db
    .prepare(
      `
      SELECT id, email
      FROM users
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(userId)
    .first<UserRecord>();

  return user;
};

export const findUsersByIds = async (
  db: SqlDatabase,
  userIds: readonly string[],
): Promise<Map<string, UserRecord>> => {
  const uniqueUserIds = [
    ...new Set(
      userIds.filter((userId): userId is string => {
        return userId.length > 0;
      }),
    ),
  ];

  if (uniqueUserIds.length === 0) {
    return new Map();
  }

  const placeholders = uniqueUserIds.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `
      SELECT id, email
      FROM users
      WHERE id IN (${placeholders})
    `,
    )
    .bind(...uniqueUserIds)
    .all<UserRecord>();

  const usersById = new Map<string, UserRecord>();

  for (const user of result.results ?? []) {
    usersById.set(user.id, user);
  }

  return usersById;
};

export const createAuthIdentityLink = async (
  db: SqlDatabase,
  input: CreateAuthIdentityLinkInput,
): Promise<AuthIdentityLinkRecord> => {
  const id = createPrefixedId("ail");
  const createdAt = new Date().toISOString();
  const emailSnapshot =
    input.emailSnapshot === undefined || input.emailSnapshot === null
      ? null
      : normalizeEmail(input.emailSnapshot);

  await db
    .prepare(
      `
      INSERT INTO auth_identity_links (
        id,
        auth_system,
        auth_user_id,
        auth_account_id,
        credtrail_user_id,
        email_snapshot,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.authSystem,
      input.authUserId,
      input.authAccountId ?? null,
      input.credtrailUserId,
      emailSnapshot,
      createdAt,
      createdAt,
    )
    .run();

  return {
    id,
    authSystem: input.authSystem,
    authUserId: input.authUserId,
    authAccountId: input.authAccountId ?? null,
    credtrailUserId: input.credtrailUserId,
    emailSnapshot,
    createdAt,
    updatedAt: createdAt,
  };
};

export const findAuthIdentityLinkByAuthUserId = async (
  db: SqlDatabase,
  authSystem: string,
  authUserId: string,
): Promise<AuthIdentityLinkRecord | null> => {
  const link = await db
    .prepare(
      `
      SELECT
        id,
        auth_system AS authSystem,
        auth_user_id AS authUserId,
        auth_account_id AS authAccountId,
        credtrail_user_id AS credtrailUserId,
        email_snapshot AS emailSnapshot,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM auth_identity_links
      WHERE auth_system = ?
        AND auth_user_id = ?
      LIMIT 1
    `,
    )
    .bind(authSystem, authUserId)
    .first<AuthIdentityLinkRecord>();

  return link;
};

export const findAuthIdentityLinkByCredtrailUserId = async (
  db: SqlDatabase,
  authSystem: string,
  credtrailUserId: string,
): Promise<AuthIdentityLinkRecord | null> => {
  const link = await db
    .prepare(
      `
      SELECT
        id,
        auth_system AS authSystem,
        auth_user_id AS authUserId,
        auth_account_id AS authAccountId,
        credtrail_user_id AS credtrailUserId,
        email_snapshot AS emailSnapshot,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM auth_identity_links
      WHERE auth_system = ?
        AND credtrail_user_id = ?
      LIMIT 1
    `,
    )
    .bind(authSystem, credtrailUserId)
    .first<AuthIdentityLinkRecord>();

  return link;
};
