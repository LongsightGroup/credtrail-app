import {
  createAuthIdentityLink,
  findAuthIdentityLinkByAuthUserId,
  findAuthIdentityLinkByCredtrailUserId,
  findUserById,
  type SqlDatabase,
} from "@credtrail/db";
import { betterAuth } from "better-auth";
import {
  createAdapterFactory,
  type CleanedWhere,
  type CustomAdapter,
  type DBAdapterInstance,
  type JoinConfig,
} from "better-auth/adapters";
import { magicLink, twoFactor } from "better-auth/plugins";
import { genericOAuth, type GenericOAuthConfig } from "better-auth/plugins/generic-oauth";
import type { BetterAuthRuntimeConfig } from "./better-auth-config";

const BETTER_AUTH_BASE_PATH = "/api/auth";
const REQUESTED_TENANT_COOKIE_NAME = "credtrail_requested_tenant";
const HOSTED_MAGIC_LINK_TOKEN_PREFIX = "ctml";

type SupportedAuthModel = "user" | "session" | "account" | "verification" | "twoFactor";

const MODEL_TABLES: Record<SupportedAuthModel, string> = {
  user: "auth.user",
  session: "auth.session",
  account: "auth.account",
  verification: "auth.verification",
  twoFactor: "auth.two_factor",
};

const quoteIdentifier = (identifier: string): string => {
  const parts = identifier.split(".");

  for (const part of parts) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(part)) {
      throw new Error(`Unsupported SQL identifier: ${identifier}`);
    }
  }

  return parts.map((part) => `"${part}"`).join(".");
};

const tableNameForModel = (model: string): string => {
  if (model in MODEL_TABLES) {
    return quoteIdentifier(MODEL_TABLES[model as SupportedAuthModel]);
  }

  throw new Error(`Unsupported Better Auth model: ${model}`);
};

const toSnakeCase = (value: string): string => {
  return value.replace(/[A-Z]/g, (character) => `_${character.toLowerCase()}`);
};

const toCamelCase = (value: string): string => {
  return value.replace(/_([a-z])/g, (_match, character: string) => character.toUpperCase());
};

const columnName = (_model: string, field: string): string => {
  return quoteIdentifier(toSnakeCase(field));
};

const normalizeRowKeys = <RowType extends Record<string, unknown>>(row: RowType): RowType => {
  const normalized = Object.create(null) as RowType;

  for (const [key, value] of Object.entries(row)) {
    normalized[toCamelCase(key) as keyof RowType] = value as RowType[keyof RowType];
  }

  return normalized;
};

const normalizeValue = (value: unknown): unknown => {
  if (value instanceof Date) {
    return value.toISOString();
  }

  return value;
};

const filterSelectedFields = <RowType extends Record<string, unknown>>(
  row: RowType,
  select?: string[],
): RowType => {
  if (select === undefined || select.length === 0) {
    return row;
  }

  const filtered = Object.create(null) as RowType;

  for (const key of select) {
    if (key in row) {
      filtered[key as keyof RowType] = row[key as keyof RowType];
    }
  }

  return filtered;
};

const whereClauseToSql = (
  model: string,
  where: CleanedWhere[] | undefined,
): {
  sql: string;
  params: unknown[];
} => {
  if (where === undefined || where.length === 0) {
    return {
      sql: "",
      params: [],
    };
  }

  const fragments: string[] = [];
  const params: unknown[] = [];

  for (const clause of where) {
    const connector = fragments.length === 0 ? "" : clause.connector === "OR" ? " OR " : " AND ";
    const field = columnName(model, clause.field);

    switch (clause.operator) {
      case "in":
      case "not_in": {
        const values = Array.isArray(clause.value) ? clause.value : [clause.value];

        if (values.length === 0) {
          fragments.push(`${connector}${clause.operator === "in" ? "FALSE" : "TRUE"}`);
          continue;
        }

        const placeholders = values.map(() => "?").join(", ");
        fragments.push(
          `${connector}${field} ${clause.operator === "in" ? "IN" : "NOT IN"} (${placeholders})`,
        );
        params.push(...values.map(normalizeValue));
        continue;
      }
      case "contains":
        fragments.push(`${connector}${field} LIKE ?`);
        params.push(`%${String(clause.value)}%`);
        continue;
      case "starts_with":
        fragments.push(`${connector}${field} LIKE ?`);
        params.push(`${String(clause.value)}%`);
        continue;
      case "ends_with":
        fragments.push(`${connector}${field} LIKE ?`);
        params.push(`%${String(clause.value)}`);
        continue;
      case "ne":
        if (clause.value === null) {
          fragments.push(`${connector}${field} IS NOT NULL`);
        } else {
          fragments.push(`${connector}${field} <> ?`);
          params.push(normalizeValue(clause.value));
        }
        continue;
      case "lt":
      case "lte":
      case "gt":
      case "gte": {
        const operator =
          clause.operator === "lt"
            ? "<"
            : clause.operator === "lte"
              ? "<="
              : clause.operator === "gt"
                ? ">"
                : ">=";
        fragments.push(`${connector}${field} ${operator} ?`);
        params.push(normalizeValue(clause.value));
        continue;
      }
      case "eq":
      default:
        if (clause.value === null) {
          fragments.push(`${connector}${field} IS NULL`);
        } else {
          fragments.push(`${connector}${field} = ?`);
          params.push(normalizeValue(clause.value));
        }
        continue;
    }
  }

  return {
    sql: ` WHERE ${fragments.join("")}`,
    params,
  };
};

const listRows = async (
  db: SqlDatabase,
  input: {
    model: string;
    where?: CleanedWhere[] | undefined;
    select?: string[] | undefined;
    sortBy?:
      | {
          field: string;
          direction: "asc" | "desc";
        }
      | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
  },
): Promise<Record<string, unknown>[]> => {
  const selectSql =
    input.select !== undefined && input.select.length > 0
      ? input.select
          .map((field) => `${columnName(input.model, field)} AS ${quoteIdentifier(field)}`)
          .join(", ")
      : "*";
  const whereClause = whereClauseToSql(input.model, input.where);
  const orderBySql =
    input.sortBy === undefined
      ? ""
      : ` ORDER BY ${columnName(input.model, input.sortBy.field)} ${input.sortBy.direction.toUpperCase()}`;
  const limitSql = input.limit === undefined ? "" : " LIMIT ?";
  const offsetSql = input.offset === undefined ? "" : " OFFSET ?";
  const params = [...whereClause.params];

  if (input.limit !== undefined) {
    params.push(input.limit);
  }

  if (input.offset !== undefined) {
    params.push(input.offset);
  }

  const result = await db
    .prepare(
      `SELECT ${selectSql} FROM ${tableNameForModel(input.model)}${whereClause.sql}${orderBySql}${limitSql}${offsetSql}`,
    )
    .bind(...params)
    .all<Record<string, unknown>>();

  return result.results.map((row) => normalizeRowKeys(row));
};

const attachJoinedRows = async (
  db: SqlDatabase,
  rows: Record<string, unknown>[],
  join: JoinConfig,
): Promise<Record<string, unknown>[]> => {
  if (rows.length === 0) {
    return rows;
  }

  const outputRows = rows.map((row) => ({ ...row }));

  for (const [joinModel, joinConfig] of Object.entries(join)) {
    const baseValues = outputRows
      .map((row) => row[joinConfig.on.from])
      .filter((value): value is string | number => value !== undefined && value !== null);

    if (baseValues.length === 0) {
      for (const row of outputRows) {
        row[joinModel] = joinConfig.relation === "one-to-one" ? null : [];
      }
      continue;
    }

    const joinValues = [...new Set(baseValues)] as string[] | number[];
    const joinedRows = await listRows(db, {
      model: joinModel,
      where: [
        {
          field: joinConfig.on.to,
          operator: "in",
          value: joinValues,
          connector: "AND",
          mode: "sensitive",
        },
      ],
      limit:
        joinConfig.relation === "one-to-one"
          ? undefined
          : (joinConfig.limit ?? 100) * Math.max(baseValues.length, 1),
    });

    for (const row of outputRows) {
      const relatedRows = joinedRows.filter(
        (joinedRow) => joinedRow[joinConfig.on.to] === row[joinConfig.on.from],
      );

      row[joinModel] =
        joinConfig.relation === "one-to-one"
          ? (relatedRows[0] ?? null)
          : relatedRows.slice(0, joinConfig.limit ?? 100);
    }
  }

  return outputRows;
};

const createBetterAuthCustomAdapter = (db: SqlDatabase): CustomAdapter => {
  return {
    create: async ({ model, data, select }) => {
      const dataRecord = data as Record<string, unknown>;
      const keys = Object.keys(dataRecord);
      const values = keys.map((key) => dataRecord[key]);
      const columnsSql = keys.map((key) => columnName(model, key)).join(", ");
      const placeholders = keys.map(() => "?").join(", ");

      await db
        .prepare(`INSERT INTO ${tableNameForModel(model)} (${columnsSql}) VALUES (${placeholders})`)
        .bind(...values.map(normalizeValue))
        .run();

      return filterSelectedFields(
        {
          ...dataRecord,
        },
        select,
      ) as never;
    },
    update: async ({ model, where, update }) => {
      const updateRecord = update as Record<string, unknown>;
      const keys = Object.keys(updateRecord);

      if (keys.length === 0) {
        const rows = await listRows(db, {
          model,
          where,
          limit: 1,
        });

        return (rows[0] ?? null) as never;
      }

      const assignments = keys.map((key) => `${columnName(model, key)} = ?`).join(", ");
      const whereClause = whereClauseToSql(model, where);
      const params = [
        ...keys.map((key) => normalizeValue(updateRecord[key])),
        ...whereClause.params,
      ];

      await db
        .prepare(`UPDATE ${tableNameForModel(model)} SET ${assignments}${whereClause.sql}`)
        .bind(...params)
        .run();

      const rows = await listRows(db, {
        model,
        where,
        limit: 1,
      });

      return (rows[0] ?? null) as never;
    },
    updateMany: async ({ model, where, update }) => {
      const matchingRows = await listRows(db, {
        model,
        where,
      });
      const updateRecord = update as Record<string, unknown>;
      const keys = Object.keys(updateRecord);

      if (matchingRows.length === 0 || keys.length === 0) {
        return matchingRows.length;
      }

      const assignments = keys.map((key) => `${columnName(model, key)} = ?`).join(", ");
      const whereClause = whereClauseToSql(model, where);
      const params = [
        ...keys.map((key) => normalizeValue(updateRecord[key])),
        ...whereClause.params,
      ];

      await db
        .prepare(`UPDATE ${tableNameForModel(model)} SET ${assignments}${whereClause.sql}`)
        .bind(...params)
        .run();

      return matchingRows.length;
    },
    findOne: async ({ model, where, select, join }) => {
      const rows = await listRows(db, {
        model,
        where,
        select,
        limit: 1,
      });

      if (rows.length === 0) {
        return null;
      }

      if (join === undefined) {
        return rows[0] as never;
      }

      const joinedRows = await attachJoinedRows(db, rows, join);
      return (joinedRows[0] ?? null) as never;
    },
    findMany: async ({ model, where, limit, select, sortBy, offset, join }) => {
      const rows = await listRows(db, {
        model,
        where,
        select,
        sortBy,
        limit,
        offset,
      });

      if (join === undefined) {
        return rows as never;
      }

      return (await attachJoinedRows(db, rows, join)) as never;
    },
    delete: async ({ model, where }) => {
      const whereClause = whereClauseToSql(model, where);
      await db
        .prepare(`DELETE FROM ${tableNameForModel(model)}${whereClause.sql}`)
        .bind(...whereClause.params)
        .run();
    },
    deleteMany: async ({ model, where }) => {
      const matchingRows = await listRows(db, {
        model,
        where,
      });
      const whereClause = whereClauseToSql(model, where);

      await db
        .prepare(`DELETE FROM ${tableNameForModel(model)}${whereClause.sql}`)
        .bind(...whereClause.params)
        .run();

      return matchingRows.length;
    },
    count: async ({ model, where }) => {
      const whereClause = whereClauseToSql(model, where);
      const row = await db
        .prepare(`SELECT COUNT(*) AS count FROM ${tableNameForModel(model)}${whereClause.sql}`)
        .bind(...whereClause.params)
        .first<{ count: number | string }>();

      if (row === null) {
        return 0;
      }

      return Number(row.count);
    },
  };
};

export const createBetterAuthDatabaseAdapter = (db: SqlDatabase): DBAdapterInstance => {
  return createAdapterFactory({
    config: {
      adapterId: "credtrail-sql",
      adapterName: "CredTrail SQL Better Auth Adapter",
      usePlural: false,
      supportsBooleans: true,
      supportsDates: false,
      supportsJSON: false,
      supportsArrays: false,
      transaction: false,
    },
    adapter: () => createBetterAuthCustomAdapter(db),
  });
};

const encodeBase64Url = (value: string): string => {
  const bytes = new TextEncoder().encode(value);
  let raw = "";

  for (const byte of bytes) {
    raw += String.fromCharCode(byte);
  }

  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const decodeBase64Url = (value: string): string => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = `${normalized}${"=".repeat((4 - (normalized.length % 4)) % 4)}`;
  const raw = atob(padded);
  const bytes = Uint8Array.from(raw, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
};

export const buildHostedMagicLinkToken = (tenantId: string): string => {
  const payload = encodeBase64Url(
    JSON.stringify({
      tenantId,
    }),
  );
  const nonce = crypto.randomUUID().replace(/-/g, "");

  return `${HOSTED_MAGIC_LINK_TOKEN_PREFIX}.${payload}.${nonce}`;
};

export const parseHostedMagicLinkToken = (
  token: string,
): {
  tenantId: string;
} | null => {
  const [prefix, payload] = token.split(".");

  if (prefix !== HOSTED_MAGIC_LINK_TOKEN_PREFIX || payload === undefined) {
    return null;
  }

  try {
    const parsed = JSON.parse(decodeBase64Url(payload)) as {
      tenantId?: unknown;
    };

    if (typeof parsed.tenantId !== "string" || parsed.tenantId.trim().length === 0) {
      return null;
    }

    return {
      tenantId: parsed.tenantId,
    };
  } catch {
    return null;
  }
};

export const tenantIdFromNextPath = (nextPath: string | undefined): string | null => {
  if (!nextPath?.startsWith("/")) {
    return null;
  }

  const match = /^\/tenants\/([^/]+)\//.exec(nextPath);

  return match?.[1] ?? null;
};

export const buildHostedMagicLinkUrl = (input: {
  baseURL: string;
  token: string;
  nextPath: string;
}): string => {
  const url = new URL("/auth/magic-link/verify", input.baseURL);
  url.searchParams.set("token", input.token);
  url.searchParams.set("next", input.nextPath);
  return url.toString();
};

export interface BetterAuthDatabaseSessionRecord {
  sessionId: string;
  sessionToken: string;
  userId: string;
  expiresAt: string;
  userEmail: string | null;
  userEmailVerified: boolean;
}

interface BetterAuthDatabaseUserRecord {
  id: string;
  email: string | null;
  emailVerified: boolean;
}

const normalizedEmail = (email: string | null): string | null => {
  const trimmed = email?.trim();

  if (trimmed === undefined || trimmed.length === 0) {
    return null;
  }

  return trimmed.toLowerCase();
};

const findBetterAuthUserByEmail = async (
  db: SqlDatabase,
  email: string,
): Promise<BetterAuthDatabaseUserRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        email,
        email_verified AS emailVerified
      FROM auth.user
      WHERE LOWER(email) = LOWER(?)
      LIMIT 1
    `,
    )
    .bind(email)
    .first<BetterAuthDatabaseUserRecord>();

  return row;
};

const createBetterAuthUser = async (input: {
  db: SqlDatabase;
  email: string | null;
}): Promise<BetterAuthDatabaseUserRecord> => {
  const userId = `ba_usr_${crypto.randomUUID().replace(/-/g, "")}`;
  const email = normalizedEmail(input.email);

  await input.db
    .prepare(
      `
      INSERT INTO auth.user (
        id,
        email,
        email_verified,
        name,
        image
      )
      VALUES (?, ?, ?, NULL, NULL)
    `,
    )
    .bind(userId, email, false)
    .run();

  return {
    id: userId,
    email,
    emailVerified: false,
  };
};

const resolveBetterAuthUser = async (input: {
  db: SqlDatabase;
  runtimeConfig: BetterAuthRuntimeConfig;
  credtrailUserId: string;
}): Promise<{
  authUserId: string;
}> => {
  const existingLink = await findAuthIdentityLinkByCredtrailUserId(
    input.db,
    input.runtimeConfig.authSystem,
    input.credtrailUserId,
  );

  if (existingLink !== null) {
    return {
      authUserId: existingLink.authUserId,
    };
  }

  const credtrailUser = await findUserById(input.db, input.credtrailUserId);

  if (credtrailUser === null) {
    throw new Error("CredTrail user not found for Better Auth session creation");
  }

  const matchedAuthUser =
    credtrailUser.email.length === 0
      ? null
      : await findBetterAuthUserByEmail(input.db, credtrailUser.email);
  const linkedMatchedUser =
    matchedAuthUser === null
      ? null
      : await findAuthIdentityLinkByAuthUserId(
          input.db,
          input.runtimeConfig.authSystem,
          matchedAuthUser.id,
        );
  const betterAuthUser =
    matchedAuthUser !== null &&
    (linkedMatchedUser === null || linkedMatchedUser.credtrailUserId === input.credtrailUserId)
      ? matchedAuthUser
      : await createBetterAuthUser({
          db: input.db,
          email: credtrailUser.email,
        });

  await createAuthIdentityLink(input.db, {
    authSystem: input.runtimeConfig.authSystem,
    authUserId: betterAuthUser.id,
    credtrailUserId: input.credtrailUserId,
    emailSnapshot: credtrailUser.email,
  });

  return {
    authUserId: betterAuthUser.id,
  };
};

export const findBetterAuthSessionByToken = async (
  db: SqlDatabase,
  sessionToken: string,
): Promise<BetterAuthDatabaseSessionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        session.id AS sessionId,
        session.token AS sessionToken,
        session.user_id AS userId,
        session.expires_at AS expiresAt,
        auth_user.email AS userEmail,
        auth_user.email_verified AS userEmailVerified
      FROM auth.session AS session
      INNER JOIN auth.user AS auth_user
        ON auth_user.id = session.user_id
      WHERE session.token = ?
      LIMIT 1
    `,
    )
    .bind(sessionToken)
    .first<BetterAuthDatabaseSessionRecord>();

  return row;
};

export const createBetterAuthSessionForCredtrailUser = async (input: {
  db: SqlDatabase;
  runtimeConfig: BetterAuthRuntimeConfig;
  credtrailUserId: string;
  ipAddress?: string | null;
  userAgent?: string | null;
}): Promise<{
  sessionToken: string;
  session: BetterAuthDatabaseSessionRecord;
}> => {
  const resolvedUser = await resolveBetterAuthUser({
    db: input.db,
    runtimeConfig: input.runtimeConfig,
    credtrailUserId: input.credtrailUserId,
  });
  const sessionId = `ba_ses_${crypto.randomUUID().replace(/-/g, "")}`;
  const sessionToken = crypto.randomUUID().replace(/-/g, "");
  const expiresAt = new Date(
    Date.now() + input.runtimeConfig.session.expiresInSeconds * 1000,
  ).toISOString();

  await input.db
    .prepare(
      `
      INSERT INTO auth.session (
        id,
        token,
        user_id,
        expires_at,
        ip_address,
        user_agent
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      sessionId,
      sessionToken,
      resolvedUser.authUserId,
      expiresAt,
      input.ipAddress ?? null,
      input.userAgent ?? null,
    )
    .run();

  const session = await findBetterAuthSessionByToken(input.db, sessionToken);

  if (session === null) {
    throw new Error("Better Auth session creation succeeded but the session could not be loaded");
  }

  return {
    sessionToken,
    session,
  };
};

export const createCredtrailBetterAuth = (input: {
  db: SqlDatabase;
  runtimeConfig: BetterAuthRuntimeConfig;
  magicLinkTtlSeconds: number;
  generateMagicLinkToken?: (() => string) | undefined;
  oauthProviders?: readonly GenericOAuthConfig[] | undefined;
  sendMagicLink: (data: { email: string; token: string; url: string }) => Promise<void>;
  sendResetPassword?: (data: { email: string; url: string; token: string }) => Promise<void>;
}) => {
  const plugins: (
    | ReturnType<typeof magicLink>
    | ReturnType<typeof genericOAuth>
    | ReturnType<typeof twoFactor>
  )[] = [
    magicLink({
      expiresIn: input.magicLinkTtlSeconds,
      generateToken: () => {
        return input.generateMagicLinkToken?.() ?? crypto.randomUUID().replace(/-/g, "");
      },
      sendMagicLink: async ({ email, token, url }) => {
        await input.sendMagicLink({
          email,
          token,
          url,
        });
      },
    }),
    twoFactor(),
  ];

  if (input.oauthProviders !== undefined && input.oauthProviders.length > 0) {
    plugins.push(
      genericOAuth({
        config: [...input.oauthProviders],
      }),
    );
  }

  return betterAuth({
    baseURL: input.runtimeConfig.baseURL,
    basePath: BETTER_AUTH_BASE_PATH,
    ...(input.runtimeConfig.secret === null ? {} : { secret: input.runtimeConfig.secret }),
    trustedOrigins: input.runtimeConfig.trustedOrigins,
    emailAndPassword: {
      enabled: true,
      sendResetPassword: async ({ user, url, token }) => {
        await input.sendResetPassword?.({
          email: user.email,
          url,
          token,
        });
      },
      revokeSessionsOnPasswordReset: true,
    },
    database: createBetterAuthDatabaseAdapter(input.db),
    session: {
      expiresIn: input.runtimeConfig.session.expiresInSeconds,
      disableSessionRefresh: input.runtimeConfig.session.disableRefresh,
      cookieCache: {
        enabled: false,
      },
    },
    cookies: {
      session_token: {
        name: input.runtimeConfig.session.cookieName,
        attributes: {
          path: "/",
          sameSite: "lax",
          httpOnly: true,
          secure: input.runtimeConfig.baseURL.startsWith("https://"),
        },
      },
    },
    plugins,
  });
};

export { BETTER_AUTH_BASE_PATH, REQUESTED_TENANT_COOKIE_NAME };
