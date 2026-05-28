import type { SqlDatabase, SqlPreparedStatement, SqlQueryResult, SqlRunResult } from "./index";

type PostgresConnectionMode = "pool" | "single-use";

interface QueryExecutor {
  query(sql: string, params: readonly unknown[]): Promise<readonly unknown[]>;
}

type PgPoolLike = import("pg").Pool;
type PgClientLike = import("pg").Client;

const UNQUOTED_ALIAS_PATTERN = /\bAS\s+([A-Za-z_][A-Za-z0-9_]*)/gi;

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return value !== null && typeof value === "object" && !Array.isArray(value);
};

const collectAliasMap = (sql: string): Map<string, string> => {
  const aliasMap = new Map<string, string>();
  UNQUOTED_ALIAS_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null = UNQUOTED_ALIAS_PATTERN.exec(sql);

  while (match !== null) {
    const alias = match[1];

    if (alias !== undefined) {
      const foldedAlias = alias.toLowerCase();

      if (foldedAlias !== alias) {
        aliasMap.set(foldedAlias, alias);
      }
    }

    match = UNQUOTED_ALIAS_PATTERN.exec(sql);
  }

  return aliasMap;
};

const remapRowAliases = (
  row: Record<string, unknown>,
  aliasMap: ReadonlyMap<string, string>,
): Record<string, unknown> => {
  const remappedRow: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(row)) {
    const normalizedKey = aliasMap.get(key) ?? key;
    remappedRow[normalizedKey] = value;
  }

  return remappedRow;
};

const normalizeSqlForPostgres = (sql: string): string => {
  let normalizedSql = sql.trim();

  let placeholderIndex = 0;
  normalizedSql = normalizedSql.replace(/\?/g, () => {
    placeholderIndex += 1;
    return `$${String(placeholderIndex)}`;
  });

  return normalizedSql;
};

const loadPgPool = async (databaseUrl: string): Promise<PgPoolLike> => {
  return import("pg").then((pgModule: typeof import("pg")) => {
    return new pgModule.Pool({
      connectionString: databaseUrl,
    });
  });
};

const createPgQueryExecutor = (databaseUrl: string): QueryExecutor => {
  const poolPromise = loadPgPool(databaseUrl);

  return {
    async query(sql, params) {
      const pool = await poolPromise;
      const result = await pool.query(sql, [...params]);
      return result.rows as readonly unknown[];
    },
  };
};

const createSingleUsePgQueryExecutor = (databaseUrl: string): QueryExecutor => {
  return {
    async query(sql, params) {
      const pgModule = await import("pg");
      const client: PgClientLike = new pgModule.Client({
        connectionString: databaseUrl,
      });

      try {
        await client.connect();
        const result = await client.query(sql, [...params]);
        return result.rows as readonly unknown[];
      } finally {
        await client.end();
      }
    },
  };
};

class PostgresPreparedStatement implements SqlPreparedStatement {
  private readonly queryExecutor: QueryExecutor;
  private readonly sql: string;
  private readonly aliasMap: Map<string, string>;
  private params: readonly unknown[] = [];

  constructor(queryExecutor: QueryExecutor, sql: string) {
    this.queryExecutor = queryExecutor;
    this.sql = sql;
    this.aliasMap = collectAliasMap(sql);
  }

  bind(...params: unknown[]): SqlPreparedStatement {
    this.params = params;
    return this;
  }

  async first<T>(): Promise<T | null> {
    const rows = await this.executeQuery<T>();
    return rows[0] ?? null;
  }

  async all<T>(): Promise<SqlQueryResult<T>> {
    const startedAt = Date.now();
    const rows = await this.executeQuery<T>();

    return {
      success: true,
      meta: {
        rowsRead: rows.length,
        durationMs: Date.now() - startedAt,
      },
      results: rows,
    };
  }

  async run(): Promise<SqlRunResult> {
    const startedAt = Date.now();
    const rows = await this.executeQuery<Record<string, unknown>>();

    return {
      success: true,
      meta: {
        rowsWritten: rows.length,
        durationMs: Date.now() - startedAt,
      },
    };
  }

  private async executeQuery<T>(): Promise<T[]> {
    const sql = normalizeSqlForPostgres(this.sql);
    const rows = await this.queryExecutor.query(sql, this.params);

    if (this.aliasMap.size === 0) {
      return rows as T[];
    }

    return rows.map((row) => {
      if (!isRecord(row)) {
        return row;
      }

      return remapRowAliases(row, this.aliasMap);
    }) as T[];
  }
}

class PostgresDatabase implements SqlDatabase {
  private readonly queryExecutor: QueryExecutor;

  constructor(queryExecutor: QueryExecutor) {
    this.queryExecutor = queryExecutor;
  }

  prepare(sql: string): SqlPreparedStatement {
    return new PostgresPreparedStatement(this.queryExecutor, sql);
  }
}

export interface CreatePostgresDatabaseOptions {
  databaseUrl: string;
  connectionMode?: PostgresConnectionMode;
}

export const createPostgresDatabase = (options: CreatePostgresDatabaseOptions): SqlDatabase => {
  const trimmedUrl = options.databaseUrl.trim();

  if (trimmedUrl.length === 0) {
    throw new Error("databaseUrl is required");
  }

  const queryExecutor =
    options.connectionMode === "single-use"
      ? createSingleUsePgQueryExecutor(trimmedUrl)
      : createPgQueryExecutor(trimmedUrl);

  return new PostgresDatabase(queryExecutor);
};
