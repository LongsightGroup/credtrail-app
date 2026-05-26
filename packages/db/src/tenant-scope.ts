export interface TenantQueryContext {
  tenantId: string;
}

export interface TenantScopedQuery {
  sql: string;
  params: readonly string[];
}

export const withTenantScope = (sql: string, context: TenantQueryContext): TenantScopedQuery => {
  return {
    sql: `${sql} WHERE tenant_id = ?`,
    params: [context.tenantId],
  };
};

export interface SqlExecutionMeta {
  rowsRead?: number | undefined;
  rowsWritten?: number | undefined;
  durationMs?: number | undefined;
}

export interface SqlRunResult {
  success: boolean;
  meta: SqlExecutionMeta;
}

export interface SqlQueryResult<T> extends SqlRunResult {
  results: T[];
}

export interface SqlPreparedStatement {
  bind(...params: unknown[]): SqlPreparedStatement;
  first<T>(): Promise<T | null>;
  all<T>(): Promise<SqlQueryResult<T>>;
  run(): Promise<SqlRunResult>;
}

export interface SqlDatabase {
  prepare(sql: string): SqlPreparedStatement;
}
