import type { AssertionLifecycleState } from "./assertion-types.js";
import { normalizeReportingDateBoundary } from "./assertion-internal.js";

export interface AssertionRecordFilterSqlInput {
  tenantId: string;
  issuedFrom?: string | undefined;
  issuedTo?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  recipientQuery?: string | undefined;
  state?: AssertionLifecycleState | undefined;
}

export interface AssertionRecordFilterSqlOptions {
  context: "ledger" | "reporting";
  includeLifecycleStatePredicate?: boolean;
}

export interface AssertionRecordFilterSql {
  whereClauses: string[];
  params: unknown[];
}

export const assertionReportingAttributionJoinSql = `
        INNER JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id`;

const assertionBadgeTemplateColumnForContext = (
  context: AssertionRecordFilterSqlOptions["context"],
): "assertions.badge_template_id" | "attribution.badge_template_id" => {
  return context === "reporting" ? "attribution.badge_template_id" : "assertions.badge_template_id";
};

export const buildAssertionRecordFilterSql = (
  input: AssertionRecordFilterSqlInput,
  options: AssertionRecordFilterSqlOptions,
): AssertionRecordFilterSql => {
  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.issuedFrom !== undefined) {
    whereClauses.push("assertions.issued_at >= ?");
    params.push(normalizeReportingDateBoundary(input.issuedFrom, "start"));
  }

  if (input.issuedTo !== undefined) {
    whereClauses.push("assertions.issued_at <= ?");
    params.push(normalizeReportingDateBoundary(input.issuedTo, "end"));
  }

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push(`${assertionBadgeTemplateColumnForContext(options.context)} = ?`);
    params.push(input.badgeTemplateId);
  }

  if (input.orgUnitId !== undefined) {
    whereClauses.push("attribution.org_unit_id = ?");
    params.push(input.orgUnitId);
  }

  if (input.recipientQuery !== undefined) {
    const normalizedQuery = `%${input.recipientQuery.trim().toLowerCase()}%`;
    whereClauses.push(
      `(
        LOWER(assertions.recipient_identity) LIKE ?
        OR LOWER(assertions.id) LIKE ?
        OR LOWER(COALESCE(assertions.public_id, '')) LIKE ?
      )`,
    );
    params.push(normalizedQuery, normalizedQuery, normalizedQuery);
  }

  if (options.includeLifecycleStatePredicate !== false && input.state !== undefined) {
    whereClauses.push(
      `(
        CASE
          WHEN assertions.revoked_at IS NOT NULL THEN 'revoked'
          WHEN lifecycle.to_state IS NOT NULL THEN lifecycle.to_state
          ELSE 'active'
        END
      ) = ?`,
    );
    params.push(input.state);
  }

  return { whereClauses, params };
};
