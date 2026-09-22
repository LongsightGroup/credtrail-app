import { z } from "zod";
import { badgeRuleRegistryScopeSql } from "./badge-issuance-rule-registry";
import {
  badgeIssuanceRuleVersionSelectColumns,
  mapBadgeIssuanceRuleVersionRow,
  type BadgeIssuanceRuleVersionRow,
} from "./badge-issuance-rule-version-sql";
import {
  tenantMembershipRoleSatisfiesMinimumRole,
  type TenantMembershipRole,
} from "./tenant-memberships";
import type {
  BadgeIssuanceRuleVersionRecord,
  ListBadgeIssuanceRulesInput,
} from "./badge-issuance-rule-types";
import type { SqlDatabase } from "./tenant-scope";

const taskSchema = z.enum([
  "revise",
  "configure_approval",
  "review",
  "activate",
  "schedule",
  "placement",
  "resume",
  "submit",
]);
/** A bounded Home task identifies the exact version requiring action. */
export interface BadgeWorkflowTask {
  readonly action: z.infer<typeof taskSchema>;
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly current: boolean;
}
/** Counts cover the full authorized scope, independently of the five task rows. */
export interface BadgeWorkflowHomeSummary {
  readonly ruleCount: number;
  readonly activeRuleCount: number;
  readonly actionCount: number;
  readonly waitingCount: number;
  readonly tasks: readonly BadgeWorkflowTask[];
}

const roles: readonly TenantMembershipRole[] = ["owner", "admin", "issuer", "approver", "viewer"];
// Only closed role literals are interpolated; capability meaning comes from the authorization helper.
const reviewerRoleSql = roles
  .map(
    (minimum) =>
      `(COALESCE(step.required_role, 'viewer') = '${minimum}' AND member.role IN (${roles
        .filter((role) => tenantMembershipRoleSatisfiesMinimumRole(role, minimum))
        .map((role) => `'${role}'`)
        .join(", ")}))`,
  )
  .join(" OR ");
const eligibleReviewerSql = `
  SELECT member.user_id FROM memberships AS member
  WHERE member.tenant_id = versions.tenant_id
    AND member.user_id IS DISTINCT FROM versions.created_by_user_id
    AND member.user_id IS DISTINCT FROM versions.submitted_by_user_id
    AND (
      (step.target_type = 'user' AND member.user_id = step.target_user_id)
      OR (step.target_type = 'role_threshold' AND (${reviewerRoleSql}))
      OR (step.target_type = 'approver_group' AND (${reviewerRoleSql}) AND EXISTS (
        SELECT 1 FROM badge_rule_approver_group_members AS gm
        WHERE gm.tenant_id = member.tenant_id AND gm.group_id = step.target_approver_group_id
          AND gm.user_id = member.user_id
      ))
    )
`;

/** Loads actor-specific rule tasks without reading every rule history or deriving totals from a page. */
export const loadBadgeWorkflowHomeSummary = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRulesInput & {
    readonly actorUserId: string;
    readonly actorRole: TenantMembershipRole;
  },
): Promise<BadgeWorkflowHomeSummary> => {
  const scope = badgeRuleRegistryScopeSql(input);
  const empty: BadgeWorkflowHomeSummary = {
    ruleCount: 0,
    activeRuleCount: 0,
    actionCount: 0,
    waitingCount: 0,
    tasks: [],
  };
  if (scope.empty) return empty;
  const isAdmin = input.actorRole === "admin" || input.actorRole === "owner";
  const source = `${scope.cte.trim().length === 0 ? "WITH" : `${scope.cte},`} workflow AS (
    SELECT versions.*, rules.active_version_id,
      CASE
        WHEN versions.status = 'draft' AND ? AND EXISTS (
          SELECT 1 FROM badge_issuance_rule_approval_steps AS returned_step
          WHERE returned_step.tenant_id = versions.tenant_id AND returned_step.version_id = versions.id
            AND returned_step.status = 'changes_requested'
        ) THEN 'revise'
        WHEN versions.status = 'pending_approval' AND ? AND NOT EXISTS (${eligibleReviewerSql}) THEN 'configure_approval'
        WHEN versions.status = 'pending_approval' AND EXISTS (${eligibleReviewerSql} AND member.user_id = ?) THEN 'review'
        WHEN versions.status = 'approved' AND ? THEN 'activate'
        WHEN versions.status = 'active' AND versions.id = rules.active_version_id AND ?
          AND versions.rule_json::jsonb #>> '{options,issuanceTiming}' = 'end_of_term' AND versions.expires_at IS NULL THEN 'schedule'
        WHEN versions.status = 'active' AND versions.id = rules.active_version_id AND ? AND NOT EXISTS (
          SELECT 1 FROM lti_resource_link_placements AS placement
          WHERE placement.tenant_id = rules.tenant_id AND placement.rule_id = rules.id AND placement.status = 'active'
        ) THEN 'placement'
        WHEN versions.status = 'suspended' AND ? THEN 'resume'
        WHEN versions.status IN ('draft', 'rejected') AND ? AND versions.created_by_user_id = ? THEN 'submit'
        ELSE NULL
      END AS workflow_action,
      versions.status = 'pending_approval' AND versions.submitted_by_user_id = ? AS waiting_for_review,
      EXISTS (SELECT 1 FROM badge_issuance_rule_versions AS active WHERE active.tenant_id = rules.tenant_id
        AND active.rule_id = rules.id AND active.id = rules.active_version_id AND active.status = 'active') AS has_active_version
    FROM badge_issuance_rule_registry_projection AS registry
    JOIN badge_issuance_rules AS rules ON rules.tenant_id = registry.tenant_id AND rules.id = registry.rule_id
    JOIN LATERAL (SELECT * FROM badge_issuance_rule_versions AS candidate
      WHERE candidate.tenant_id = rules.tenant_id AND candidate.rule_id = rules.id
      ORDER BY candidate.version_number DESC LIMIT 1) AS versions ON TRUE
    LEFT JOIN badge_issuance_rule_approval_steps AS step ON step.tenant_id = versions.tenant_id
      AND step.version_id = versions.id AND step.status = 'pending'
    WHERE registry.tenant_id = ? ${scope.where}
  )`;
  const params = [
    ...scope.beforeTenantParams,
    isAdmin,
    isAdmin,
    input.actorUserId,
    isAdmin,
    isAdmin,
    isAdmin,
    isAdmin,
    isAdmin,
    input.actorUserId,
    input.actorUserId,
    input.tenantId,
    ...scope.afterTenantParams,
  ];
  const [countsRow, rows] = await Promise.all([
    db
      .prepare(`${source} SELECT COUNT(*) AS ruleCount,
      COUNT(*) FILTER (WHERE has_active_version) AS activeRuleCount,
      COUNT(*) FILTER (WHERE workflow_action IS NOT NULL) AS actionCount,
      COUNT(*) FILTER (WHERE waiting_for_review AND workflow_action IS NULL) AS waitingCount FROM workflow`)
      .bind(...params)
      .first<unknown>(),
    db
      .prepare(`${source} SELECT ${badgeIssuanceRuleVersionSelectColumns("workflow")}, workflow_action AS workflowAction,
      id = active_version_id AND status = 'active' AS current
      FROM workflow WHERE workflow_action IS NOT NULL
      ORDER BY CASE workflow_action WHEN 'revise' THEN 0 WHEN 'configure_approval' THEN 1 WHEN 'review' THEN 2 WHEN 'activate' THEN 3
        WHEN 'schedule' THEN 4 WHEN 'placement' THEN 5 WHEN 'resume' THEN 6 ELSE 7 END, updated_at, id LIMIT 5`)
      .bind(...params)
      .all<BadgeIssuanceRuleVersionRow & { workflowAction: unknown; current: boolean }>(),
  ]);
  const counts = z
    .object({
      ruleCount: z.coerce.number().int().nonnegative(),
      activeRuleCount: z.coerce.number().int().nonnegative(),
      actionCount: z.coerce.number().int().nonnegative(),
      waitingCount: z.coerce.number().int().nonnegative(),
    })
    .parse(countsRow);
  return {
    ...counts,
    tasks: rows.results.map((row) => ({
      action: taskSchema.parse(row.workflowAction),
      current: z.boolean().parse(row.current),
      version: mapBadgeIssuanceRuleVersionRow(row),
    })),
  };
};
