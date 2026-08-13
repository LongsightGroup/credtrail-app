import {
  ensureInstitutionOrgUnitForTenant,
  upsertBadgeRuleApprovalPolicy,
  upsertTenant,
  upsertTenantLmsConnection,
  upsertTenantMembershipRole,
  upsertUserByEmail,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { managedBadgeTemplateImagePath } from "@credtrail/validation";
import { createTestBadgeIssuanceRule } from "../../../packages/db/src/badge-issuance-rule-test-fixtures";

import { loadLocalDevEnv, requireEnv } from "../../../scripts/local-dev-env.mjs";

export interface LiveBadgeRuleApprovalFixture {
  readonly tenantId: string;
  readonly authorEmail: string;
  readonly reviewerEmail: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly ruleName: string;
  readonly rulesPath: string;
  readonly approvalsPath: string;
  readonly dispose: () => Promise<void>;
}

const deleteFixture = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly userIds: readonly string[];
  },
): Promise<void> => {
  const authUsers = await db
    .prepare(
      `
        SELECT auth_user_id AS authUserId
        FROM auth_identity_links
        WHERE credtrail_user_id IN (${input.userIds.map(() => "?").join(", ")})
      `,
    )
    .bind(...input.userIds)
    .all<{ authUserId: string }>();

  await db.prepare("DELETE FROM job_queue_messages WHERE tenant_id = ?").bind(input.tenantId).run();
  await db.prepare("DELETE FROM assertions WHERE tenant_id = ?").bind(input.tenantId).run();
  await db.prepare("DELETE FROM tenants WHERE id = ?").bind(input.tenantId).run();

  for (const userId of input.userIds) {
    await db.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
  }

  for (const authUser of authUsers.results) {
    await db.prepare("DELETE FROM auth.user WHERE id = ?").bind(authUser.authUserId).run();
  }
};

/** Creates a disposable real-database tenant for the two-person approval browser test. */
export const createLiveBadgeRuleApprovalFixture =
  async (): Promise<LiveBadgeRuleApprovalFixture> => {
    loadLocalDevEnv();
    const db = createPostgresDatabase({
      databaseUrl: requireEnv("DATABASE_URL"),
      connectionMode: "single-use",
    });
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `tenant_e2e_approval_${suffix}`;
    const authorEmail = `approval-author-${suffix}@example.edu`;
    const reviewerEmail = `approval-reviewer-${suffix}@example.edu`;
    const badgeTemplateId = `badge_template_e2e_${suffix}`;
    const lmsConnectionId = `lms_e2e_${suffix}`;
    const ruleName = `Approval workflow ${suffix.slice(0, 8)}`;

    await upsertTenant(db, {
      id: tenantId,
      slug: `approval-e2e-${suffix}`,
      displayName: "Approval E2E University",
      planTier: "institution",
      issuerDomain: `approval-e2e-${suffix}.issuer.test`,
      didWeb: `did:web:approval-e2e-${suffix}.issuer.test`,
      isActive: true,
    });
    const ownerOrgUnitId = await ensureInstitutionOrgUnitForTenant(db, tenantId);
    const [author, reviewer] = await Promise.all([
      upsertUserByEmail(db, authorEmail),
      upsertUserByEmail(db, reviewerEmail),
    ]);

    await Promise.all([
      upsertTenantMembershipRole(db, { tenantId, userId: author.id, role: "owner" }),
      upsertTenantMembershipRole(db, { tenantId, userId: reviewer.id, role: "admin" }),
    ]);
    await db
      .prepare(
        `
        INSERT INTO badge_templates (
          id,
          tenant_id,
          slug,
          title,
          description,
          criteria_uri,
          image_uri,
          created_by_user_id,
          owner_org_unit_id,
          governance_metadata_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        badgeTemplateId,
        tenantId,
        `approval-workflow-${suffix}`,
        "Approval Workflow Badge",
        "Awarded after the governed browser workflow is approved.",
        "https://example.edu/criteria/approval-workflow",
        `https://credtrail.org${managedBadgeTemplateImagePath({
          tenantId,
          badgeTemplateId,
          assetId: `asset_${suffix}`,
        })}`,
        author.id,
        ownerOrgUnitId,
        '{"source":"e2e_test"}',
      )
      .run();
    await upsertTenantLmsConnection(db, {
      id: lmsConnectionId,
      tenantId,
      displayName: "Approval E2E LMS",
      providerKind: "canvas",
      apiBaseUrl: "https://canvas.example.edu",
    });
    await upsertBadgeRuleApprovalPolicy(db, {
      tenantId,
      approvalRequirement: "always",
      approvalSteps: [{ requiredRole: "admin", label: "Registrar review" }],
      createdByUserId: author.id,
    });
    const created = await createTestBadgeIssuanceRule(db, {
      tenantId,
      name: ruleName,
      description: "A disposable draft used to prove the real approval workflow.",
      badgeTemplateId,
      lmsProviderKind: "canvas",
      lmsConnectionId,
      ruleJson: JSON.stringify({
        conditions: {
          type: "course_completion",
          courseId: "course_approval_e2e",
          minCompletionPercent: 100,
        },
      }),
      changeSummary: "Create browser approval fixture",
      createdByUserId: author.id,
    });

    return {
      tenantId,
      authorEmail,
      reviewerEmail,
      ruleId: created.rule.id,
      versionId: created.version.id,
      ruleName,
      rulesPath: `/tenants/${encodeURIComponent(tenantId)}/admin/rules`,
      approvalsPath: `/tenants/${encodeURIComponent(tenantId)}/admin/rules/approvals`,
      dispose: () =>
        deleteFixture(db, {
          tenantId,
          userIds: [author.id, reviewer.id],
        }),
    };
  };
