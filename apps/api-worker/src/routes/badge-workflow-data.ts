import {
  listTenantMembers,
  listTenantOrgUnits,
  listBadgeRuleApproverGroupsWithMembers,
  listBadgeIssuanceRuleVersionApprovalStepsForVersions,
  resolveBadgeRuleApprovalPolicies,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
} from "@credtrail/db";
import {
  describeBadgeWorkflowPolicy,
  type BadgeTemplateWorkflow,
  buildBadgeWorkflowResponsibility,
  type BadgeWorkflowDirectory,
  type BadgeWorkflowResponsibility,
} from "../admin/badge-workflow-responsibility";

/** Loads tenant-local names and reviewer memberships once for a rendered workflow. */
export const loadBadgeWorkflowDirectory = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<BadgeWorkflowDirectory> => {
  const [members, orgUnits, groups] = await Promise.all([
    listTenantMembers(db, tenantId),
    listTenantOrgUnits(db, { tenantId, includeInactive: true }),
    listBadgeRuleApproverGroupsWithMembers(db, tenantId),
  ]);
  return { members, orgUnits, groups };
};

/** Bulk-loads summaries for the already-authorized versions visible on this page. */
export const loadBadgeWorkflowResponsibilities = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly actorUserId: string;
    readonly rules: readonly BadgeIssuanceRuleRecord[];
    readonly activeVersionIds?: readonly string[];
    readonly versions: readonly BadgeIssuanceRuleVersionRecord[];
  },
): Promise<ReadonlyMap<string, BadgeWorkflowResponsibility>> => {
  if (input.versions.length === 0) return new Map();
  const versions = input.versions.filter((version) => version.tenantId === input.tenantId);
  const [directory, policies, steps] = await Promise.all([
    loadBadgeWorkflowDirectory(db, input.tenantId),
    resolveBadgeRuleApprovalPolicies(db, {
      tenantId: input.tenantId,
      orgUnitIds: versions.map((version) => version.snapshot.orgUnitId),
    }),
    listBadgeIssuanceRuleVersionApprovalStepsForVersions(db, {
      tenantId: input.tenantId,
      versionIds: versions.map((version) => version.id),
    }),
  ]);
  const summaries = new Map<string, BadgeWorkflowResponsibility>();
  for (const version of versions) {
    const policy = policies.get(version.snapshot.orgUnitId);
    if (policy === undefined) continue;
    summaries.set(
      version.id,
      buildBadgeWorkflowResponsibility({
        version,
        policy,
        directory,
        actorUserId: input.actorUserId,
        current:
          input.activeVersionIds?.includes(version.id) ||
          input.rules.some(
            (rule) =>
              rule.tenantId === input.tenantId &&
              rule.activeVersionId === version.id &&
              version.status === "active",
          ),
        steps: steps.filter((step) => step.versionId === version.id),
      }),
    );
  }
  return summaries;
};

/** Resolves displayed identities and effective approval policy for selectable badges. */
export const loadBadgeTemplateWorkflows = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly actorUserId: string;
    readonly templates: readonly BadgeTemplateRecord[];
    readonly ruleOrgUnitId?: string;
    readonly ruleAuthorId?: string | null;
  },
): Promise<Readonly<Record<string, BadgeTemplateWorkflow>>> => {
  const templates = input.templates.filter((template) => template.tenantId === input.tenantId);
  const [directory, policies] = await Promise.all([
    loadBadgeWorkflowDirectory(db, input.tenantId),
    resolveBadgeRuleApprovalPolicies(db, {
      tenantId: input.tenantId,
      orgUnitIds: templates.map((template) => input.ruleOrgUnitId ?? template.ownerOrgUnitId),
    }),
  ]);
  const person = (id: string | null): string =>
    directory.members.find((member) => member.userId === id)?.email ??
    (id === null ? "Creator not recorded" : "Creator no longer a member");
  const summaries: Record<string, BadgeTemplateWorkflow> = {};
  for (const template of templates) {
    const policy = policies.get(input.ruleOrgUnitId ?? template.ownerOrgUnitId);
    if (policy === undefined) continue;
    summaries[template.id] = {
      badgeOwner:
        directory.orgUnits.find((unit) => unit.id === template.ownerOrgUnitId)?.displayName ??
        "Owning department not available",
      badgeCreator: person(template.createdByUserId),
      ruleAuthor: person(input.ruleAuthorId === undefined ? input.actorUserId : input.ruleAuthorId),
      approval: describeBadgeWorkflowPolicy(policy, directory, [
        input.ruleAuthorId ?? input.actorUserId,
        input.actorUserId,
      ]),
    };
  }
  return summaries;
};
