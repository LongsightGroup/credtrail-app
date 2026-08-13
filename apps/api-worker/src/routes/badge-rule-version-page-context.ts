import {
  findBadgeIssuanceRuleById,
  findTenantOrgUnitById,
  listBadgeIssuanceRuleVersions,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
  type TenantOrgUnitRecord,
} from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinitionJson,
  type BadgeIssuanceRuleDefinition,
} from "@credtrail/validation";
import type { AppContext } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import type { AuthenticatedPrincipal } from "../auth/auth-context";
import { resolveBadgeIssuanceRuleDefinitionValueLists } from "../rules/badge-rule-definition-resolver";

/** The authenticated administrator identity used by badge-rule version pages. */
export interface BadgeRuleVersionPageActor {
  readonly principal: AuthenticatedPrincipal;
  readonly membershipRole: TenantMembershipRole;
}

/** Resolves and authorizes the administrator opening a badge-rule version page. */
export type ResolveBadgeRuleVersionPageActor = (
  c: AppContext,
  tenantId: string,
  nextPath: string,
) => Promise<Response | BadgeRuleVersionPageActor>;

/** Shared authorized rule and all-version context for version page routes. */
export interface BadgeRuleVersionsPageContext extends BadgeRuleVersionPageActor {
  readonly db: SqlDatabase;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly versions: readonly BadgeIssuanceRuleVersionRecord[];
}

/** Shared authorized context for one selected rule version and its resolved definition. */
export interface BadgeRuleVersionPageContext extends BadgeRuleVersionsPageContext {
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly definition: BadgeIssuanceRuleDefinition;
  readonly orgUnit: TenantOrgUnitRecord | null;
}

interface LoadBadgeRuleVersionsPageContextInput {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly nextPath: string;
  readonly resolveDatabase: ResolveDatabase;
  readonly resolveActor: ResolveBadgeRuleVersionPageActor;
}

interface LoadBadgeRuleVersionPageContextInput extends LoadBadgeRuleVersionsPageContextInput {
  readonly versionId: string;
}

/** Authorizes the actor and loads one rule with all of its versions. */
export const loadBadgeRuleVersionsPageContext = async (
  c: AppContext,
  input: LoadBadgeRuleVersionsPageContextInput,
): Promise<Response | BadgeRuleVersionsPageContext> => {
  const actor = await input.resolveActor(c, input.tenantId, input.nextPath);

  if (actor instanceof Response) {
    return actor;
  }

  const db = input.resolveDatabase(c.env);
  const [rule, versions] = await Promise.all([
    findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId),
    listBadgeIssuanceRuleVersions(db, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
    }),
  ]);

  if (rule === null || versions.length === 0) {
    return c.json({ error: "Badge rule not found" }, 404);
  }

  return {
    db,
    principal: actor.principal,
    membershipRole: actor.membershipRole,
    rule,
    versions,
  };
};

/** Loads one authorized version and resolves every reusable value-list reference it contains. */
export const loadBadgeRuleVersionPageContext = async (
  c: AppContext,
  input: LoadBadgeRuleVersionPageContextInput,
): Promise<Response | BadgeRuleVersionPageContext> => {
  const loaded = await loadBadgeRuleVersionsPageContext(c, input);

  if (loaded instanceof Response) {
    return loaded;
  }

  const version = loaded.versions.find((candidate) => candidate.id === input.versionId);

  if (version === undefined) {
    return c.json({ error: "Badge rule version not found" }, 404);
  }

  let definition: BadgeIssuanceRuleDefinition;
  let orgUnit: TenantOrgUnitRecord | null;

  try {
    [definition, orgUnit] = await Promise.all([
      resolveBadgeIssuanceRuleDefinitionValueLists(
        loaded.db,
        input.tenantId,
        parseBadgeIssuanceRuleDefinitionJson(version.ruleJson),
      ),
      findTenantOrgUnitById(loaded.db, input.tenantId, version.snapshot.orgUnitId),
    ]);
  } catch {
    return c.json({ error: "Saved badge rule references could not be resolved" }, 409);
  }

  return {
    ...loaded,
    version,
    definition,
    orgUnit,
  };
};
