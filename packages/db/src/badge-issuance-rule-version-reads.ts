import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";
import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeIssuanceRuleVersionStatus,
  ListBadgeIssuanceRuleVersionsForRulesInput,
  ListBadgeIssuanceRuleVersionsInput,
} from "./badge-issuance-rule-types.js";
import {
  badgeIssuanceRuleVersionSelectColumns,
  mapBadgeIssuanceRuleVersionRow,
  type BadgeIssuanceRuleVersionRow,
} from "./badge-issuance-rule-version-sql.js";

export interface BadgeIssuanceRuleVersionNumberRow {
  maxVersionNumber: number | string | null;
}

const BADGE_ISSUANCE_RULE_VERSION_STATUSES = new Set<BadgeIssuanceRuleVersionStatus>([
  "draft",
  "pending_approval",
  "approved",
  "active",
  "suspended",
  "expired",
  "rejected",
  "deprecated",
]);
const uniqueNonEmptyIds = (ids: readonly string[]): readonly string[] => {
  return [...new Set(ids.filter((id) => id.length > 0))];
};
export const listBadgeIssuanceRuleVersions = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionsInput,
): Promise<BadgeIssuanceRuleVersionRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleVersionRow>> =>
    db
      .prepare(
        `
        SELECT
          ${badgeIssuanceRuleVersionSelectColumns()}
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id = ?
        ORDER BY version_number DESC
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .all<BadgeIssuanceRuleVersionRow>();

  const result = await listStatement();

  return result.results
    .map((row) => mapBadgeIssuanceRuleVersionRow(row))
    .filter((version) => BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status));
};

/** Loads all saved versions for the requested tenant-scoped rule IDs in one query. */
export const listBadgeIssuanceRuleVersionsForRules = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionsForRulesInput,
): Promise<BadgeIssuanceRuleVersionRecord[]> => {
  const ruleIds = uniqueNonEmptyIds(input.ruleIds);

  if (ruleIds.length === 0) {
    return [];
  }

  const ruleIdPlaceholders = ruleIds.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `
        SELECT
          ${badgeIssuanceRuleVersionSelectColumns()}
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id IN (${ruleIdPlaceholders})
        ORDER BY rule_id ASC, version_number DESC
      `,
    )
    .bind(input.tenantId, ...ruleIds)
    .all<BadgeIssuanceRuleVersionRow>();

  return result.results
    .map((row) => mapBadgeIssuanceRuleVersionRow(row))
    .filter((version) => BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status));
};
export const findBadgeIssuanceRuleVersionById = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    versionId: string;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const lookupStatement = (): Promise<BadgeIssuanceRuleVersionRow | null> =>
    db
      .prepare(
        `
        SELECT
          ${badgeIssuanceRuleVersionSelectColumns()}
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.ruleId, input.versionId)
      .first<BadgeIssuanceRuleVersionRow>();

  const row = await lookupStatement();

  if (row === null) {
    return null;
  }

  const version = mapBadgeIssuanceRuleVersionRow(row);
  return BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status) ? version : null;
};

export const findActiveBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    nowIso?: string | undefined;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const nowIso = input.nowIso ?? new Date().toISOString();
  const lookupStatement = (): Promise<BadgeIssuanceRuleVersionRow | null> =>
    db
      .prepare(
        `
        SELECT
          ${badgeIssuanceRuleVersionSelectColumns("versions")}
        FROM badge_issuance_rules AS rules
        INNER JOIN badge_issuance_rule_versions AS versions
          ON versions.id = rules.active_version_id
          AND versions.rule_id = rules.id
          AND versions.tenant_id = rules.tenant_id
        WHERE rules.tenant_id = ?
          AND rules.id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .first<BadgeIssuanceRuleVersionRow>();

  const row = await lookupStatement();

  if (row === null) {
    return null;
  }

  const version = mapBadgeIssuanceRuleVersionRow(row);
  if (!BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status) || version.status !== "active") {
    return null;
  }

  if (
    version.effectiveStartsAt !== null &&
    version.effectiveStartsAt !== undefined &&
    version.effectiveStartsAt > nowIso
  ) {
    return null;
  }

  if (
    version.expiresAt !== null &&
    version.expiresAt !== undefined &&
    version.expiresAt <= nowIso
  ) {
    return null;
  }

  return version;
};

const DRAFT_EDITABLE_BADGE_ISSUANCE_RULE_VERSION_STATUSES: ReadonlySet<BadgeIssuanceRuleVersionStatus> =
  new Set(["draft", "rejected"]);

export const BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE =
  "Only the latest draft or rejected version can be edited from the builder.";

/** Returns badge-rule versions newest first without mutating the caller's collection. */
export const orderBadgeIssuanceRuleVersionsNewestFirst = (
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): readonly BadgeIssuanceRuleVersionRecord[] => {
  return versions.slice().sort((left, right) => right.versionNumber - left.versionNumber);
};

/** Groups badge-rule versions by rule ID with every group ordered newest first. */
export const indexBadgeIssuanceRuleVersionsByRuleId = (
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): ReadonlyMap<string, readonly BadgeIssuanceRuleVersionRecord[]> => {
  const indexedVersions = new Map<string, BadgeIssuanceRuleVersionRecord[]>();

  for (const version of versions) {
    const ruleVersions = indexedVersions.get(version.ruleId);

    if (ruleVersions === undefined) {
      indexedVersions.set(version.ruleId, [version]);
      continue;
    }

    ruleVersions.push(version);
  }

  for (const [ruleId, ruleVersions] of indexedVersions) {
    indexedVersions.set(ruleId, [...orderBadgeIssuanceRuleVersionsNewestFirst(ruleVersions)]);
  }

  return indexedVersions;
};

export const latestBadgeIssuanceRuleVersion = (
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): BadgeIssuanceRuleVersionRecord | null => {
  return orderBadgeIssuanceRuleVersionsNewestFirst(versions)[0] ?? null;
};

/** Returns the newest version older than the selected version number. */
export const previousBadgeIssuanceRuleVersion = (
  versions: readonly BadgeIssuanceRuleVersionRecord[],
  selectedVersionNumber: number,
): BadgeIssuanceRuleVersionRecord | null => {
  return (
    orderBadgeIssuanceRuleVersionsNewestFirst(versions).find(
      (version) => version.versionNumber < selectedVersionNumber,
    ) ?? null
  );
};

/** Canonical ordering and lifecycle selections for one badge rule's versions. */
export interface BadgeIssuanceRuleVersionSelection {
  readonly orderedVersions: readonly BadgeIssuanceRuleVersionRecord[];
  readonly latestVersion: BadgeIssuanceRuleVersionRecord | null;
  readonly activeVersion: BadgeIssuanceRuleVersionRecord | null;
  readonly defaultVersion: BadgeIssuanceRuleVersionRecord | null;
}

/** Resolves the canonical latest, active, and default detail versions for one rule. */
export const resolveBadgeIssuanceRuleVersionSelection = (input: {
  readonly rule: BadgeIssuanceRuleRecord;
  readonly versions: readonly BadgeIssuanceRuleVersionRecord[];
}): BadgeIssuanceRuleVersionSelection => {
  const orderedVersions = orderBadgeIssuanceRuleVersionsNewestFirst(input.versions);
  const latestVersion = orderedVersions[0] ?? null;
  const activeVersion =
    input.rule.activeVersionId === null
      ? null
      : (orderedVersions.find((version) => version.id === input.rule.activeVersionId) ?? null);

  return {
    orderedVersions,
    latestVersion,
    activeVersion,
    defaultVersion: input.rule.activeVersionId === null ? latestVersion : activeVersion,
  };
};

export const canEditBadgeIssuanceRuleDraft = (
  rule: BadgeIssuanceRuleRecord,
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): boolean => {
  const latestVersion = latestBadgeIssuanceRuleVersion(versions);

  return (
    latestVersion !== null &&
    latestVersion.id !== rule.activeVersionId &&
    DRAFT_EDITABLE_BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(latestVersion.status)
  );
};

export const canDeleteBadgeIssuanceRuleDraft = (
  rule: BadgeIssuanceRuleRecord,
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): boolean => {
  return (
    rule.activeVersionId === null &&
    versions.length > 0 &&
    versions.every((version) =>
      DRAFT_EDITABLE_BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status),
    )
  );
};
