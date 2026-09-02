import {
  canDeleteNeverActiveBadgeIssuanceRule,
  canEditBadgeIssuanceRuleDraft,
  indexBadgeIssuanceRuleVersionsByRuleId,
  resolveBadgeIssuanceRuleVersionSelection,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleRegistrySort,
  type BadgeIssuanceRuleVersionSelection,
  type BadgeIssuanceRuleVersionRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { CtInput, CtSelect } from "../../ui/forms";
import {
  badgeRuleVersionDisplayFields,
  badgeRuleVersionStatusLabel,
} from "../../badges/badge-rule-presentation";
import { badgeRuleLmsProviderLabel } from "../../badges/badge-rule-lms-provider-label";
import { formatIsoTimestamp } from "../../utils/display-format";
import {
  buildBadgeRuleCopyPath,
  buildBadgeRuleDetailPath,
  buildBadgeRulePlacementAvailabilityPath,
  buildBadgeRuleVersionDetailPath,
  tenantBadgeRuleDeleteAdminPath,
} from "../access-admin-helpers";
import {
  AdminActionMenu,
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminEmptyTableRow,
  AdminField,
  AdminForm,
  AdminListHeader,
  AdminMeta,
  AdminPanel,
  AdminStatusPill,
  AdminTable,
  type AdminTableHeader,
} from "../components";
import {
  badgeRuleRegistryPageUrl,
  badgeRuleRegistrySortUrl,
  buildBadgeRuleRegistryPath,
  type BadgeRuleRegistryPageQuery,
} from "../badge-rule-registry-admin-helpers";
import { buildBadgeRuleWorkflowMenuActions } from "./badge-rule-workflow-actions";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface RenderBadgeRulesTableInput {
  readonly tenantId: string;
  readonly userId: string;
  readonly ruleBuilderPath: string;
  readonly rulesTemplatesPath: string;
  readonly badgeRules: readonly BadgeIssuanceRuleRecord[];
  readonly badgeRuleVersions: readonly BadgeIssuanceRuleVersionRecord[];
  readonly builderDraftRows: HonoElement[];
  readonly builderDraftCount: number;
  readonly registry: {
    readonly searchQuery: string;
    readonly latestStatus: BadgeIssuanceRuleVersionRecord["status"] | null;
    readonly sort: BadgeIssuanceRuleRegistrySort;
    readonly direction: "asc" | "desc";
    readonly limit: number;
    readonly totalCount: number;
    readonly previousPageHref: string | null;
    readonly nextPageHref: string | null;
  };
}

type ResolvedBadgeRuleVersionSelection = Extract<
  BadgeIssuanceRuleVersionSelection,
  { readonly _tag: "resolved" }
>;

type InvalidBadgeRuleVersionSelection = Extract<
  BadgeIssuanceRuleVersionSelection,
  { readonly _tag: "invalid_active_reference" }
>;

const renderIncompleteRuleRow = (
  input: RenderBadgeRulesTableInput,
  rule: BadgeIssuanceRuleRecord,
): HonoElement => {
  return (
    <tr>
      <td>
        <strong>{rule.name}</strong>
        <AdminMeta>Setup incomplete</AdminMeta>
      </td>
      <td>Not recorded</td>
      <td>{badgeRuleLmsProviderLabel(rule.lmsProviderKind)}</td>
      <td>Not active</td>
      <td>
        <strong>Setup incomplete</strong>
        <AdminMeta>No version was created</AdminMeta>
        <AdminStatusPill tone="warning">Needs cleanup</AdminStatusPill>
      </td>
      <td>{formatIsoTimestamp(rule.updatedAt)}</td>
      <td>
        <AdminActions>
          <AdminActionMenu
            menuId={`badge-rule-action-menu-${rule.id}`}
            ariaLabel={`More actions for ${rule.name}`}
          >
            <AdminForm
              method="post"
              action={tenantBadgeRuleDeleteAdminPath(input.tenantId, rule.id)}
              className="ct-admin__action-menu-form"
              dataAttributes={{
                "data-confirm-message": `Delete incomplete rule "${rule.name}"? This rule has no saved versions and cannot be used for awarding.`,
              }}
            >
              <button
                type="submit"
                class="ct-admin__action-menu-item ct-admin__action-menu-item--danger"
              >
                Delete
              </button>
            </AdminForm>
          </AdminActionMenu>
        </AdminActions>
      </td>
    </tr>
  );
};

const renderInvalidActiveVersionRuleRow = (
  input: RenderBadgeRulesTableInput,
  rule: BadgeIssuanceRuleRecord,
  selection: InvalidBadgeRuleVersionSelection,
): HonoElement => {
  const detailPath = buildBadgeRuleDetailPath(input.tenantId, rule.id);
  const latestVersion = selection.latestVersion;

  return (
    <tr>
      <td>
        <a class="ct-admin__rule-name-link" href={detailPath}>
          <strong>{rule.name}</strong>
        </a>
        <AdminMeta>Version reference unavailable</AdminMeta>
      </td>
      <td>Unavailable</td>
      <td>{badgeRuleLmsProviderLabel(rule.lmsProviderKind)}</td>
      <td>
        <strong>Reference unavailable</strong>
        <AdminMeta>The saved active version was not found</AdminMeta>
        <AdminStatusPill tone="warning">Needs attention</AdminStatusPill>
      </td>
      <td>
        {latestVersion === null ? (
          "No version found"
        ) : (
          <>
            <strong>Version {String(latestVersion.versionNumber)}</strong>
            <AdminStatusPill tone={latestVersion.status}>
              {badgeRuleVersionStatusLabel(latestVersion.status)}
            </AdminStatusPill>
          </>
        )}
      </td>
      <td>{formatIsoTimestamp(rule.updatedAt)}</td>
      <td>
        <AdminActions>
          <AdminButtonLink href={detailPath} variant="secondary" size="tiny">
            View
          </AdminButtonLink>
        </AdminActions>
      </td>
    </tr>
  );
};

const renderResolvedRuleRow = (
  input: RenderBadgeRulesTableInput,
  rule: BadgeIssuanceRuleRecord,
  versions: readonly BadgeIssuanceRuleVersionRecord[],
  selection: ResolvedBadgeRuleVersionSelection,
): HonoElement => {
  const { activeVersion, defaultVersion, latestVersion } = selection;
  const displayFields = badgeRuleVersionDisplayFields(defaultVersion);
  const detailPath = buildBadgeRuleVersionDetailPath(input.tenantId, rule.id, defaultVersion.id);
  const editRulePath = `${buildBadgeRuleDetailPath(input.tenantId, rule.id)}/edit`;
  const menuActions = buildBadgeRuleWorkflowMenuActions({
    tenantId: input.tenantId,
    userId: input.userId,
    rule,
    latestVersion,
    canDeleteRule: canDeleteNeverActiveBadgeIssuanceRule(rule, versions),
  });

  return (
    <tr>
      <td>
        <a class="ct-admin__rule-name-link" href={detailPath}>
          <strong>{displayFields.displayName}</strong>
        </a>
      </td>
      <td>{displayFields.badgeTitle}</td>
      <td>{displayFields.lmsProviderLabel}</td>
      <td>
        {activeVersion === null ? (
          "Not active"
        ) : (
          <>
            <strong>Version {String(activeVersion.versionNumber)}</strong>
            <AdminStatusPill tone={activeVersion.status}>
              {badgeRuleVersionStatusLabel(activeVersion.status)}
            </AdminStatusPill>
          </>
        )}
      </td>
      <td>
        <strong>Version {String(latestVersion.versionNumber)}</strong>
        <AdminStatusPill tone={latestVersion.status}>
          {badgeRuleVersionStatusLabel(latestVersion.status)}
        </AdminStatusPill>
        {latestVersion.recertificationDueAt === null ? null : (
          <AdminMeta>
            Recertification due {formatIsoTimestamp(latestVersion.recertificationDueAt)}
          </AdminMeta>
        )}
      </td>
      <td>{formatIsoTimestamp(displayFields.updatedAt)}</td>
      <td>
        <AdminActions className="ct-admin__rule-row-actions">
          <AdminButtonLink href={detailPath} variant="secondary" size="tiny">
            View
          </AdminButtonLink>
          <AdminButtonLink
            href={buildBadgeRuleCopyPath(input.tenantId, rule.id)}
            variant="quiet"
            size="tiny"
            ariaLabel={`Copy ${displayFields.displayName}`}
          >
            Copy
          </AdminButtonLink>
          {canEditBadgeIssuanceRuleDraft(rule, versions) ? (
            <AdminButtonLink href={editRulePath} variant="quiet" size="tiny">
              Edit
            </AdminButtonLink>
          ) : null}
          <AdminButtonLink
            href={buildBadgeRulePlacementAvailabilityPath(input.tenantId, rule.id)}
            variant="quiet"
            size="tiny"
            ariaLabel={`Set course availability for ${displayFields.displayName}`}
          >
            Set course availability
          </AdminButtonLink>
          {menuActions.length > 0 ? (
            <AdminActionMenu
              menuId={`badge-rule-action-menu-${rule.id}`}
              ariaLabel={`More actions for ${displayFields.displayName}`}
            >
              {menuActions}
            </AdminActionMenu>
          ) : null}
        </AdminActions>
      </td>
    </tr>
  );
};

const renderFormalRuleRow = (
  input: RenderBadgeRulesTableInput,
  rule: BadgeIssuanceRuleRecord,
  versions: readonly BadgeIssuanceRuleVersionRecord[],
): HonoElement => {
  const selection = resolveBadgeIssuanceRuleVersionSelection({ rule, versions });

  if (selection._tag === "incomplete") {
    return renderIncompleteRuleRow(input, rule);
  }

  if (selection._tag === "invalid_active_reference") {
    return renderInvalidActiveVersionRuleRow(input, rule, selection);
  }

  return renderResolvedRuleRow(input, rule, versions, selection);
};

const renderFormalRuleRows = (input: RenderBadgeRulesTableInput): HonoElement => {
  if (input.badgeRules.length === 0) {
    const hasFilters =
      input.registry.searchQuery.length > 0 || input.registry.latestStatus !== null;
    return (
      <AdminEmptyTableRow colSpan={7}>
        {hasFilters ? (
          <>
            No governed rules match these filters.{" "}
            <a href={buildBadgeRuleRegistryPath(input.tenantId)}>Clear filters</a>.
          </>
        ) : (
          <>
            No governed rules found. <a href={input.ruleBuilderPath}>Create your first rule</a>.
          </>
        )}
      </AdminEmptyTableRow>
    );
  }

  const versionsByRule = indexBadgeIssuanceRuleVersionsByRuleId(input.badgeRuleVersions);

  return (
    <>
      {input.badgeRules.map((rule) =>
        renderFormalRuleRow(input, rule, versionsByRule.get(rule.id) ?? []),
      )}
    </>
  );
};

const RULE_STATUS_OPTIONS: readonly {
  readonly value: BadgeIssuanceRuleVersionRecord["status"];
  readonly label: string;
}[] = [
  { value: "draft", label: "Draft" },
  { value: "pending_approval", label: "Awaiting approval" },
  { value: "approved", label: "Approved" },
  { value: "active", label: "Active" },
  { value: "suspended", label: "Suspended" },
  { value: "expired", label: "Expired" },
  { value: "rejected", label: "Needs changes" },
  { value: "deprecated", label: "Previous" },
];

const registryPageQuery = (input: RenderBadgeRulesTableInput): BadgeRuleRegistryPageQuery => {
  return {
    searchQuery: input.registry.searchQuery,
    latestStatus: input.registry.latestStatus,
    sort: input.registry.sort,
    direction: input.registry.direction,
    limit: input.registry.limit,
  };
};

const sortableHeader = (
  input: RenderBadgeRulesTableInput,
  label: string,
  sort: BadgeIssuanceRuleRegistrySort,
): AdminTableHeader => {
  const isCurrent = input.registry.sort === sort;
  const currentDirection = isCurrent ? input.registry.direction : null;
  const nextDirection = isCurrent
    ? input.registry.direction === "asc"
      ? "descending"
      : "ascending"
    : sort === "updated" || sort === "current_version" || sort === "latest_version"
      ? "descending"
      : "ascending";

  return {
    label: (
      <a
        class="ct-admin__table-sort-link"
        href={badgeRuleRegistrySortUrl(input.tenantId, registryPageQuery(input), sort)}
        aria-label={`Sort by ${label}, ${nextDirection}`}
      >
        <span>{label}</span>
        {currentDirection === null ? null : (
          <span class="ct-admin__table-sort-direction" aria-hidden="true">
            {currentDirection === "asc" ? "↑" : "↓"}
          </span>
        )}
      </a>
    ),
    ariaSort:
      currentDirection === null ? "none" : currentDirection === "asc" ? "ascending" : "descending",
  };
};

const plainRuleHeaders = (): readonly string[] => {
  return ["Rule", "Badge", "LMS", "Current version", "Latest version", "Updated", "Actions"];
};

const governedRuleHeaders = (
  input: RenderBadgeRulesTableInput,
): readonly (string | AdminTableHeader)[] => {
  return [
    sortableHeader(input, "Rule", "rule"),
    sortableHeader(input, "Badge", "badge"),
    sortableHeader(input, "LMS", "lms"),
    sortableHeader(input, "Current version", "current_version"),
    sortableHeader(input, "Latest version", "latest_version"),
    sortableHeader(input, "Updated", "updated"),
    "Actions",
  ];
};

const renderRegistryFilters = (input: RenderBadgeRulesTableInput): HonoElement => {
  const query = registryPageQuery(input);
  const clearFiltersUrl = badgeRuleRegistryPageUrl(input.tenantId, {
    ...query,
    searchQuery: "",
    latestStatus: null,
  });

  return (
    <AdminForm
      method="get"
      action={buildBadgeRuleRegistryPath(input.tenantId)}
      className="ct-admin__form ct-admin__registry-filters ct-grid"
    >
      <AdminField label="Search rules">
        <CtInput
          name="q"
          type="search"
          value={input.registry.searchQuery}
          placeholder="Search rules, badges, or LMS"
        />
      </AdminField>
      <AdminField label="Latest status">
        <CtSelect name="status">
          <option value="" selected={input.registry.latestStatus === null}>
            All statuses
          </option>
          {RULE_STATUS_OPTIONS.map((option) => (
            <option value={option.value} selected={input.registry.latestStatus === option.value}>
              {option.label}
            </option>
          ))}
        </CtSelect>
      </AdminField>
      <AdminField label="Rules per page">
        <CtSelect name="limit">
          {[25, 50, 100].map((limit) => (
            <option value={String(limit)} selected={input.registry.limit === limit}>
              {String(limit)}
            </option>
          ))}
        </CtSelect>
      </AdminField>
      <CtInput type="hidden" name="sort" value={input.registry.sort} />
      <CtInput type="hidden" name="direction" value={input.registry.direction} />
      <AdminButton type="submit">Apply filters</AdminButton>
      {input.registry.searchQuery.length === 0 && input.registry.latestStatus === null ? null : (
        <AdminButtonLink href={clearFiltersUrl} variant="quiet">
          Clear filters
        </AdminButtonLink>
      )}
    </AdminForm>
  );
};

const renderRegistryPagination = (
  input: RenderBadgeRulesTableInput,
  options: { readonly announce: boolean; readonly hideWithoutPages: boolean },
): HonoElement | null => {
  const visibleCount = input.badgeRules.length;
  const hasPages = input.registry.previousPageHref !== null || input.registry.nextPageHref !== null;
  if (options.hideWithoutPages && !hasPages) {
    return null;
  }

  const matchingLabel = `${String(input.registry.totalCount)} matching ${
    input.registry.totalCount === 1 ? "rule" : "rules"
  }`;

  return (
    <div class="ct-admin__registry-pagination">
      <p aria-live={options.announce ? "polite" : undefined}>
        {visibleCount === 0 ? matchingLabel : `${String(visibleCount)} shown · ${matchingLabel}`}
      </p>
      {hasPages ? (
        <nav aria-label="Badge rule pages" class="ct-admin__registry-page-actions">
          {input.registry.previousPageHref === null ? (
            <span class="ct-admin__button ct-admin__button--ghost" aria-disabled="true">
              Previous
            </span>
          ) : (
            <AdminButtonLink href={input.registry.previousPageHref} variant="quiet">
              Previous
            </AdminButtonLink>
          )}
          {input.registry.nextPageHref === null ? (
            <span class="ct-admin__button ct-admin__button--ghost" aria-disabled="true">
              Next
            </span>
          ) : (
            <AdminButtonLink href={input.registry.nextPageHref} variant="quiet">
              Next
            </AdminButtonLink>
          )}
        </nav>
      ) : null}
    </div>
  );
};

/** Renders the institution-admin badge-rules table and owns every formal rule row. */
export const renderBadgeRulesTable = (input: RenderBadgeRulesTableInput): HonoElement => {
  return (
    <AdminPanel variant="table">
      <AdminListHeader
        title="Badge Rules"
        description="Find governed awarding rules by name, badge, LMS, or lifecycle status."
        action={
          <AdminActions>
            <AdminButtonLink href={input.ruleBuilderPath} variant="secondary">
              Create badge rule
            </AdminButtonLink>
            <AdminButtonLink href={input.rulesTemplatesPath} variant="quiet">
              Manage badge templates
            </AdminButtonLink>
          </AdminActions>
        }
      />
      {input.builderDraftCount === 0 ? null : (
        <section class="ct-admin__registry-drafts" aria-labelledby="unfinished-rule-drafts-title">
          <div>
            <h3 id="unfinished-rule-drafts-title">
              Your unfinished setups ({String(input.builderDraftCount)})
            </h3>
            <p>Resume these drafts before filtering or sorting the governed registry.</p>
          </div>
          <AdminTable headers={plainRuleHeaders()}>{input.builderDraftRows}</AdminTable>
        </section>
      )}
      {renderRegistryFilters(input)}
      {renderRegistryPagination(input, { announce: true, hideWithoutPages: false })}
      <AdminTable headers={governedRuleHeaders(input)}>{renderFormalRuleRows(input)}</AdminTable>
      {renderRegistryPagination(input, { announce: false, hideWithoutPages: true })}
    </AdminPanel>
  );
};
