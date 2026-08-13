import {
  canDeleteBadgeIssuanceRuleDraft,
  canEditBadgeIssuanceRuleDraft,
  indexBadgeIssuanceRuleVersionsByRuleId,
  resolveBadgeIssuanceRuleVersionSelection,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleRegistrySort,
  type BadgeIssuanceRuleVersionRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { CtInput, CtSelect } from "../../ui/forms";
import {
  badgeRuleVersionDisplayFields,
  badgeRuleVersionStatusLabel,
} from "../../badges/badge-rule-presentation";
import { formatIsoTimestamp } from "../../utils/display-format";
import { buildBadgeRuleDetailPath, buildBadgeRuleVersionDetailPath } from "../access-admin-helpers";
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
      {input.badgeRules.map((rule) => {
        const versions = versionsByRule.get(rule.id) ?? [];
        const versionSelection = resolveBadgeIssuanceRuleVersionSelection({ rule, versions });
        const latestVersion = versionSelection.latestVersion;
        const activeVersion = versionSelection.activeVersion;
        const displayVersion = versionSelection.defaultVersion;
        const displayFields =
          displayVersion === null ? null : badgeRuleVersionDisplayFields(displayVersion);
        const displayName = displayFields?.displayName ?? "Rule version unavailable";
        const isEditableRule = canEditBadgeIssuanceRuleDraft(rule, versions);
        const canDeleteRule = canDeleteBadgeIssuanceRuleDraft(rule, versions);
        const editRulePath = `${buildBadgeRuleDetailPath(input.tenantId, rule.id)}/edit`;
        const detailPath =
          versionSelection.defaultVersion === null
            ? buildBadgeRuleDetailPath(input.tenantId, rule.id)
            : buildBadgeRuleVersionDetailPath(
                input.tenantId,
                rule.id,
                versionSelection.defaultVersion.id,
              );
        const menuActions =
          latestVersion === null
            ? []
            : buildBadgeRuleWorkflowMenuActions({
                tenantId: input.tenantId,
                userId: input.userId,
                rule,
                latestVersion,
                canDeleteRule,
              });

        return (
          <tr>
            <td>
              <a class="ct-admin__rule-name-link" href={detailPath}>
                <strong>{displayName}</strong>
              </a>
            </td>
            <td>{displayFields?.badgeTitle ?? "Unavailable"}</td>
            <td>{displayFields?.lmsProviderLabel ?? "Unavailable"}</td>
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
              {latestVersion === null ? (
                "No version"
              ) : (
                <>
                  <strong>Version {String(latestVersion.versionNumber)}</strong>
                  <AdminStatusPill tone={latestVersion.status}>
                    {badgeRuleVersionStatusLabel(latestVersion.status)}
                  </AdminStatusPill>
                  {latestVersion.recertificationDueAt === null ? null : (
                    <AdminMeta>
                      Recertification due {formatIsoTimestamp(latestVersion.recertificationDueAt)}
                    </AdminMeta>
                  )}
                </>
              )}
            </td>
            <td>
              {displayFields === null ? "Unavailable" : formatIsoTimestamp(displayFields.updatedAt)}
            </td>
            <td>
              <AdminActions>
                <AdminButtonLink href={detailPath} variant="secondary" size="tiny">
                  View
                </AdminButtonLink>
                {isEditableRule ? (
                  <AdminButtonLink href={editRulePath} variant="ghost" size="tiny">
                    Edit
                  </AdminButtonLink>
                ) : null}
                {menuActions.length > 0 ? (
                  <AdminActionMenu
                    menuId={`badge-rule-action-menu-${rule.id}`}
                    ariaLabel={`More actions for ${displayName}`}
                  >
                    {menuActions}
                  </AdminActionMenu>
                ) : null}
              </AdminActions>
            </td>
          </tr>
        );
      })}
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
        <AdminButtonLink href={clearFiltersUrl} variant="ghost">
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
            <AdminButtonLink href={input.registry.previousPageHref} variant="ghost">
              Previous
            </AdminButtonLink>
          )}
          {input.registry.nextPageHref === null ? (
            <span class="ct-admin__button ct-admin__button--ghost" aria-disabled="true">
              Next
            </span>
          ) : (
            <AdminButtonLink href={input.registry.nextPageHref} variant="ghost">
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
            <AdminButtonLink href={input.rulesTemplatesPath} variant="ghost">
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
