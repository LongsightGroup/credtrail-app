import {
  canDeleteBadgeIssuanceRuleDraft,
  canEditBadgeIssuanceRuleDraft,
  indexBadgeIssuanceRuleVersionsByRuleId,
  resolveBadgeIssuanceRuleVersionSelection,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  badgeRuleVersionDisplayFields,
  badgeRuleVersionStatusLabel,
} from "../../badges/badge-rule-presentation";
import { formatIsoTimestamp } from "../../utils/display-format";
import { buildBadgeRuleDetailPath, buildBadgeRuleVersionDetailPath } from "../access-admin-helpers";
import {
  AdminActionMenu,
  AdminActions,
  AdminButtonLink,
  AdminEmptyTableRow,
  AdminMeta,
  AdminPanel,
  AdminStatusPill,
  AdminTable,
} from "../components";
import { buildBadgeRuleWorkflowMenuActions } from "./badge-rule-workflow-actions";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface RenderBadgeRulesTableInput {
  readonly tenantId: string;
  readonly userId: string;
  readonly ruleCount: string;
  readonly ruleBuilderPath: string;
  readonly rulesTemplatesPath: string;
  readonly badgeRules: readonly BadgeIssuanceRuleRecord[];
  readonly badgeRuleVersions: readonly BadgeIssuanceRuleVersionRecord[];
  readonly builderDraftRows: HonoElement[];
}

const renderFormalRuleRows = (input: RenderBadgeRulesTableInput): HonoElement => {
  if (input.badgeRules.length === 0 && input.builderDraftRows.length === 0) {
    return (
      <AdminEmptyTableRow colSpan={7}>
        No badge rules found. <a href={input.ruleBuilderPath}>Create your first rule</a>.
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

/** Renders the institution-admin badge-rules table and owns every formal rule row. */
export const renderBadgeRulesTable = (input: RenderBadgeRulesTableInput): HonoElement => {
  return (
    <AdminPanel variant="table">
      <h2>Badge Rules ({input.ruleCount})</h2>
      <p>Rules award badges from LMS activity and other verified facts.</p>
      <AdminActions>
        <AdminButtonLink href={input.ruleBuilderPath} variant="secondary">
          Create badge rule
        </AdminButtonLink>
        <AdminButtonLink href={input.rulesTemplatesPath} variant="ghost">
          Manage badge templates
        </AdminButtonLink>
      </AdminActions>
      <AdminTable
        headers={[
          "Rule",
          "Badge",
          "LMS",
          "Current version",
          "Latest version",
          "Updated",
          "Actions",
        ]}
      >
        {input.builderDraftRows}
        {renderFormalRuleRows(input)}
      </AdminTable>
    </AdminPanel>
  );
};
