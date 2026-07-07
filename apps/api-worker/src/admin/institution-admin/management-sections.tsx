import type { HtmlEscapedString } from "hono/utils/html";
import { AdminActions, AdminButtonLink, AdminPanel, AdminTable } from "../components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | HonoElement[];

interface RenderInstitutionAdminManagementSectionsInput {
  ruleCount: string;
  hasBadgeRules: boolean;
  ruleBuilderPath: string;
  rulesTemplatesPath: string;
  ruleRows: HonoElement;
  evaluateRulePanelMarkup: HonoElement;
}

interface InstitutionAdminManagementSections {
  badgeRulesTableMarkup: HonoElement;
  ruleAdvancedToolsMarkup: HonoElement;
}

export const renderInstitutionAdminManagementSections = (
  input: RenderInstitutionAdminManagementSectionsInput,
): InstitutionAdminManagementSections => {
  const badgeRulesTableMarkup = (
    <AdminPanel variant="table">
      <h2>Badge Rules ({input.ruleCount})</h2>
      <p>
        Create and review the rules that award badges from LMS activity and other verified facts.
      </p>
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
          "Template",
          "LMS",
          "Active Version",
          "Latest Version",
          "Status",
          "Updated",
          "Actions",
        ]}
      >
        {input.ruleRows}
      </AdminTable>
    </AdminPanel>
  );
  const ruleAdvancedToolsMarkup = (
    <details class="ct-admin__advanced-tools">
      <summary>
        <span>Check a rule before issuing</span>
        <small>
          Use this only when you want to test what a rule would do before issuing a real badge.
        </small>
      </summary>
      {input.hasBadgeRules ? (
        <div class="ct-admin__advanced-tools-body ct-grid">{input.evaluateRulePanelMarkup}</div>
      ) : (
        <p class="ct-admin__hint">
          Create a badge rule first. Testing becomes useful once there is a rule to review.
        </p>
      )}
    </details>
  );

  return {
    badgeRulesTableMarkup,
    ruleAdvancedToolsMarkup,
  };
};
