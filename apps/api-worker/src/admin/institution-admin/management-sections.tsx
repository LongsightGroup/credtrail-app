import type { HtmlEscapedString } from "hono/utils/html";
import { AdminActions, AdminButtonLink, AdminPanel, AdminTable } from "../components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | HonoElement[];

interface RenderInstitutionAdminManagementSectionsInput {
  ruleCount: string;
  ruleBuilderPath: string;
  rulesTemplatesPath: string;
  ruleRows: HonoElement;
}

interface InstitutionAdminManagementSections {
  badgeRulesTableMarkup: HonoElement;
}

export const renderInstitutionAdminManagementSections = (
  input: RenderInstitutionAdminManagementSectionsInput,
): InstitutionAdminManagementSections => {
  return {
    badgeRulesTableMarkup: (
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
    ),
  };
};
