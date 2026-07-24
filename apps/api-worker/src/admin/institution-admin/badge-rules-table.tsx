import type { HtmlEscapedString } from "hono/utils/html";
import { AdminActions, AdminButtonLink, AdminPanel, AdminTable } from "../components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | HonoElement[];

interface RenderBadgeRulesTableInput {
  readonly ruleCount: string;
  readonly ruleBuilderPath: string;
  readonly rulesTemplatesPath: string;
  readonly builderDraftRows: HonoElement[];
  readonly ruleRows: HonoElement;
}

/** Renders the institution-admin badge-rules table and its primary actions. */
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
          "Template",
          "LMS",
          "Active Version",
          "Latest Version",
          "Status",
          "Updated",
          "Actions",
        ]}
      >
        {input.builderDraftRows}
        {input.ruleRows}
      </AdminTable>
    </AdminPanel>
  );
};
