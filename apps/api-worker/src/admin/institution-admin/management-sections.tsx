import type { HtmlEscapedString } from "hono/utils/html";
import { AdminButtonLink, AdminPanel, AdminStatus, AdminTable } from "../components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface RenderInstitutionAdminManagementSectionsInput {
  ruleCount: string;
  hasBadgeRules: boolean;
  ruleBuilderPath: string;
  rulesTemplatesPath: string;
  ruleRows: unknown;
  ruleValueListsPanelMarkup: unknown;
  evaluateRulePanelMarkup: unknown;
  ruleGovernancePanelMarkup: unknown;
  orgUnitCount: string;
  orgUnitRows: unknown;
  activeApiKeyCount: string;
  revokedApiKeyCount: string;
  apiKeyRows: unknown;
}

interface InstitutionAdminManagementSections {
  badgeRulesTableMarkup: HonoElement;
  ruleAdvancedToolsMarkup: HonoElement;
  orgUnitsTableMarkup: HonoElement;
  apiKeysTableMarkup: HonoElement;
}

const renderHonoElementList = (value: unknown): HonoElement | HonoElement[] => {
  return Array.isArray(value) ? (value as HonoElement[]) : (value as HonoElement);
};

export const renderInstitutionAdminManagementSections = (
  input: RenderInstitutionAdminManagementSectionsInput,
): InstitutionAdminManagementSections => {
  const badgeRulesTableMarkup = (
    <AdminPanel variant="table">
      <h2>Badge Rules ({input.ruleCount})</h2>
      <p>
        Create and review the rules that award badges from LMS activity and other verified facts.
      </p>
      <div class="ct-admin__workspace-actions">
        <AdminButtonLink href={input.ruleBuilderPath} variant="secondary">
          Create badge rule
        </AdminButtonLink>
        <AdminButtonLink href={input.rulesTemplatesPath} variant="ghost">
          Manage badge templates
        </AdminButtonLink>
      </div>
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
        {renderHonoElementList(input.ruleRows)}
      </AdminTable>
      <AdminStatus id="rule-action-status"></AdminStatus>
    </AdminPanel>
  );
  const ruleAdvancedToolsMarkup = (
    <details class="ct-admin__advanced-tools">
      <summary>
        <span>Advanced rule tools</span>
        <small>
          Use reusable value lists, dry-run evaluation, and governance after rules exist.
        </small>
      </summary>
      {input.hasBadgeRules ? (
        <div class="ct-admin__advanced-tools-body ct-grid">
          {renderHonoElementList(input.ruleValueListsPanelMarkup)}
          {renderHonoElementList(input.evaluateRulePanelMarkup)}
          {renderHonoElementList(input.ruleGovernancePanelMarkup)}
        </div>
      ) : (
        <p class="ct-admin__hint">
          Create a badge rule first. Evaluation and governance tools become useful once there is a
          rule to test or approve.
        </p>
      )}
    </details>
  );

  const orgUnitsTableMarkup = (
    <AdminPanel variant="table" className="ct-admin__org-units-table">
      <h2>Org Units ({input.orgUnitCount})</h2>
      <AdminTable headers={["Name", "Type", "ID", "Status"]}>
        {renderHonoElementList(input.orgUnitRows)}
      </AdminTable>
    </AdminPanel>
  );

  const apiKeysTableMarkup = (
    <AdminPanel variant="table" className="ct-admin__api-keys-table">
      <h2 id="api-key-active-count">Active API Keys ({input.activeApiKeyCount})</h2>
      <p>Revoked keys: {input.revokedApiKeyCount}</p>
      <AdminTable
        headers={["Label", "Prefix", "Scopes", "Expires", "Action"]}
        tbodyId="api-key-body"
      >
        {renderHonoElementList(input.apiKeyRows)}
      </AdminTable>
    </AdminPanel>
  );

  return {
    badgeRulesTableMarkup,
    ruleAdvancedToolsMarkup,
    orgUnitsTableMarkup,
    apiKeysTableMarkup,
  };
};
