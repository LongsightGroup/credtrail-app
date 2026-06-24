import { AdminPageHeader } from "../../components";
import { renderIssuedBadgesPanel } from "../operations-sections";
import type { InstitutionAdminViewDefinition } from "../view-content";

const issuedBadgesDataNeeds = {
  accessSectionBundles: false,
  operationsSectionBundles: false,
  reportingSectionBundles: false,
  managementSectionBundles: false,
  learnerRecordSectionBundles: false,
  ruleTableRows: false,
  lmsConnectionRows: false,
  apiKeyRows: false,
  orgUnitRows: false,
  governanceTableRows: false,
  tenantMemberRows: false,
  templateSelectOptions: false,
  delegationSelectOptions: false,
  ruleSelectOptions: false,
  ruleVersionIndexes: false,
  orgUnitParentOptions: false,
  issuedBadgeFilters: true,
} as const;

export const OPERATIONS_ISSUED_BADGES_VIEW: InstitutionAdminViewDefinition = {
  titlePrefix: "Badge Records · Institution Admin",
  controller: "shell",
  extraAssets: ["institutionAdminIssuedBadgesJs"],
  dataNeeds: issuedBadgesDataNeeds,
  build: ({ input, paths }) => {
    const selectedBadgeTemplateFilterId =
      input.issuedBadgesWorkspace?.filters.badgeTemplateId ?? "";
    const selectedOrgUnitFilterId = input.issuedBadgesWorkspace?.filters.orgUnitId ?? "";
    const templateFilterOptions = (
      <>
        <option value="" selected={selectedBadgeTemplateFilterId.length === 0}>
          All templates
        </option>
        {input.badgeTemplates.map((template) => (
          <option value={template.id} selected={template.id === selectedBadgeTemplateFilterId}>
            {template.title}
          </option>
        ))}
      </>
    );
    const activeOrgUnitOptions = input.orgUnits
      .filter((orgUnit) => orgUnit.isActive)
      .map((orgUnit) => {
        return (
          <option value={orgUnit.id} selected={orgUnit.id === selectedOrgUnitFilterId}>
            {`${orgUnit.displayName} (${orgUnit.unitType})`}
          </option>
        );
      });
    const issuedBadgesPanelMarkup = renderIssuedBadgesPanel({
      tenantId: input.tenant.id,
      templateFilterOptions,
      activeOrgUnitOptions,
      ...(input.issuedBadgesWorkspace === undefined
        ? {}
        : { issuedBadgesWorkspace: input.issuedBadgesWorkspace }),
    });

    return {
      adminPageContext: {
        assertionsApiPathPrefix: paths.assertionsApiPathPrefix,
      },
      viewContent: (
        <>
          <AdminPageHeader
            title="Badge Records"
            description="Search issued badge records and take audit or revocation actions from one page."
          />
          <section class="ct-admin ct-stack">{issuedBadgesPanelMarkup}</section>
        </>
      ),
    };
  },
};
