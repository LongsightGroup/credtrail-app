import type { TenantMembershipRole } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { badgeRuleApprovalPolicyFormState } from "../../badges/badge-rule-approval-policy-summary";
import type { InstitutionAdminPageInput } from "./page-types";
import type {
  InstitutionAdminViewContentInput,
  InstitutionAdminViewDataNeeds,
} from "./view-content";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const emptyOptions = <></>;

const buildOrgUnitOptions = (
  page: InstitutionAdminPageInput,
  dataNeeds: InstitutionAdminViewDataNeeds,
): {
  activeOrgUnitSelectOptions: HonoElement;
  orgUnitParentOptions: HonoElement[];
} => {
  const orgUnitParentOptions = dataNeeds.orgUnitParentOptions
    ? page.orgUnits
        .filter((orgUnit) => orgUnit.isActive)
        .map((orgUnit) => (
          <option value={orgUnit.id} data-unit-type={orgUnit.unitType}>
            {`${orgUnit.displayName} (${orgUnit.unitType})`}
          </option>
        ))
    : [];
  const activeOrgUnitOptions = dataNeeds.accessOrgUnitSelectOptions
    ? page.orgUnits
        .filter((orgUnit) => orgUnit.isActive)
        .map((orgUnit) => (
          <option value={orgUnit.id}>{`${orgUnit.displayName} (${orgUnit.unitType})`}</option>
        ))
    : [];
  const activeOrgUnitSelectOptions = !dataNeeds.accessOrgUnitSelectOptions ? (
    emptyOptions
  ) : activeOrgUnitOptions.length > 0 ? (
    <>{activeOrgUnitOptions}</>
  ) : (
    <option value="">No active org units available</option>
  );

  return { activeOrgUnitSelectOptions, orgUnitParentOptions };
};

const buildTenantOptions = (
  page: InstitutionAdminPageInput,
  dataNeeds: InstitutionAdminViewDataNeeds,
): {
  tenantMemberRoleSelectOptions: HonoElement[];
  tenantMemberSelectOptions: HonoElement;
} => {
  const tenantMemberOptions = dataNeeds.accessMemberSelectOptions
    ? page.tenantMembers.map((member) => (
        <option value={member.userId}>{`${member.email} (${member.role})`}</option>
      ))
    : [];
  const tenantMemberSelectOptions = !dataNeeds.accessMemberSelectOptions ? (
    emptyOptions
  ) : tenantMemberOptions.length > 0 ? (
    <>{tenantMemberOptions}</>
  ) : (
    <option value="">No tenant members available</option>
  );
  const assignableTenantRoles: readonly TenantMembershipRole[] = dataNeeds.tenantMemberRows
    ? page.membershipRole === "owner"
      ? ["owner", "admin", "issuer", "approver", "viewer"]
      : ["admin", "issuer", "approver", "viewer"]
    : [];
  const tenantMemberRoleSelectOptions = assignableTenantRoles.map((role) => (
    <option value={role}>{role}</option>
  ));

  return { tenantMemberRoleSelectOptions, tenantMemberSelectOptions };
};

const buildTemplateOptions = (
  page: InstitutionAdminPageInput,
  dataNeeds: InstitutionAdminViewDataNeeds,
): {
  optionalBadgeTemplateScopeOptions: HonoElement;
  templateSelectOptions: HonoElement;
} => {
  const selectedPathwayTemplateId = page.manualIssueWorkspace?.pathwayIssuance?.badgeTemplateId;
  const options = dataNeeds.templateSelectOptions
    ? page.badgeTemplates.map((template, index) => (
        <option
          value={template.id}
          selected={
            selectedPathwayTemplateId === undefined
              ? index === 0
              : template.id === selectedPathwayTemplateId
          }
        >
          {`${template.title} (${template.id})`}
        </option>
      ))
    : [];
  const templateSelectOptions = !dataNeeds.templateSelectOptions ? (
    emptyOptions
  ) : options.length > 0 ? (
    <>{options}</>
  ) : (
    <option value="">No badge templates available</option>
  );
  const optionalBadgeTemplateScopeOptions = !dataNeeds.delegationSelectOptions ? (
    emptyOptions
  ) : (
    <>
      <option value="">All badge templates in the selected scope</option>
      {page.badgeTemplates.map((template) => (
        <option value={template.id}>{template.title}</option>
      ))}
    </>
  );

  return { optionalBadgeTemplateScopeOptions, templateSelectOptions };
};

const buildApprovalOptions = (
  page: InstitutionAdminPageInput,
  dataNeeds: InstitutionAdminViewDataNeeds,
): {
  approverGroupSelectOptions: HonoElement;
  badgeRuleApprovalOrgUnitSelectOptions: HonoElement;
  badgeRuleApprovalTargetApproverGroupSelectOptions: HonoElement;
  badgeRuleApprovalTargetUserSelectOptions: HonoElement;
} => {
  if (!dataNeeds.governanceTableRows) {
    return {
      approverGroupSelectOptions: emptyOptions,
      badgeRuleApprovalOrgUnitSelectOptions: emptyOptions,
      badgeRuleApprovalTargetApproverGroupSelectOptions: emptyOptions,
      badgeRuleApprovalTargetUserSelectOptions: emptyOptions,
    };
  }

  const formState = badgeRuleApprovalPolicyFormState(page.badgeRuleApprovalPolicy ?? null);
  const badgeRuleApprovalOrgUnitSelectOptions = (
    <>
      {page.orgUnits
        .filter((orgUnit) => orgUnit.isActive)
        .map((orgUnit) => (
          <option
            value={orgUnit.id}
            selected={orgUnit.id === formState.orgUnitId ? true : undefined}
          >
            {`${orgUnit.displayName} (${orgUnit.unitType})`}
          </option>
        ))}
    </>
  );
  const badgeRuleApprovalTargetUserSelectOptions =
    page.tenantMembers.length > 0 ? (
      <>
        {page.tenantMembers.map((member) => (
          <option
            value={member.userId}
            selected={member.userId === formState.targetUserId ? true : undefined}
          >
            {`${member.email} (${member.role})`}
          </option>
        ))}
      </>
    ) : (
      <option value="">No tenant members available</option>
    );
  const approverGroupSelectOptions =
    page.badgeRuleApproverGroups.length > 0 ? (
      <>
        {page.badgeRuleApproverGroups.map((group) => (
          <option value={group.id}>{group.name}</option>
        ))}
      </>
    ) : (
      <option value="">No approver groups available</option>
    );
  const badgeRuleApprovalTargetApproverGroupSelectOptions =
    page.badgeRuleApproverGroups.length > 0 ? (
      <>
        {page.badgeRuleApproverGroups.map((group) => (
          <option
            value={group.id}
            selected={group.id === formState.targetApproverGroupId ? true : undefined}
          >
            {group.name}
          </option>
        ))}
      </>
    ) : (
      <option value="">No approver groups available</option>
    );

  return {
    approverGroupSelectOptions,
    badgeRuleApprovalOrgUnitSelectOptions,
    badgeRuleApprovalTargetApproverGroupSelectOptions,
    badgeRuleApprovalTargetUserSelectOptions,
  };
};

export interface InstitutionAdminViewOptionResources {
  controls: InstitutionAdminViewContentInput["controls"];
  access: {
    activeOrgUnitSelectOptions: HonoElement;
    approverGroupSelectOptions: HonoElement;
    badgeRuleApprovalOrgUnitSelectOptions: HonoElement;
    badgeRuleApprovalTargetApproverGroupSelectOptions: HonoElement;
    badgeRuleApprovalTargetUserSelectOptions: HonoElement;
    optionalBadgeTemplateScopeOptions: HonoElement;
    orgUnitParentOptions: HonoElement[];
    tenantMemberRoleSelectOptions: HonoElement[];
    tenantMemberSelectOptions: HonoElement;
  };
}

export const buildInstitutionAdminViewOptionResources = (input: {
  page: InstitutionAdminPageInput;
  dataNeeds: InstitutionAdminViewDataNeeds;
}): InstitutionAdminViewOptionResources => {
  const orgUnits = buildOrgUnitOptions(input.page, input.dataNeeds);
  const tenants = buildTenantOptions(input.page, input.dataNeeds);
  const templates = buildTemplateOptions(input.page, input.dataNeeds);
  const approval = buildApprovalOptions(input.page, input.dataNeeds);

  return {
    controls: {
      activeOrgUnitSelectOptions: orgUnits.activeOrgUnitSelectOptions,
      optionalBadgeTemplateScopeOptions: templates.optionalBadgeTemplateScopeOptions,
      templateSelectOptions: templates.templateSelectOptions,
      tenantMemberSelectOptions: tenants.tenantMemberSelectOptions,
    },
    access: {
      activeOrgUnitSelectOptions: orgUnits.activeOrgUnitSelectOptions,
      approverGroupSelectOptions: approval.approverGroupSelectOptions,
      badgeRuleApprovalOrgUnitSelectOptions: approval.badgeRuleApprovalOrgUnitSelectOptions,
      badgeRuleApprovalTargetApproverGroupSelectOptions:
        approval.badgeRuleApprovalTargetApproverGroupSelectOptions,
      badgeRuleApprovalTargetUserSelectOptions: approval.badgeRuleApprovalTargetUserSelectOptions,
      optionalBadgeTemplateScopeOptions: templates.optionalBadgeTemplateScopeOptions,
      orgUnitParentOptions: orgUnits.orgUnitParentOptions,
      tenantMemberRoleSelectOptions: tenants.tenantMemberRoleSelectOptions,
      tenantMemberSelectOptions: tenants.tenantMemberSelectOptions,
    },
  };
};
