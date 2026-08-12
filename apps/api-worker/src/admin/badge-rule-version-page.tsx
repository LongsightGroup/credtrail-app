import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  TenantMembershipRole,
  TenantOrgUnitRecord,
  TenantRecord,
} from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { badgeRuleVersionDisplayFields } from "../badges/badge-rule-presentation";
import type { AppPage } from "../ui/render-page";
import { buildRulesAdminPath } from "./access-admin-helpers";
import {
  BadgeRuleVersionNavigator,
  buildBadgeRuleVersionNavigationModel,
} from "./badge-rule-version-navigator";
import { BadgeRuleVersionOverview } from "./badge-rule-version-overview";
import { renderInstitutionAdminShellPage } from "./institution-admin-shell";

/** Builds the canonical institution-admin page for inspecting one badge-rule version. */
export const badgeRuleVersionPage = (input: {
  readonly tenant: TenantRecord;
  readonly userId: string;
  readonly userEmail?: string | undefined;
  readonly membershipRole: TenantMembershipRole;
  readonly switchOrganizationPath?: string | null | undefined;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly versions: readonly BadgeIssuanceRuleVersionRecord[];
  readonly definition: BadgeIssuanceRuleDefinition;
  readonly orgUnit: TenantOrgUnitRecord | null;
}): AppPage => {
  const navigation = buildBadgeRuleVersionNavigationModel({
    rule: input.rule,
    selectedVersion: input.version,
    versions: input.versions,
  });

  const displayFields = badgeRuleVersionDisplayFields(input.version);

  return renderInstitutionAdminShellPage({
    tenant: input.tenant,
    userId: input.userId,
    ...(input.userEmail === undefined ? {} : { userEmail: input.userEmail }),
    membershipRole: input.membershipRole,
    view: "rules",
    title: `${displayFields.displayName} · Rules · Institution Admin · ${input.tenant.displayName}`,
    assets: [
      "institutionAdminCss",
      "institutionAdminRuleVersionCss",
      "institutionAdminShellJs",
      "institutionAdminRuleVersionJs",
    ],
    contextJson: {},
    ...(input.switchOrganizationPath === undefined
      ? {}
      : { switchOrganizationPath: input.switchOrganizationPath }),
    children: (
      <>
        <header class="ct-admin-page-header ct-admin__rule-version-page-header">
          <p class="ct-admin__rule-version-back-link">
            <a href={buildRulesAdminPath(input.tenant.id)}>← All rules</a>
          </p>
          <h1>{displayFields.displayName}</h1>
          <p>Immutable rule record · Version {String(input.version.versionNumber)}</p>
        </header>
        <section class="ct-admin ct-stack">
          <BadgeRuleVersionNavigator
            tenantId={input.tenant.id}
            rule={input.rule}
            navigation={navigation}
            destination="detail"
          />
          <BadgeRuleVersionOverview
            tenantId={input.tenant.id}
            rule={input.rule}
            version={input.version}
            latestVersion={navigation.latestVersion}
            definition={input.definition}
            orgUnit={input.orgUnit}
          />
        </section>
      </>
    ),
  });
};
