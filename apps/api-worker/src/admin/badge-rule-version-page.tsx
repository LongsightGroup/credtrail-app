import {
  resolveBadgeIssuanceRuleVersionSelection,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type TenantMembershipRole,
  type TenantRecord,
} from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import type { HtmlEscapedString } from "hono/utils/html";
import { CtSelect } from "../ui/forms";
import type { AppPage } from "../ui/render-page";
import { buildBadgeRuleDetailPath, buildRulesAdminPath } from "./access-admin-helpers";
import { badgeRuleVersionStateLabel } from "./badge-rule-presentation";
import { BadgeRuleVersionLifecycleExplanation } from "./badge-rule-version-lifecycle-explanation";
import { BadgeRuleVersionOverview } from "./badge-rule-version-overview";
import { AdminButton, AdminField, AdminForm, AdminPanel } from "./components";
import { renderInstitutionAdminShellPage } from "./institution-admin-shell";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const VersionNavigator = (input: {
  readonly tenantId: string;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly versions: readonly BadgeIssuanceRuleVersionRecord[];
  readonly latestVersion: BadgeIssuanceRuleVersionRecord;
}): HonoElement => {
  return (
    <AdminPanel className="ct-admin__rule-version-navigation">
      <h2>Versions</h2>
      <p>
        Inspect any saved version. When issuance is running, the current active version is the one
        CredTrail uses for new awards.
      </p>
      <AdminForm method="get" action={buildBadgeRuleDetailPath(input.tenantId, input.rule.id)}>
        <div class="ct-admin__rule-version-selector">
          <AdminField label="Version">
            <CtSelect name="versionId" required>
              {input.versions.map((version) => (
                <option value={version.id} selected={version.id === input.version.id}>
                  Version {String(version.versionNumber)} —{" "}
                  {badgeRuleVersionStateLabel({
                    rule: input.rule,
                    version,
                    latestVersion: input.latestVersion,
                  })}
                </option>
              ))}
            </CtSelect>
          </AdminField>
          <AdminButton type="submit" variant="secondary">
            View version
          </AdminButton>
        </div>
      </AdminForm>
    </AdminPanel>
  );
};

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
}): AppPage => {
  const versionSelection = resolveBadgeIssuanceRuleVersionSelection({
    rule: input.rule,
    versions: input.versions,
  });

  if (versionSelection.latestVersion === null) {
    throw new Error("Badge rule version page requires at least one saved version");
  }

  return renderInstitutionAdminShellPage({
    tenant: input.tenant,
    userId: input.userId,
    ...(input.userEmail === undefined ? {} : { userEmail: input.userEmail }),
    membershipRole: input.membershipRole,
    view: "rules",
    title: `${input.version.snapshot.name} · Rules · Institution Admin · ${input.tenant.displayName}`,
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
          <h1>{input.version.snapshot.name}</h1>
          <p>Read-only rule record · Version {String(input.version.versionNumber)}</p>
        </header>
        <section class="ct-admin ct-stack">
          <BadgeRuleVersionOverview
            tenantId={input.tenant.id}
            rule={input.rule}
            version={input.version}
            latestVersion={versionSelection.latestVersion}
            definition={input.definition}
          />
          <VersionNavigator
            tenantId={input.tenant.id}
            rule={input.rule}
            version={input.version}
            versions={versionSelection.orderedVersions}
            latestVersion={versionSelection.latestVersion}
          />
          <BadgeRuleVersionLifecycleExplanation />
        </section>
      </>
    ),
  });
};
