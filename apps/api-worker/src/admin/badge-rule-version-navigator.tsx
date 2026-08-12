import {
  resolveBadgeIssuanceRuleVersionSelection,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { badgeRuleVersionStateLabel } from "../badges/badge-rule-presentation";
import { CtSelect } from "../ui/forms";
import {
  buildBadgeRuleApprovalReviewSelectionPath,
  buildBadgeRuleDetailPath,
  buildBadgeRuleVersionDetailPath,
  buildBadgeRuleVersionReviewPath,
} from "./access-admin-helpers";
import { AdminButton, AdminButtonLink, AdminField, AdminForm } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
type BadgeRuleVersionNavigationDestination = "detail" | "approval_review";

/** Canonically ordered rule versions and the selected version's adjacent records. */
export interface BadgeRuleVersionNavigationModel {
  readonly selectedVersion: BadgeIssuanceRuleVersionRecord;
  readonly orderedVersions: readonly BadgeIssuanceRuleVersionRecord[];
  readonly latestVersion: BadgeIssuanceRuleVersionRecord;
  readonly previousVersion: BadgeIssuanceRuleVersionRecord | null;
  readonly nextVersion: BadgeIssuanceRuleVersionRecord | null;
}

/** Builds version navigation from the database's canonical newest-first selection. */
export const buildBadgeRuleVersionNavigationModel = (input: {
  readonly rule: BadgeIssuanceRuleRecord;
  readonly selectedVersion: BadgeIssuanceRuleVersionRecord;
  readonly versions: readonly BadgeIssuanceRuleVersionRecord[];
}): BadgeRuleVersionNavigationModel => {
  const selection = resolveBadgeIssuanceRuleVersionSelection({
    rule: input.rule,
    versions: input.versions,
  });

  if (selection.latestVersion === null) {
    throw new Error("Badge rule version navigation requires at least one saved version");
  }

  const selectedIndex = selection.orderedVersions.findIndex(
    (version) => version.id === input.selectedVersion.id,
  );

  if (selectedIndex < 0) {
    throw new Error("Badge rule version navigation requires the selected version");
  }

  const selectedVersion = selection.orderedVersions[selectedIndex];

  if (selectedVersion === undefined) {
    throw new Error("Badge rule version navigation selected index is out of bounds");
  }

  return {
    selectedVersion,
    orderedVersions: selection.orderedVersions,
    latestVersion: selection.latestVersion,
    previousVersion: selection.orderedVersions[selectedIndex + 1] ?? null,
    nextVersion:
      selectedIndex === 0 ? null : (selection.orderedVersions[selectedIndex - 1] ?? null),
  };
};

const buildVersionDestination = (input: {
  readonly destination: BadgeRuleVersionNavigationDestination;
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
}): string => {
  if (input.destination === "approval_review") {
    return buildBadgeRuleVersionReviewPath(input.tenantId, input.ruleId, input.versionId);
  }

  return buildBadgeRuleVersionDetailPath(input.tenantId, input.ruleId, input.versionId);
};

const buildVersionSelectionAction = (input: {
  readonly destination: BadgeRuleVersionNavigationDestination;
  readonly tenantId: string;
  readonly ruleId: string;
}): string => {
  if (input.destination === "approval_review") {
    return buildBadgeRuleApprovalReviewSelectionPath(input.tenantId, input.ruleId);
  }

  return buildBadgeRuleDetailPath(input.tenantId, input.ruleId);
};

/** Renders a shared selector that navigates directly between immutable badge-rule versions. */
export const BadgeRuleVersionNavigator = (input: {
  readonly tenantId: string;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly navigation: BadgeRuleVersionNavigationModel;
  readonly destination: BadgeRuleVersionNavigationDestination;
}): HonoElement => {
  const { latestVersion, nextVersion, orderedVersions, previousVersion, selectedVersion } =
    input.navigation;
  const destinationFor = (version: BadgeIssuanceRuleVersionRecord): string =>
    buildVersionDestination({
      destination: input.destination,
      tenantId: input.tenantId,
      ruleId: input.rule.id,
      versionId: version.id,
    });

  return (
    <nav class="ct-admin__rule-version-navigation" aria-label="Rule version navigation">
      {previousVersion === null ? (
        <span class="ct-admin__rule-version-direction" aria-disabled="true">
          ← Previous version
        </span>
      ) : (
        <AdminButtonLink
          href={destinationFor(previousVersion)}
          variant="secondary"
          size="tiny"
          ariaLabel={`Previous version, version ${String(previousVersion.versionNumber)}`}
        >
          ← Previous version
        </AdminButtonLink>
      )}
      <AdminForm
        method="get"
        action={buildVersionSelectionAction({
          destination: input.destination,
          tenantId: input.tenantId,
          ruleId: input.rule.id,
        })}
        className="ct-admin__rule-version-navigation-form"
        dataAttributes={{ "data-rule-version-navigation": "" }}
      >
        <span class="ct-admin__rule-version-position">
          Version {String(selectedVersion.versionNumber)} of {String(orderedVersions.length)}
        </span>
        <div class="ct-admin__rule-version-selector">
          <AdminField label="Choose version" compact>
            <CtSelect name="versionId" required dataAttributes={{ "data-rule-version-select": "" }}>
              {orderedVersions.map((version) => (
                <option
                  value={version.id}
                  selected={version.id === selectedVersion.id}
                  data-version-url={destinationFor(version)}
                >
                  Version {String(version.versionNumber)} —{" "}
                  {badgeRuleVersionStateLabel({
                    rule: input.rule,
                    version,
                    latestVersion,
                  })}
                </option>
              ))}
            </CtSelect>
          </AdminField>
          <AdminButton type="submit" variant="secondary" size="tiny">
            View version
          </AdminButton>
        </div>
      </AdminForm>
      {nextVersion === null ? (
        <span class="ct-admin__rule-version-direction" aria-disabled="true">
          Next version →
        </span>
      ) : (
        <AdminButtonLink
          href={destinationFor(nextVersion)}
          variant="secondary"
          size="tiny"
          ariaLabel={`Next version, version ${String(nextVersion.versionNumber)}`}
        >
          Next version →
        </AdminButtonLink>
      )}
    </nav>
  );
};
