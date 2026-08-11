import type { BadgeIssuanceRuleRecord, BadgeIssuanceRuleVersionRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { badgeRuleVersionStateLabel } from "../badges/badge-rule-presentation";
import { CtSelect } from "../ui/forms";
import {
  buildBadgeRuleDetailPath,
  buildBadgeRuleVersionDetailPath,
  buildBadgeRuleVersionReviewPath,
} from "./access-admin-helpers";
import { AdminButton, AdminField, AdminForm, AdminPanel } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
type BadgeRuleVersionNavigationDestination = "detail" | "approval_review";

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

/** Renders a shared selector that navigates directly between immutable badge-rule versions. */
export const BadgeRuleVersionNavigator = (input: {
  readonly tenantId: string;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly versions: readonly BadgeIssuanceRuleVersionRecord[];
  readonly latestVersion: BadgeIssuanceRuleVersionRecord;
  readonly destination: BadgeRuleVersionNavigationDestination;
}): HonoElement => {
  return (
    <AdminPanel className="ct-admin__rule-version-navigation">
      <h2>Versions</h2>
      <p>
        Inspect any saved version. When issuance is running, the current active version is the one
        CredTrail uses for new awards.
      </p>
      <AdminForm
        method="get"
        action={buildBadgeRuleDetailPath(input.tenantId, input.rule.id)}
        dataAttributes={{ "data-rule-version-navigation": "" }}
      >
        <div class="ct-admin__rule-version-selector">
          <AdminField label="Version">
            <CtSelect name="versionId" required dataAttributes={{ "data-rule-version-select": "" }}>
              {input.versions.map((version) => (
                <option
                  value={version.id}
                  selected={version.id === input.version.id}
                  data-version-url={buildVersionDestination({
                    destination: input.destination,
                    tenantId: input.tenantId,
                    ruleId: input.rule.id,
                    versionId: version.id,
                  })}
                >
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
