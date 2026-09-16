import type { AssertionRecord } from "@credtrail/db";
import { AdminActions, AdminButtonLink, AdminPanel } from "./components";
import {
  renderInstitutionAdminShellPage,
  renderInstitutionAdminPageHeader,
} from "./institution-admin-shell";
import type { InstitutionAdminPageInput } from "./institution-admin/page-types";
import { tenantOperationsManualIssuePath } from "./access-admin-helpers";
import {
  emptyIssuedBadgesPageFilterValues,
  issuedBadgesAssertionPageUrl,
} from "./issued-badges-admin-helpers";
import { publicBadgePathForAssertion } from "../badges/public-badge-model";
import { formatIsoTimestamp } from "../utils/display-format";
import type { AppPage } from "../ui/render-page";

export const issuanceReceiptPath = (tenantId: string, assertionId: string): string =>
  `${tenantOperationsManualIssuePath(tenantId)}/${encodeURIComponent(assertionId)}/receipt`;

export const issuanceReceiptPage = (
  input: Pick<
    InstitutionAdminPageInput,
    "tenant" | "userId" | "userEmail" | "membershipRole" | "switchOrganizationPath"
  > & { readonly assertion: AssertionRecord },
): AppPage => {
  const publicBadgePath = publicBadgePathForAssertion(input.assertion);
  const recordPath = issuedBadgesAssertionPageUrl(
    input.tenant.id,
    emptyIssuedBadgesPageFilterValues(),
    input.assertion.id,
    "audit",
  );
  return renderInstitutionAdminShellPage({
    tenant: input.tenant,
    userId: input.userId,
    userEmail: input.userEmail,
    membershipRole: input.membershipRole,
    ...(input.switchOrganizationPath === undefined
      ? {}
      : { switchOrganizationPath: input.switchOrganizationPath }),
    view: "operationsManualIssue",
    title: `Issuance receipt · ${input.tenant.displayName}`,
    assets: ["institutionAdminCss", "institutionAdminShellJs"],
    contextJson: {},
    children: (
      <>
        {renderInstitutionAdminPageHeader(
          "Badge issued",
          "Review the credential record or continue with another learner.",
        )}
        <section class="ct-admin ct-stack">
          <AdminPanel id="issuance-receipt-panel">
            <section aria-label="Issuance receipt" class="ct-stack">
              <h2>{input.assertion.achievementSnapshot.title}</h2>
              <p>
                <strong>Recipient:</strong> {input.assertion.recipientIdentity}
                <br />
                <strong>Issued:</strong> {formatIsoTimestamp(input.assertion.issuedAt)} UTC
              </p>
              <p>
                The credential is issued. You can open its public page or review its record and
                status.
              </p>
              <AdminActions>
                <AdminButtonLink href={recordPath} variant="primary">
                  View badge record
                </AdminButtonLink>
                <AdminButtonLink
                  href={publicBadgePath}
                  variant="secondary"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Open public badge
                </AdminButtonLink>
                <AdminButtonLink
                  href={tenantOperationsManualIssuePath(input.tenant.id)}
                  variant="quiet"
                >
                  Issue another badge
                </AdminButtonLink>
              </AdminActions>
              <details>
                <summary>Technical details</summary>
                <AdminActions>
                  <AdminButtonLink
                    href={`${publicBadgePath}/verification`}
                    variant="quiet"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Open verification JSON
                  </AdminButtonLink>
                  <AdminButtonLink
                    href={`${publicBadgePath}/jsonld`}
                    variant="quiet"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Open JSON-LD
                  </AdminButtonLink>
                </AdminActions>
              </details>
            </section>
          </AdminPanel>
        </section>
      </>
    ),
  });
};
