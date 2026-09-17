import type { IssuanceEmailOutcome } from "../notifications/issuance-email-outcome";
import { IssuanceNotification } from "./issuance-notification";
import { learnerRecordLink } from "./learner-record-link";
import { issuePreparedBadgePath } from "./badge-awarding-links";
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
  > & {
    readonly returnHref?: string | null | undefined;
    readonly notificationRetry?: import("./issuance-notification").NotificationRetry | undefined;
    readonly notificationMessage?: string | undefined;
    readonly assertion: AssertionRecord;
    readonly notificationOutcome: IssuanceEmailOutcome;
    readonly publicBadgeUrl: string;
  },
): AppPage => {
  const learnerHref = learnerRecordLink(
    input.assertion.tenantId,
    input.assertion.recipientIdentityType,
    input.assertion.recipientIdentity,
  );
  const publicBadgePath = publicBadgePathForAssertion(input.assertion);
  const recordPath = issuedBadgesAssertionPageUrl(
    input.tenant.id,
    emptyIssuedBadgesPageFilterValues(),
    input.assertion.id,
    "audit",
  );
  const returnLabel =
    input.returnHref &&
    new URL(input.returnHref, "https://return.invalid").searchParams.get("notificationStatus") ===
      "failed"
      ? "Back to failed emails"
      : "Back to badge records";
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
    assets: ["institutionAdminCss", "institutionAdminShellJs", "copyPublicBadgeLinkJs"],
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
                {learnerHref === null ? null : (
                  <>
                    <a href={learnerHref}>View learner record</a>
                    <br />
                  </>
                )}
                <strong>Issued:</strong>{" "}
                <time datetime={input.assertion.issuedAt} title={input.assertion.issuedAt}>
                  {formatIsoTimestamp(input.assertion.issuedAt)} UTC
                </time>
              </p>
              <p>
                The credential is issued. You can open its public page or review its record and
                status.
              </p>
              {input.notificationMessage ? <p role="status">{input.notificationMessage}</p> : null}
              <IssuanceNotification
                retry={input.notificationRetry}
                outcome={input.notificationOutcome}
                publicBadgeUrl={input.publicBadgeUrl}
              />
              <AdminActions>
                {input.returnHref ? (
                  <AdminButtonLink href={input.returnHref} variant="secondary">
                    {returnLabel}
                  </AdminButtonLink>
                ) : null}
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
                  href={issuePreparedBadgePath(input.tenant.id, input.assertion.badgeTemplateId)}
                  variant="quiet"
                >
                  Issue this badge to another learner
                </AdminButtonLink>
                {input.assertion.recipientIdentityType === "email" ? (
                  <AdminButtonLink
                    href={`${tenantOperationsManualIssuePath(input.tenant.id)}?${new URLSearchParams({ recipientAssertionId: input.assertion.id })}`}
                    variant="quiet"
                  >
                    Award another badge to this learner
                  </AdminButtonLink>
                ) : null}
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
