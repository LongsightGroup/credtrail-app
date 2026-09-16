import { IssuedBadgeStatusPanel } from "../issued-badge-status-panel";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminEmptyTableRow,
  AdminField,
  AdminForm,
  AdminPanel,
  AdminStatus,
  AdminTable,
  IssuedBadgeRows,
  ReviewQueueRows,
} from "../components";
import { CtInput, CtSelect } from "../../ui/forms";
import {
  buildIssuedBadgesPagePath,
  emptyIssuedBadgesPageFilterValues,
  issuedBadgesAssertionPageUrl,
  issuedBadgesLedgerExportUrl,
} from "../issued-badges-admin-helpers";
import { tenantReviewQueueAdminResolvePath } from "../review-queue-admin-helpers";
import type {
  InstitutionAdminIssuedBadgesWorkspace,
  InstitutionAdminReviewQueueWorkspace,
} from "./page-types";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | HonoElement[];

/** Input required to render the rule-review queue panel. */
export interface RenderRuleReviewQueuePanelInput {
  readonly tenantId: string;
  readonly reviewQueueWorkspace?: InstitutionAdminReviewQueueWorkspace;
}

/** Input required to render the issued-badge operations panel. */
export interface RenderIssuedBadgesPanelInput {
  readonly tenantId: string;
  readonly templateFilterOptions: HonoElement;
  readonly activeOrgUnitOptions: HonoElement;
  readonly issuedBadgesWorkspace?: InstitutionAdminIssuedBadgesWorkspace;
}

/** Renders the issued-badge search, audit, and lifecycle-management panel. */
export const renderIssuedBadgesPanel = (input: RenderIssuedBadgesPanelInput): HonoElement => {
  const issuedBadgesFilters =
    input.issuedBadgesWorkspace?.filters ?? emptyIssuedBadgesPageFilterValues();
  const issuedBadgesPagePath = buildIssuedBadgesPagePath(input.tenantId);
  const selectedBadge = input.issuedBadgesWorkspace?.selectedBadge ?? null;
  const issuedBadgesAssertions = input.issuedBadgesWorkspace?.assertions ?? null;
  const showIssuedBadgesExportAction =
    issuedBadgesAssertions !== null && issuedBadgesAssertions.length > 0;
  const issuedBadgesExportHref = issuedBadgesLedgerExportUrl(input.tenantId, issuedBadgesFilters);
  return (
    <AdminPanel id="issued-badges-panel" variant="table">
      <h2>Badge Records</h2>
      <p>Issued credentials, their current status, and their history.</p>
      {input.issuedBadgesWorkspace?.listError !== null &&
      input.issuedBadgesWorkspace?.listError !== undefined &&
      input.issuedBadgesWorkspace.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.issuedBadgesWorkspace.listError}</AdminStatus>
      ) : input.issuedBadgesWorkspace?.listNotice !== null &&
        input.issuedBadgesWorkspace?.listNotice !== undefined &&
        input.issuedBadgesWorkspace.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.issuedBadgesWorkspace.listNotice}</AdminStatus>
      ) : null}
      <details open={selectedBadge === null}>
        <summary>Search badge records</summary>
        <AdminForm
          id="issued-badges-filter-form"
          method="get"
          action={issuedBadgesPagePath}
          className="ct-admin__form ct-admin__form--inline ct-grid"
        >
          <AdminField label="Issued from">
            <CtInput name="issuedFrom" type="date" value={issuedBadgesFilters.issuedFrom} />
          </AdminField>
          <AdminField label="Issued to">
            <CtInput name="issuedTo" type="date" value={issuedBadgesFilters.issuedTo} />
          </AdminField>
          <AdminField label="Recipient or record">
            <CtInput
              name="recipientQuery"
              type="text"
              placeholder="Recipient email or record identifier"
              value={issuedBadgesFilters.recipientQuery}
            />
          </AdminField>
          <AdminField label="Badge template">
            <CtSelect name="badgeTemplateId">{input.templateFilterOptions}</CtSelect>
          </AdminField>
          <AdminField label="Org unit">
            <CtSelect name="orgUnitId">
              <option value="" selected={issuedBadgesFilters.orgUnitId.length === 0}>
                All org units
              </option>
              {input.activeOrgUnitOptions}
            </CtSelect>
          </AdminField>
          <AdminField label="Status">
            <CtSelect name="state">
              <option value="" selected={issuedBadgesFilters.state.length === 0}>
                All states
              </option>
              <option value="active" selected={issuedBadgesFilters.state === "active"}>
                active
              </option>
              <option value="suspended" selected={issuedBadgesFilters.state === "suspended"}>
                suspended
              </option>
              <option value="revoked" selected={issuedBadgesFilters.state === "revoked"}>
                revoked
              </option>
              <option value="expired" selected={issuedBadgesFilters.state === "expired"}>
                expired
              </option>
            </CtSelect>
          </AdminField>
          <AdminField label="Limit">
            <CtInput
              name="limit"
              type="number"
              min="1"
              max="500"
              step="1"
              value={String(issuedBadgesFilters.limit)}
            />
          </AdminField>
          <AdminButton type="submit">Search issued badges</AdminButton>
        </AdminForm>
      </details>
      {showIssuedBadgesExportAction ? (
        <>
          <AdminActions>
            <AdminButtonLink href={issuedBadgesExportHref} variant="secondary">
              Export matching CSV
            </AdminButtonLink>
          </AdminActions>
          <p class="ct-admin__hint">
            Direct CSV export is capped at 5000 rows. Narrow the filters above if the export is too
            large for direct download.
          </p>
        </>
      ) : null}
      {selectedBadge === null ? null : (
        <IssuedBadgeStatusPanel
          tenantId={input.tenantId}
          badge={selectedBadge}
          mode={input.issuedBadgesWorkspace?.lifecycleMode ?? null}
          filters={issuedBadgesFilters}
        />
      )}
      <AdminTable headers={["Issued", "Recipient", "Template", "State", "Assertion", "Actions"]}>
        {issuedBadgesAssertions === null ? (
          <AdminEmptyTableRow colSpan={6}>
            Use the search form above to load issued badges.
          </AdminEmptyTableRow>
        ) : (
          <IssuedBadgeRows
            assertions={issuedBadgesAssertions}
            evidenceHrefForAssertion={(assertionId) =>
              issuedBadgesAssertionPageUrl(
                input.tenantId,
                issuedBadgesFilters,
                assertionId,
                "audit",
              )
            }
            statusHrefForAssertion={(assertionId) =>
              issuedBadgesAssertionPageUrl(
                input.tenantId,
                issuedBadgesFilters,
                assertionId,
                "status",
              )
            }
          />
        )}
      </AdminTable>
    </AdminPanel>
  );
};

/** Renders pending rule evaluations that require an administrator decision. */
export const renderRuleReviewQueuePanel = (input: RenderRuleReviewQueuePanelInput): HonoElement => {
  const reviewQueueResolvePath = tenantReviewQueueAdminResolvePath(input.tenantId);
  return (
    <AdminPanel id="rule-review-queue-panel" variant="table">
      <h2>Rule Review Queue</h2>
      <p>
        Missing-data evaluations that require a human issue-or-dismiss decision before a badge is
        created.
      </p>
      {input.reviewQueueWorkspace?.listError !== null &&
      input.reviewQueueWorkspace?.listError !== undefined &&
      input.reviewQueueWorkspace.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.reviewQueueWorkspace.listError}</AdminStatus>
      ) : input.reviewQueueWorkspace?.listNotice !== null &&
        input.reviewQueueWorkspace?.listNotice !== undefined &&
        input.reviewQueueWorkspace.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.reviewQueueWorkspace.listNotice}</AdminStatus>
      ) : null}
      <AdminTable headers={["Evaluated", "Recipient", "Rule", "Summary", "Actions"]}>
        {input.reviewQueueWorkspace === undefined ? (
          <AdminEmptyTableRow colSpan={5}>No pending review queue entries.</AdminEmptyTableRow>
        ) : (
          <ReviewQueueRows
            entries={input.reviewQueueWorkspace.entries}
            resolveActionPath={reviewQueueResolvePath}
          />
        )}
      </AdminTable>
    </AdminPanel>
  );
};
