import { formatIsoTimestamp } from "../../utils/display-format";
import { SYNCHRONOUS_EXPORT_ROW_LIMIT } from "@credtrail/db";
import { assertionLifecycleLabels } from "../../badges/assertion-lifecycle-labels";
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
import { CtInput, CtSelect, CtTextarea } from "../../ui/forms";
import {
  buildIssuedBadgesPagePath,
  emptyIssuedBadgesPageFilterValues,
  issuedBadgesAssertionPageUrl,
  issuedBadgesLedgerExportUrl,
  issuedBadgesPageUrl,
} from "../issued-badges-admin-helpers";
import {
  buildReviewQueuePagePath,
  tenantReviewQueueAdminResolvePath,
} from "../review-queue-admin-helpers";
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
  readonly filterLabels?: { readonly badgeTemplate: string; readonly orgUnit: string };
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
  const exportCount = input.issuedBadgesWorkspace?.exportCount;
  const showIssuedBadgesExportAction =
    exportCount !== undefined && exportCount !== null && exportCount > 0;
  const issuedBadgesExportHref = issuedBadgesLedgerExportUrl(input.tenantId, issuedBadgesFilters);
  const activeFilters = Object.entries({
    issuedFrom: issuedBadgesFilters.issuedFrom
      ? `Issued from: ${issuedBadgesFilters.issuedFrom}`
      : "",
    issuedTo: issuedBadgesFilters.issuedTo ? `Issued through: ${issuedBadgesFilters.issuedTo}` : "",
    recipientQuery: issuedBadgesFilters.recipientQuery
      ? `Recipient or record: ${issuedBadgesFilters.recipientQuery}`
      : "",
    badgeTemplateId: issuedBadgesFilters.badgeTemplateId
      ? `Badge: ${input.filterLabels?.badgeTemplate ?? "Selected badge"}`
      : "",
    orgUnitId: issuedBadgesFilters.orgUnitId
      ? `Organization unit: ${input.filterLabels?.orgUnit ?? "Selected unit"}`
      : "",
    state: issuedBadgesFilters.state
      ? `Status: ${Object.entries(assertionLifecycleLabels).find(([state]) => state === issuedBadgesFilters.state)?.[1] ?? issuedBadgesFilters.state}`
      : "",
  })
    .map(([key, label]) => ({ key, label }))
    .filter(({ label }) => label.length > 0);
  const noRecordsMessage =
    activeFilters.length > 0 || issuedBadgesFilters.cursor
      ? "No records match these filters. Change or clear the filters to try again."
      : "No badges have been issued yet.";
  const pagination = input.issuedBadgesWorkspace?.pagination;
  const pageHref = (cursor: string): string =>
    issuedBadgesPageUrl(
      input.tenantId,
      { ...issuedBadgesFilters, cursor },
      {
        cursor,
        limit: String(issuedBadgesFilters.limit),
      },
    );
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
        <AdminStatus data-tone="success">
          {input.issuedBadgesWorkspace.listNotice}
          {selectedBadge ? (
            <>
              {" "}
              <a
                href={issuedBadgesAssertionPageUrl(
                  input.tenantId,
                  issuedBadgesFilters,
                  selectedBadge.assertionId,
                  "audit",
                )}
              >
                View updated record
              </a>
            </>
          ) : null}
        </AdminStatus>
      ) : null}
      <AdminForm
        id="issued-badges-filter-form"
        method="get"
        action={issuedBadgesPagePath}
        className="ct-admin__form ct-stack"
      >
        <div class="ct-admin__record-search">
          <AdminField label="Recipient or record">
            <CtInput
              name="recipientQuery"
              type="search"
              placeholder="Recipient email or record identifier"
              value={issuedBadgesFilters.recipientQuery}
            />
          </AdminField>
          <AdminButton type="submit">Search issued badges</AdminButton>
        </div>
        <details
          open={Boolean(
            issuedBadgesFilters.issuedFrom ||
            issuedBadgesFilters.issuedTo ||
            issuedBadgesFilters.badgeTemplateId ||
            issuedBadgesFilters.orgUnitId ||
            issuedBadgesFilters.state,
          )}
        >
          <summary>More filters</summary>
          <div class="ct-admin__record-filters ct-grid">
            <AdminField label="Issued from">
              <CtInput name="issuedFrom" type="date" value={issuedBadgesFilters.issuedFrom} />
            </AdminField>
            <AdminField label="Issued to">
              <CtInput name="issuedTo" type="date" value={issuedBadgesFilters.issuedTo} />
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
                  All statuses
                </option>
                {Object.entries(assertionLifecycleLabels).map(([value, label]) => (
                  <option value={value} selected={issuedBadgesFilters.state === value}>
                    {label}
                  </option>
                ))}
              </CtSelect>
            </AdminField>
            <AdminField label="Results to show">
              <CtSelect name="limit">
                {Array.from(new Set([25, 50, 100, 250, 500, issuedBadgesFilters.limit]))
                  .sort((a, b) => a - b)
                  .map((limit) => (
                    <option value={String(limit)} selected={limit === issuedBadgesFilters.limit}>
                      {String(limit)} records
                    </option>
                  ))}
              </CtSelect>
            </AdminField>
          </div>
          <AdminButton type="submit">Apply filters</AdminButton>
        </details>
      </AdminForm>
      {activeFilters.length > 0 ? (
        <section aria-label="Active filters" class="ct-stack">
          <p>
            <strong>Active filters:</strong>
            {activeFilters.map(({ key, label }) => (
              <span>
                {" "}
                <a
                  href={issuedBadgesPageUrl(
                    input.tenantId,
                    { ...issuedBadgesFilters, [key]: "", cursor: "" },
                    { limit: String(issuedBadgesFilters.limit) },
                  )}
                  aria-label={`Remove ${key === "recipientQuery" ? "recipient filter" : label}`}
                >
                  {label} ×
                </a>{" "}
              </span>
            ))}
          </p>
          <AdminButtonLink
            href={`${issuedBadgesPagePath}?limit=${String(issuedBadgesFilters.limit)}`}
            variant="quiet"
          >
            Clear filters
          </AdminButtonLink>
        </section>
      ) : null}
      {issuedBadgesAssertions === null ? null : (
        <p role="status">
          {issuedBadgesAssertions.length > 0 &&
          (pagination?.olderCursor || issuedBadgesFilters.cursor)
            ? `${String(issuedBadgesAssertions.length)} records on this page.`
            : issuedBadgesAssertions.length === 0
              ? noRecordsMessage
              : `${String(issuedBadgesAssertions.length)} matching ${issuedBadgesAssertions.length === 1 ? "record" : "records"}.`}
        </p>
      )}
      {issuedBadgesAssertions?.length === 0 &&
      activeFilters.length === 0 &&
      !issuedBadgesFilters.cursor ? (
        <AdminButtonLink
          href={`/tenants/${encodeURIComponent(input.tenantId)}/admin/operations/issue`}
        >
          Issue a badge
        </AdminButtonLink>
      ) : null}
      {showIssuedBadgesExportAction ? (
        <section aria-label="CSV export" class="ct-stack">
          {exportCount > SYNCHRONOUS_EXPORT_ROW_LIMIT ? (
            <p>
              {exportCount.toLocaleString("en-US")} records match your filters. CSV exports support
              up to 5,000 records. Narrow the date range or choose a badge, organization unit, or
              status before downloading.
            </p>
          ) : (
            <>
              <p>
                Export includes all {exportCount.toLocaleString("en-US")} matching{" "}
                {exportCount === 1 ? "record" : "records"} across every page. The count may change
                if records are updated before download.
              </p>
              <AdminActions>
                <AdminButtonLink href={issuedBadgesExportHref} variant="secondary">
                  Export matching CSV
                </AdminButtonLink>
              </AdminActions>
            </>
          )}
        </section>
      ) : null}
      {selectedBadge === null ? null : (
        <IssuedBadgeStatusPanel
          tenantId={input.tenantId}
          badge={selectedBadge}
          formError={input.issuedBadgesWorkspace?.statusFormError}
          mode={input.issuedBadgesWorkspace?.lifecycleMode ?? null}
          filters={issuedBadgesFilters}
        />
      )}
      <AdminTable
        headers={["Learner", "Badge", "Issued", "Status", "Actions"]}
        tableClassName="ct-admin__badge-records"
        wrapperClassName="ct-admin__table-wrap ct-admin__badge-records-wrap"
      >
        {issuedBadgesAssertions === null ? (
          <AdminEmptyTableRow colSpan={5}>No badges have been issued yet.</AdminEmptyTableRow>
        ) : (
          <IssuedBadgeRows
            assertions={issuedBadgesAssertions}
            emptyMessage={noRecordsMessage}
            learnerReturnHref={pageHref(issuedBadgesFilters.cursor ?? "")}
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
      {pagination?.newerCursor || pagination?.olderCursor || issuedBadgesFilters.cursor ? (
        <nav aria-label="Badge record pages">
          <AdminActions>
            {pagination?.newerCursor ? (
              <AdminButtonLink href={pageHref(pagination.newerCursor)} variant="secondary">
                Newer records
              </AdminButtonLink>
            ) : null}
            {pagination?.olderCursor ? (
              <AdminButtonLink href={pageHref(pagination.olderCursor)} variant="secondary">
                Older records
              </AdminButtonLink>
            ) : null}
            {issuedBadgesFilters.cursor ? (
              <AdminButtonLink href={pageHref("")} variant="quiet">
                Newest records
              </AdminButtonLink>
            ) : null}
          </AdminActions>
        </nav>
      ) : null}
    </AdminPanel>
  );
};

/** Renders pending rule evaluations that require an administrator decision. */
export const renderRuleReviewQueuePanel = (input: RenderRuleReviewQueuePanelInput): HonoElement => {
  const reviewQueueResolvePath = tenantReviewQueueAdminResolvePath(input.tenantId);
  const selectedEntry = input.reviewQueueWorkspace?.entries.find(
    (entry) => entry.evaluationId === input.reviewQueueWorkspace?.selectedEvaluationId,
  );
  return (
    <AdminPanel id="rule-review-queue-panel" variant="table">
      <h2>Rule Review Queue</h2>
      <nav aria-label="Review status" class="ct-action-group">
        <a
          href={buildReviewQueuePagePath(input.tenantId)}
          aria-current={
            input.reviewQueueWorkspace?.reviewStatus !== "resolved" ? "page" : undefined
          }
        >
          {input.reviewQueueWorkspace?.reviewStatus !== "resolved" ? (
            <strong>Pending</strong>
          ) : (
            "Pending"
          )}
        </a>
        <a
          href={`${buildReviewQueuePagePath(input.tenantId)}?reviewStatus=resolved`}
          aria-current={
            input.reviewQueueWorkspace?.reviewStatus === "resolved" ? "page" : undefined
          }
        >
          {input.reviewQueueWorkspace?.reviewStatus === "resolved" ? (
            <strong>Resolved</strong>
          ) : (
            "Resolved"
          )}
        </a>
      </nav>
      <p>
        Showing up to 50 recent{" "}
        {input.reviewQueueWorkspace?.reviewStatus === "resolved"
          ? "resolved reviews"
          : "pending reviews"}
        .
      </p>
      <p>Review missing information before issuing a badge, or look up a saved decision.</p>
      {input.reviewQueueWorkspace?.listError !== null &&
      input.reviewQueueWorkspace?.listError !== undefined &&
      input.reviewQueueWorkspace.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.reviewQueueWorkspace.listError}</AdminStatus>
      ) : input.reviewQueueWorkspace?.listNotice !== null &&
        input.reviewQueueWorkspace?.listNotice !== undefined &&
        input.reviewQueueWorkspace.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.reviewQueueWorkspace.listNotice}</AdminStatus>
      ) : null}
      {selectedEntry ? (
        <section
          id="review-decision-panel"
          aria-label="Review decision"
          class="ct-admin__setup-panel ct-stack"
        >
          <h3>
            {selectedEntry.reviewStatus === "pending" ? "Review badge decision" : "Saved decision"}
          </h3>
          <p>
            <strong>Learner:</strong> {selectedEntry.recipientIdentity}
            <br />
            <strong>Badge:</strong> {selectedEntry.badgeTitle ?? "Badge details unavailable"}
            <br />
            <strong>Rule:</strong> {selectedEntry.ruleName ?? "Rule details unavailable"}
          </p>
          {selectedEntry.reviewStatus !== "pending" ? (
            <section aria-label="Decision details" class="ct-stack">
              <p>
                <strong>Decision:</strong>{" "}
                {selectedEntry.decision === "issue" ? "Badge issued" : "Review dismissed"}
              </p>
              <p>
                <strong>Reviewed by:</strong>{" "}
                {selectedEntry.reviewerEmail ?? "Reviewer unavailable"}
              </p>
              <p>
                <strong>Reviewed on:</strong>{" "}
                {selectedEntry.reviewedAt
                  ? `${formatIsoTimestamp(selectedEntry.reviewedAt)} UTC`
                  : "Date unavailable"}
              </p>
              <p>
                <strong>Decision note:</strong> {selectedEntry.decisionNote || "No note was saved."}
              </p>
            </section>
          ) : (
            <>
              <h4>Missing information</h4>
              {selectedEntry.missingInformation?.length ? (
                <ul>
                  {selectedEntry.missingInformation.map((detail) => (
                    <li>{detail}</li>
                  ))}
                </ul>
              ) : (
                <p>
                  No detailed explanation is available. Check the rule and supporting learner
                  evidence before deciding.
                </p>
              )}
              <p>
                Issue badge creates a credential despite the missing information. Dismiss review
                closes this request without issuing a badge.
              </p>
              <AdminForm
                method="post"
                action={reviewQueueResolvePath}
                className="ct-admin__form ct-admin__setup-form ct-stack"
              >
                <CtInput type="hidden" name="evaluationId" value={selectedEntry.evaluationId} />
                <AdminField label="Decision note (optional)">
                  <CtTextarea name="comment" maxlength={2000} rows={3} />
                </AdminField>
                <AdminActions>
                  <AdminButton type="submit" name="decision" value="issue">
                    Issue badge
                  </AdminButton>
                  <AdminButton type="submit" name="decision" value="dismiss" variant="secondary">
                    Dismiss review
                  </AdminButton>
                  <AdminButtonLink href={buildReviewQueuePagePath(input.tenantId)} variant="quiet">
                    Cancel
                  </AdminButtonLink>
                </AdminActions>
              </AdminForm>
            </>
          )}
        </section>
      ) : null}
      <AdminTable headers={["Evaluated", "Recipient", "Rule", "Summary", "Actions"]}>
        {input.reviewQueueWorkspace === undefined ? (
          <AdminEmptyTableRow colSpan={5}>No pending review queue entries.</AdminEmptyTableRow>
        ) : (
          <ReviewQueueRows
            entries={input.reviewQueueWorkspace.entries}
            emptyMessage={
              input.reviewQueueWorkspace.reviewStatus === "resolved"
                ? "No resolved reviews yet."
                : "No pending review queue entries."
            }
            resolveActionPath={reviewQueueResolvePath}
          />
        )}
      </AdminTable>
    </AdminPanel>
  );
};
