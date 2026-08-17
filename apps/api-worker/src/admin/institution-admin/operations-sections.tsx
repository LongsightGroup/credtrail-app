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
  tenantIssuedBadgeAdminRevokePath,
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
  const showIssuedBadgeRevokeForm = input.issuedBadgesWorkspace?.lifecycleMode === "revoke";
  const showIssuedBadgeLifecyclePanel =
    showIssuedBadgeRevokeForm &&
    input.issuedBadgesWorkspace?.lifecycleAssertionId !== null &&
    input.issuedBadgesWorkspace?.lifecycleAssertionId !== undefined;
  const issuedBadgesAssertions = input.issuedBadgesWorkspace?.assertions ?? null;
  const showIssuedBadgesExportAction =
    issuedBadgesAssertions !== null && issuedBadgesAssertions.length > 0;
  const issuedBadgesExportHref = issuedBadgesLedgerExportUrl(input.tenantId, issuedBadgesFilters);
  return (
    <AdminPanel id="issued-badges-panel" variant="table">
      <h2>Badge Records</h2>
      <p>Tenant-wide assertion log with evidence reports and revocation actions.</p>
      {input.issuedBadgesWorkspace?.listError !== null &&
      input.issuedBadgesWorkspace?.listError !== undefined &&
      input.issuedBadgesWorkspace.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.issuedBadgesWorkspace.listError}</AdminStatus>
      ) : input.issuedBadgesWorkspace?.listNotice !== null &&
        input.issuedBadgesWorkspace?.listNotice !== undefined &&
        input.issuedBadgesWorkspace.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.issuedBadgesWorkspace.listNotice}</AdminStatus>
      ) : null}
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
        <AdminField label="Recipient / assertion search">
          <CtInput
            name="recipientQuery"
            type="text"
            placeholder="recipient@example.com or tenant_123:assertion_456"
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
        <AdminField label="Lifecycle state">
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
      <section
        id="issued-badge-lifecycle-panel"
        class="ct-admin__inline-action-panel ct-stack"
        hidden={!showIssuedBadgeLifecyclePanel}
      >
        <div class="ct-cluster">
          <h3 id="issued-badge-lifecycle-title">Revoke selected badge</h3>
          <AdminButton
            id="issued-badge-lifecycle-close"
            type="button"
            size="tiny"
            variant="secondary"
          >
            Close
          </AdminButton>
        </div>
        <AdminStatus id="issued-badge-lifecycle-status"></AdminStatus>
        <AdminForm
          id="issued-badge-revoke-form"
          method="post"
          action={tenantIssuedBadgeAdminRevokePath(input.tenantId)}
          className="ct-admin__form ct-admin__inline-action-form ct-admin__inline-action-form--issued-revoke ct-grid"
        >
          <CtInput
            name="assertionId"
            type="hidden"
            value={input.issuedBadgesWorkspace?.lifecycleAssertionId ?? ""}
          />
          <CtInput name="issuedFrom" type="hidden" value={issuedBadgesFilters.issuedFrom} />
          <CtInput name="issuedTo" type="hidden" value={issuedBadgesFilters.issuedTo} />
          <CtInput name="recipientQuery" type="hidden" value={issuedBadgesFilters.recipientQuery} />
          <CtInput
            name="badgeTemplateId"
            type="hidden"
            value={issuedBadgesFilters.badgeTemplateId}
          />
          <CtInput name="orgUnitId" type="hidden" value={issuedBadgesFilters.orgUnitId} />
          <CtInput name="state" type="hidden" value={issuedBadgesFilters.state} />
          <CtInput name="limit" type="hidden" value={String(issuedBadgesFilters.limit)} />
          <AdminField label="Reason code">
            <CtSelect name="reasonCode" required>
              <option value="issuer_requested">issuer requested</option>
              <option value="administrative_hold">administrative hold</option>
              <option value="policy_violation">policy violation</option>
              <option value="appeal_pending">appeal pending</option>
              <option value="other">other</option>
            </CtSelect>
          </AdminField>
          <AdminField label="Reason details">
            <CtInput
              name="reason"
              type="text"
              placeholder="Explain why this badge should be revoked."
            />
          </AdminField>
          <AdminButton type="submit" variant="danger">
            Revoke badge
          </AdminButton>
        </AdminForm>
      </section>
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
            revokeLifecycleHrefForAssertion={(assertionId) =>
              issuedBadgesAssertionPageUrl(
                input.tenantId,
                issuedBadgesFilters,
                assertionId,
                "revoke",
              )
            }
          />
        )}
      </AdminTable>
    </AdminPanel>
  );
};

/** Renders the focused badge lifecycle lookup and transition panel. */
export const renderBadgeStatusPanel = (): HonoElement => {
  return (
    <AdminPanel id="lifecycle-panel">
      <h2>Badge Status</h2>
      <p>
        Look up a badge, review its current status, and apply state changes with institutional
        reason codes.
      </p>
      <AdminForm id="assertion-lifecycle-view-form">
        <AdminField label="Assertion ID">
          <CtInput name="assertionId" type="text" required placeholder="tenant_123:assertion_456" />
        </AdminField>
        <AdminButton type="submit">Load lifecycle</AdminButton>
      </AdminForm>
      <AdminStatus id="assertion-lifecycle-view-status"></AdminStatus>
      <pre id="assertion-lifecycle-output" class="ct-admin__code-output" hidden></pre>
      <AdminForm id="assertion-lifecycle-transition-form">
        <AdminField label="Assertion ID">
          <CtInput name="assertionId" type="text" required placeholder="tenant_123:assertion_456" />
        </AdminField>
        <AdminField label="Transition to">
          <CtSelect name="toState" required>
            <option value="active">active</option>
            <option value="suspended">suspended</option>
            <option value="revoked">revoked</option>
            <option value="expired">expired</option>
          </CtSelect>
        </AdminField>
        <AdminField label="Reason code">
          <CtSelect name="reasonCode" required>
            <option value="administrative_hold">administrative_hold</option>
            <option value="policy_violation">policy_violation</option>
            <option value="appeal_pending">appeal_pending</option>
            <option value="appeal_resolved">appeal_resolved</option>
            <option value="credential_expired">credential_expired</option>
            <option value="issuer_requested">issuer_requested</option>
            <option value="other">other</option>
          </CtSelect>
        </AdminField>
        <AdminField label="Reason details (optional)">
          <CtInput
            name="reason"
            type="text"
            placeholder="Explain why this transition is being applied."
          />
        </AdminField>
        <AdminButton type="submit">Apply transition</AdminButton>
      </AdminForm>
      <AdminStatus id="assertion-lifecycle-transition-status"></AdminStatus>
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
