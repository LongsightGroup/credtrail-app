import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminButton,
  AdminCheckboxRow,
  AdminEmptyTableRow,
  AdminField,
  AdminForm,
  AdminPanel,
  AdminStatus,
  AdminStatusPill,
  AdminTable,
  IssuedBadgeRows,
  ReviewQueueRows,
  RuleValueListRows,
} from "../components";
import {
  buildIssuedBadgesPagePath,
  issuedBadgesAssertionPageUrl,
  tenantIssuedBadgeAdminRevokePath,
} from "../issued-badges-admin-helpers";
import { tenantReviewQueueAdminResolvePath } from "../review-queue-admin-helpers";
import { tenantRuleValueListsAdminCreatePath } from "../rule-value-lists-admin-helpers";
import type {
  InstitutionAdminIssuedBadgesWorkspace,
  InstitutionAdminOperationsWorkspace,
  InstitutionAdminReviewQueueWorkspace,
  InstitutionAdminRuleValueListsWorkspace,
} from "./page-types";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | readonly HonoElement[];

interface RenderInstitutionAdminOperationsSectionsInput {
  tenantId: string;
  templateSelectOptions: HonoElement;
  ruleSelectOptions: HonoElement;
  templateFilterOptions: HonoElement;
  activeOrgUnitOptions: HonoElement;
  issuedBadgesWorkspace?: InstitutionAdminIssuedBadgesWorkspace;
  reviewQueueWorkspace?: InstitutionAdminReviewQueueWorkspace;
  ruleValueListsWorkspace?: InstitutionAdminRuleValueListsWorkspace;
  operationsWorkspace?: InstitutionAdminOperationsWorkspace;
}

interface InstitutionAdminOperationsSections {
  ruleValueListsPanelMarkup: HonoElement;
  evaluateRulePanelMarkup: HonoElement;
  badgeStatusPanelMarkup: HonoElement;
  ruleGovernancePanelMarkup: HonoElement;
  ruleReviewQueuePanelMarkup: HonoElement;
  issuedBadgesPanelMarkup: HonoElement;
}

export const renderInstitutionAdminOperationsSections = (
  input: RenderInstitutionAdminOperationsSectionsInput,
): InstitutionAdminOperationsSections => {
  const ruleValueListsCreatePath = tenantRuleValueListsAdminCreatePath(input.tenantId);
  const ruleValueListsPanelMarkup = (
    <AdminPanel id="rule-value-lists-panel">
      <h2>Reusable Rule Lists</h2>
      <p>
        Optional shortcut for rules that check the same courses or badge templates. Skip this unless
        you are repeating the same values across multiple rules.
      </p>
      {input.ruleValueListsWorkspace?.listError !== null &&
      input.ruleValueListsWorkspace?.listError !== undefined &&
      input.ruleValueListsWorkspace.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.ruleValueListsWorkspace.listError}</AdminStatus>
      ) : input.ruleValueListsWorkspace?.listNotice !== null &&
        input.ruleValueListsWorkspace?.listNotice !== undefined &&
        input.ruleValueListsWorkspace.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.ruleValueListsWorkspace.listNotice}</AdminStatus>
      ) : null}
      <AdminForm id="rule-value-list-form" method="post" action={ruleValueListsCreatePath}>
        <AdminField label="Label">
          <input name="label" type="text" required placeholder="Core CS sequence" />
        </AdminField>
        <AdminField label="List kind">
          <select name="kind" required>
            <option value="course_ids">Course IDs</option>
            <option value="badge_template_ids">Badge template IDs</option>
          </select>
        </AdminField>
        <AdminField label="Values (comma separated)">
          <textarea
            name="values"
            rows={4}
            required
            spellcheck={false}
            placeholder="CS101, CS102, CS103"
          ></textarea>
        </AdminField>
        <AdminButton type="submit">Create value list</AdminButton>
      </AdminForm>
      <AdminTable headers={["Label", "Kind", "Values"]}>
        <RuleValueListRows valueLists={input.ruleValueListsWorkspace?.valueLists ?? []} />
      </AdminTable>
    </AdminPanel>
  );
  const evaluateRulePanelMarkup = (
    <AdminPanel>
      <h2>Test a Rule</h2>
      <p>Check what a rule would do before issuing a real badge.</p>
      <AdminForm id="rule-evaluate-form">
        <AdminField label="Rule">
          <select name="ruleId" required>
            {input.ruleSelectOptions}
          </select>
        </AdminField>
        <AdminField label="Learner ID">
          <input name="learnerId" type="text" required placeholder="canvas:12345" />
        </AdminField>
        <AdminField label="Recipient email">
          <input name="recipientIdentity" type="email" required placeholder="learner@example.edu" />
        </AdminField>
        <AdminField label="Course ID for provided facts">
          <input name="courseId" type="text" required placeholder="CS101" />
        </AdminField>
        <AdminField label="Final score for provided facts">
          <input
            name="finalScore"
            type="number"
            min="0"
            max="100"
            step="0.01"
            required
            value="92"
          />
        </AdminField>
        <AdminField label="Gradebook items completed %">
          <input
            name="completionPercent"
            type="number"
            min="0"
            max="100"
            step="0.01"
            required
            value="100"
          />
        </AdminField>
        <AdminCheckboxRow>
          <input name="dryRun" type="checkbox" checked />
          Dry run (don’t issue badge)
        </AdminCheckboxRow>
        <AdminButton type="submit">Evaluate rule</AdminButton>
      </AdminForm>
      <AdminStatus id="rule-evaluate-status"></AdminStatus>
    </AdminPanel>
  );
  const badgeStatusPanelMarkup = (
    <AdminPanel id="lifecycle-panel">
      <h2>Badge Status</h2>
      <p>
        Look up a badge, review its current status, and apply state changes with institutional
        reason codes.
      </p>
      <AdminForm id="assertion-lifecycle-view-form">
        <AdminField label="Assertion ID">
          <input name="assertionId" type="text" required placeholder="tenant_123:assertion_456" />
        </AdminField>
        <AdminButton type="submit">Load lifecycle</AdminButton>
      </AdminForm>
      <AdminStatus id="assertion-lifecycle-view-status"></AdminStatus>
      <pre id="assertion-lifecycle-output" class="ct-admin__code-output" hidden></pre>
      <AdminForm id="assertion-lifecycle-transition-form">
        <AdminField label="Assertion ID">
          <input name="assertionId" type="text" required placeholder="tenant_123:assertion_456" />
        </AdminField>
        <AdminField label="Transition to">
          <select name="toState" required>
            <option value="active">active</option>
            <option value="suspended">suspended</option>
            <option value="revoked">revoked</option>
            <option value="expired">expired</option>
          </select>
        </AdminField>
        <AdminField label="Reason code">
          <select name="reasonCode" required>
            <option value="administrative_hold">administrative_hold</option>
            <option value="policy_violation">policy_violation</option>
            <option value="appeal_pending">appeal_pending</option>
            <option value="appeal_resolved">appeal_resolved</option>
            <option value="credential_expired">credential_expired</option>
            <option value="issuer_requested">issuer_requested</option>
            <option value="other">other</option>
          </select>
        </AdminField>
        <AdminField label="Reason details (optional)">
          <input
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
  const ruleGovernancePanelMarkup = (
    <AdminPanel>
      <h2>Approval and Audit History</h2>
      <p>Review the latest approval steps and audit events for a rule.</p>
      <AdminForm id="rule-governance-form">
        <AdminField label="Rule">
          <select name="ruleId" required>
            {input.ruleSelectOptions}
          </select>
        </AdminField>
        <AdminField label="Audit log limit">
          <input name="auditLimit" type="number" min="1" max="100" step="1" value="20" />
        </AdminField>
        <AdminButton type="submit">Load history</AdminButton>
      </AdminForm>
      <AdminStatus id="rule-governance-status"></AdminStatus>
      <pre id="rule-governance-output" class="ct-admin__code-output" hidden></pre>
    </AdminPanel>
  );
  const reviewQueueResolvePath = tenantReviewQueueAdminResolvePath(input.tenantId);
  const ruleReviewQueuePanelMarkup = (
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
  const issuedBadgesFilters = input.issuedBadgesWorkspace?.filters ?? {
    recipientQuery: "",
    badgeTemplateId: "",
    state: "",
    limit: 100,
  };
  const issuedBadgesPagePath = buildIssuedBadgesPagePath(input.tenantId);
  const showIssuedBadgeLifecyclePanel =
    input.issuedBadgesWorkspace?.lifecycleAssertionId !== null &&
    input.issuedBadgesWorkspace?.lifecycleAssertionId !== undefined;
  const showIssuedBadgeRevokeForm = input.issuedBadgesWorkspace?.lifecycleMode === "revoke";
  const issuedBadgesPanelMarkup = (
    <AdminPanel id="issued-badges-panel" variant="table">
      <h2>Badge Records</h2>
      <p>Tenant-wide assertion log with direct audit and revocation actions.</p>
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
        <AdminField label="Recipient / assertion search">
          <input
            name="recipientQuery"
            type="text"
            placeholder="recipient@example.com or tenant_123:assertion_456"
            value={issuedBadgesFilters.recipientQuery}
          />
        </AdminField>
        <AdminField label="Badge template">
          <select name="badgeTemplateId">{input.templateFilterOptions}</select>
        </AdminField>
        <AdminField label="Lifecycle state">
          <select name="state">
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
          </select>
        </AdminField>
        <AdminField label="Limit">
          <input
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
      <AdminPanel as="section" variant="nested">
        <div class="ct-cluster">
          <h3>Ledger export</h3>
          <AdminStatusPill>Owner/admin only</AdminStatusPill>
        </div>
        <p>
          Download an audit-focused CSV directly from the operations workspace. This export stays
          separate from the browser-loaded ledger list and runs as a plain server-side attachment
          response.
        </p>
        <AdminForm
          id="issued-badges-export-form"
          method="get"
          action={`/v1/tenants/${input.tenantId}/assertions/ledger-export.csv`}
          className="ct-admin__form ct-admin__form--inline ct-grid"
        >
          <AdminField label="Issued from">
            <input name="issuedFrom" type="date" />
          </AdminField>
          <AdminField label="Issued to">
            <input name="issuedTo" type="date" />
          </AdminField>
          <AdminField label="Badge template">
            <select name="badgeTemplateId">
              <option value="">All templates</option>
              {input.templateFilterOptions}
            </select>
          </AdminField>
          <AdminField label="Org unit">
            <select name="orgUnitId">
              <option value="">All org units</option>
              {input.activeOrgUnitOptions}
            </select>
          </AdminField>
          <AdminField label="Lifecycle state">
            <select name="state">
              <option value="">All current states</option>
              <option value="active">active</option>
              <option value="suspended">suspended</option>
              <option value="revoked">revoked</option>
              <option value="expired">expired</option>
              <option value="pending_review">pending review</option>
            </select>
          </AdminField>
          <AdminField label="Recipient / assertion search">
            <input
              name="recipientQuery"
              type="text"
              placeholder="Filter by recipient, identifier, or assertion ID"
            />
          </AdminField>
          <AdminButton type="submit">Export ledger CSV</AdminButton>
        </AdminForm>
        <p class="ct-admin__hint">
          Synchronous CSV export is capped at 5000 rows. Narrow the filters above if the export is
          too large for direct download.
        </p>
        <p class="ct-admin__hint">
          Ancestor lineage columns reflect the current org tree only, while stable leaf attribution
          remains the historical contract for audit use.
        </p>
      </AdminPanel>
      <section
        id="issued-badge-lifecycle-panel"
        class="ct-admin__inline-action-panel ct-stack"
        hidden={!showIssuedBadgeLifecyclePanel}
      >
        <div class="ct-cluster">
          <h3 id="issued-badge-lifecycle-title">
            {showIssuedBadgeRevokeForm ? "Revoke selected badge" : "Selected badge lifecycle"}
          </h3>
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
        <pre id="issued-badge-lifecycle-output" class="ct-admin__code-output" hidden></pre>
        <AdminForm
          id="issued-badge-revoke-form"
          method="post"
          action={tenantIssuedBadgeAdminRevokePath(input.tenantId)}
          className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--issued-revoke ct-grid"
          hidden={!showIssuedBadgeRevokeForm}
        >
          <input
            name="assertionId"
            type="hidden"
            value={input.issuedBadgesWorkspace?.lifecycleAssertionId ?? ""}
          />
          <input name="recipientQuery" type="hidden" value={issuedBadgesFilters.recipientQuery} />
          <input name="badgeTemplateId" type="hidden" value={issuedBadgesFilters.badgeTemplateId} />
          <input name="state" type="hidden" value={issuedBadgesFilters.state} />
          <input name="limit" type="hidden" value={String(issuedBadgesFilters.limit)} />
          <AdminField label="Reason code">
            <select name="reasonCode" required>
              <option value="issuer_requested">issuer requested</option>
              <option value="administrative_hold">administrative hold</option>
              <option value="policy_violation">policy violation</option>
              <option value="appeal_pending">appeal pending</option>
              <option value="other">other</option>
            </select>
          </AdminField>
          <AdminField label="Reason details">
            <input
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
        {input.issuedBadgesWorkspace === undefined ? (
          <AdminEmptyTableRow colSpan={6}>
            Use the search form above to load issued badges.
          </AdminEmptyTableRow>
        ) : (
          <IssuedBadgeRows
            assertions={input.issuedBadgesWorkspace.assertions}
            auditLifecycleHrefForAssertion={(assertionId) =>
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

  return {
    ruleValueListsPanelMarkup,
    evaluateRulePanelMarkup,
    badgeStatusPanelMarkup,
    ruleGovernancePanelMarkup,
    ruleReviewQueuePanelMarkup,
    issuedBadgesPanelMarkup,
  };
};
