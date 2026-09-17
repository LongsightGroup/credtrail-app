import { parseReviewQueuePageQuery, reviewQueuePageUrl } from "../review-queue-page-query";
import { formatIsoTimestamp } from "../../utils/display-format";
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
  ReviewQueueRows,
} from "../components";
import { CtInput, CtTextarea } from "../../ui/forms";
import {
  buildReviewQueuePagePath,
  tenantReviewQueueAdminResolvePath,
} from "../review-queue-admin-helpers";
import type { InstitutionAdminReviewQueueWorkspace } from "./page-types";
type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
/** Input required to render the rule-review queue panel. */
export interface RenderRuleReviewQueuePanelInput {
  readonly tenantId: string;
  readonly reviewQueueWorkspace?: InstitutionAdminReviewQueueWorkspace;
}

/** Renders pending rule evaluations that require an administrator decision. */
export const renderRuleReviewQueuePanel = (input: RenderRuleReviewQueuePanelInput): HonoElement => {
  const reviewQueueResolvePath = tenantReviewQueueAdminResolvePath(input.tenantId);
  const query =
    input.reviewQueueWorkspace?.query ??
    parseReviewQueuePageQuery({ reviewStatus: input.reviewQueueWorkspace?.reviewStatus });
  const listHref = reviewQueuePageUrl(input.tenantId, { ...query, review: "" });
  const correction = input.reviewQueueWorkspace?.correction;
  const selectedEntry =
    input.reviewQueueWorkspace?.selectedEntry ??
    input.reviewQueueWorkspace?.entries.find(
      (entry) => entry.evaluationId === input.reviewQueueWorkspace?.selectedEvaluationId,
    );
  return (
    <AdminPanel id="rule-review-queue-panel" variant="table">
      <h2>Rule Review Queue</h2>
      <nav aria-label="Review status" class="ct-action-group">
        <a
          href={reviewQueuePageUrl(input.tenantId, {
            ...query,
            reviewStatus: "pending",
            review: "",
            cursor: undefined,
          })}
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
          href={reviewQueuePageUrl(input.tenantId, {
            ...query,
            reviewStatus: "resolved",
            review: "",
            cursor: undefined,
          })}
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
      <AdminForm method="get" action={buildReviewQueuePagePath(input.tenantId)}>
        <CtInput type="hidden" name="reviewStatus" value={query.reviewStatus} />
        <AdminField label="Learner or badge">
          <CtInput
            name="q"
            type="search"
            value={query.q}
            maxlength={320}
            placeholder="Learner email or badge name"
          />
        </AdminField>
        <AdminActions>
          <AdminButton type="submit">Search reviews</AdminButton>
          {query.q ? (
            <AdminButtonLink
              href={reviewQueuePageUrl(input.tenantId, {
                ...query,
                q: "",
                review: "",
                cursor: undefined,
              })}
              variant="quiet"
            >
              Clear search
            </AdminButtonLink>
          ) : null}
        </AdminActions>
      </AdminForm>
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
        <p id="review-decision-error" role="alert" tabindex={-1} class="ct-field__error">
          {input.reviewQueueWorkspace.listError}
        </p>
      ) : input.reviewQueueWorkspace?.listNotice !== null &&
        input.reviewQueueWorkspace?.listNotice !== undefined &&
        input.reviewQueueWorkspace.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.reviewQueueWorkspace.listNotice}</AdminStatus>
      ) : null}
      {correction && selectedEntry?.reviewStatus !== "pending" ? (
        <section class="ct-stack" aria-label="Unsaved decision note">
          <h3>Your unsaved decision note</h3>
          <p>
            This review is no longer available for a decision. Copy your note before leaving this
            page.
          </p>
          <AdminField label="Unsaved note">
            <CtTextarea readonly rows={4} value={correction.comment} />
          </AdminField>
        </section>
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
              {selectedEntry.decision === "issue" && selectedEntry.assertionId ? (
                <AdminButtonLink
                  href={`/tenants/${encodeURIComponent(input.tenantId)}/admin/operations/issued-badges/${encodeURIComponent(selectedEntry.assertionId)}/evidence?${new URLSearchParams({ returnTo: reviewQueuePageUrl(input.tenantId, { ...query, review: selectedEntry.evaluationId }) })}`}
                >
                  View issued badge
                </AdminButtonLink>
              ) : null}
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
                id="review-decision-form"
                method="post"
                action={reviewQueueResolvePath}
                className="ct-admin__form ct-admin__setup-form ct-stack"
              >
                <CtInput type="hidden" name="q" value={query.q} />
                <CtInput type="hidden" name="reviewStatus" value={query.reviewStatus} />
                <CtInput
                  type="hidden"
                  name="cursor"
                  value={query.cursor ? JSON.stringify(query.cursor) : ""}
                />
                <CtInput type="hidden" name="evaluationId" value={selectedEntry.evaluationId} />
                <AdminField label="Decision note (optional)">
                  <CtTextarea
                    name="comment"
                    maxlength={2000}
                    rows={3}
                    value={correction?.comment ?? ""}
                  />
                </AdminField>
                <p id="review-note-state" role="status"></p>
                <AdminActions>
                  <AdminButton type="submit" name="decision" value="issue">
                    Issue badge
                  </AdminButton>
                  <AdminButton type="submit" name="decision" value="dismiss" variant="secondary">
                    Dismiss review
                  </AdminButton>
                  <AdminButtonLink href={listHref} variant="quiet">
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
              query.q
                ? "No reviews match this learner or badge. Change or clear your search."
                : input.reviewQueueWorkspace.reviewStatus === "resolved"
                  ? "No resolved reviews yet."
                  : "No pending review queue entries."
            }
            resolveActionPath={reviewQueueResolvePath}
            reviewHrefForEntry={(entry) =>
              `${reviewQueuePageUrl(input.tenantId, { ...query, review: entry.evaluationId })}#review-decision-panel`
            }
          />
        )}
      </AdminTable>
      <nav aria-label="Review pages" class="ct-action-group">
        {input.reviewQueueWorkspace?.newerHref ? (
          <AdminButtonLink href={input.reviewQueueWorkspace.newerHref}>
            Newer reviews
          </AdminButtonLink>
        ) : null}
        {input.reviewQueueWorkspace?.olderHref ? (
          <AdminButtonLink href={input.reviewQueueWorkspace.olderHref}>
            Older reviews
          </AdminButtonLink>
        ) : null}
        {query.cursor ? (
          <AdminButtonLink
            href={reviewQueuePageUrl(input.tenantId, { ...query, review: "", cursor: undefined })}
            variant="quiet"
          >
            Latest reviews
          </AdminButtonLink>
        ) : null}
      </nav>
    </AdminPanel>
  );
};
