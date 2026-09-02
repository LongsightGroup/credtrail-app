import type { AutomatedBadgeRuleEvaluationStatusRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../utils/display-format";
import { AdminButton, AdminPanel, AdminStatusPill } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const statusLabel = (status: AutomatedBadgeRuleEvaluationStatusRecord["status"]): string => {
  switch (status) {
    case "queued":
      return "Queued";
    case "running":
      return "Checking learners";
    case "succeeded":
      return "Completed";
    case "retrying":
      return "Retrying";
    case "failed":
      return "Needs attention";
    case "noop":
      return "No check needed";
  }
};

const statusSummary = (status: AutomatedBadgeRuleEvaluationStatusRecord): string => {
  if (status.failureTag === "invalid_command") {
    return "CredTrail could not start this check because its saved command was invalid. Run the evaluation again.";
  }

  if (status.failureTag === "provider_unavailable") {
    return "CredTrail could not read the connected LMS. Check the LMS connection, then run the evaluation again.";
  }

  if (status.failureTag === "processing_error") {
    return "CredTrail could not finish this check. Run it again; if it keeps failing, contact support.";
  }

  switch (status.reasonTag) {
    case "learner_evaluation_unavailable":
      return "Some LMS facts were unavailable. CredTrail will retry this check automatically.";
    case "instructor_confirmation_required":
      return "This version requires an instructor decision, so automatic evaluation did not run.";
    case "rule_version_inactive":
    case "rule_version_changed":
      return "This command no longer belongs to the active rule version, so no awards were queued.";
    case "rule_or_version_not_found":
      return "The rule version was no longer available when this command ran.";
    case null:
      break;
  }

  switch (status.status) {
    case "queued":
      return "CredTrail will check eligible learners through the durable issuance queue.";
    case "running":
      return "CredTrail is reading LMS facts and checking this version's requirements.";
    case "succeeded":
      return "CredTrail finished checking the current LMS facts for this version.";
    case "retrying":
      return "CredTrail will retry this check automatically.";
    case "failed":
      return "CredTrail could not finish this check.";
    case "noop":
      return "No awards were evaluated for this command.";
  }
};

const statusTone = (
  status: AutomatedBadgeRuleEvaluationStatusRecord["status"],
): "success" | "warning" | "error" | "info" => {
  switch (status) {
    case "succeeded":
      return "success";
    case "retrying":
      return "warning";
    case "failed":
      return "error";
    case "queued":
    case "running":
    case "noop":
      return "info";
  }
};

const evaluationCounts = (status: AutomatedBadgeRuleEvaluationStatusRecord): HonoElement | null => {
  if (status.candidateLearnerCount === null) {
    return null;
  }

  return (
    <dl class="ct-admin__rule-evaluation-metrics">
      <div>
        <dt>Learners checked</dt>
        <dd>{String(status.candidateLearnerCount)}</dd>
      </div>
      <div>
        <dt>Learners matched</dt>
        <dd>{String(status.matchedLearnerCount ?? 0)}</dd>
      </div>
      <div>
        <dt>Awards queued</dt>
        <dd>{String(status.issueJobsEnqueued ?? 0)}</dd>
      </div>
      <div>
        <dt>Already awarded</dt>
        <dd>{String(status.learnersAlreadyIssued ?? 0)}</dd>
      </div>
      <div>
        <dt>Missing email</dt>
        <dd>{String(status.learnersMissingEmail ?? 0)}</dd>
      </div>
      <div>
        <dt>LMS facts unavailable</dt>
        <dd>{String(status.learnersUnavailable ?? 0)}</dd>
      </div>
      <div>
        <dt>Identity conflicts</dt>
        <dd>{String(status.learnerIdentityConflicts ?? 0)}</dd>
      </div>
    </dl>
  );
};

/** Renders the latest safe automatic-evaluation state and its durable retry action. */
export const BadgeRuleAutomatedEvaluationStatus = (input: {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly status: AutomatedBadgeRuleEvaluationStatusRecord | null;
  readonly canRunNow: boolean;
  readonly requestId: string;
}): HonoElement => {
  const action = `/tenants/${encodeURIComponent(input.tenantId)}/admin/rules/${encodeURIComponent(input.ruleId)}/versions/${encodeURIComponent(input.versionId)}/run-evaluation`;

  return (
    <AdminPanel as="section" className="ct-admin__rule-evaluation-status">
      <div class="ct-admin__rule-evaluation-heading">
        <div>
          <p class="ct-admin__eyebrow">Issuance health</p>
          <h2>Automatic evaluation</h2>
        </div>
        {input.status === null ? null : (
          <AdminStatusPill tone={statusTone(input.status.status)}>
            {statusLabel(input.status.status)}
          </AdminStatusPill>
        )}
      </div>

      {input.status === null ? (
        <p class="ct-admin__rule-evaluation-summary">
          No automatic evaluation has been recorded for this version yet.
        </p>
      ) : (
        <>
          <p class="ct-admin__rule-evaluation-summary">{statusSummary(input.status)}</p>
          <p class="ct-admin__rule-evaluation-time">
            Last updated {formatIsoTimestamp(input.status.updatedAt)}
          </p>
          {evaluationCounts(input.status)}
        </>
      )}

      {input.canRunNow ? (
        <form method="post" action={action} class="ct-admin__rule-evaluation-action">
          <input type="hidden" name="requestId" value={input.requestId} />
          <AdminButton type="submit" variant="secondary">
            Run evaluation now
          </AdminButton>
          <p>Queues a fresh check. Existing award safeguards still prevent duplicates.</p>
        </form>
      ) : null}
    </AdminPanel>
  );
};
