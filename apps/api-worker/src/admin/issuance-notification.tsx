import { AdminButton, AdminForm } from "./components";
import { CtInput } from "../ui/forms";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  issuanceEmailOutcomeMessage,
  type IssuanceEmailOutcome,
  type loadIssuanceEmailHistory,
} from "../notifications/issuance-email-outcome";
import { formatIsoTimestamp } from "../utils/display-format";
import { CopyPublicBadgeLink } from "./copy-public-badge-link";

export interface NotificationRetry {
  action: string;
  failedAttemptId: string;
}

const historyLabels: Record<IssuanceEmailOutcome, string> = {
  accepted: "Accepted by email provider",
  pending: "Notification retry started",
  failed: "Notification send failed",
  disabled: "Email notifications were turned off",
  suppressed: "No notification was requested",
  not_applicable: "No email recipient",
  not_configured: "Email was not configured",
  unrecorded: "Outcome unavailable",
};

export const IssuanceNotification = (input: {
  readonly history?: Awaited<ReturnType<typeof loadIssuanceEmailHistory>> | undefined;
  readonly retry?: NotificationRetry | undefined;
  readonly outcome: IssuanceEmailOutcome;
  readonly publicBadgeUrl: string;
}): HtmlEscapedString | Promise<HtmlEscapedString> => (
  <section aria-label="Email notification" class="ct-stack">
    <h2>Email notification</h2>
    <p>{issuanceEmailOutcomeMessage(input.outcome)}</p>
    {input.history?.latest.occurredAt ? (
      <p>
        Latest notification update:{" "}
        <time datetime={input.history.latest.occurredAt}>
          {formatIsoTimestamp(input.history.latest.occurredAt)} UTC
        </time>
        .
      </p>
    ) : null}
    {input.history && input.history.events.length > 0 ? (
      <details>
        <summary>Notification history</summary>
        <p>Newest updates first. Provider acceptance does not confirm delivery to the learner.</p>
        {input.history.hasMore ? <p>Showing the 20 most recent updates.</p> : null}
        <ol>
          {input.history.events.map((event) => (
            <li>
              <time datetime={event.occurredAt ?? undefined}>
                {event.occurredAt
                  ? `${formatIsoTimestamp(event.occurredAt)} UTC`
                  : "Time unavailable"}
              </time>
              <p>{historyLabels[event.outcome]}</p>
            </li>
          ))}
        </ol>
      </details>
    ) : null}
    {input.outcome === "accepted" ? null : <p>Share this link with the learner.</p>}
    {input.outcome === "failed" && input.retry ? (
      <AdminForm method="post" action={input.retry.action}>
        <CtInput type="hidden" name="failedAttemptId" value={input.retry.failedAttemptId} />
        <p>Retry sends the notification for this credential. It does not issue another badge.</p>
        <AdminButton type="submit">Retry notification email</AdminButton>
      </AdminForm>
    ) : null}
    <CopyPublicBadgeLink publicBadgeUrl={input.publicBadgeUrl} />
  </section>
);
