import { AdminButton, AdminForm } from "./components";
import { CtInput } from "../ui/forms";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  issuanceEmailOutcomeMessage,
  type IssuanceEmailOutcome,
} from "../notifications/issuance-email-outcome";
import { CopyPublicBadgeLink } from "./copy-public-badge-link";

export interface NotificationRetry {
  action: string;
  failedAttemptId: string;
}

export const IssuanceNotification = (input: {
  readonly retry?: NotificationRetry | undefined;
  readonly outcome: IssuanceEmailOutcome;
  readonly publicBadgeUrl: string;
}): HtmlEscapedString | Promise<HtmlEscapedString> => (
  <section aria-label="Email notification" class="ct-stack">
    <h2>Email notification</h2>
    <p>{issuanceEmailOutcomeMessage(input.outcome)}</p>
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
