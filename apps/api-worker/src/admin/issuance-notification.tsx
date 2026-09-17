import type { HtmlEscapedString } from "hono/utils/html";
import {
  issuanceEmailOutcomeMessage,
  type IssuanceEmailOutcome,
} from "../notifications/issuance-email-outcome";
import { CopyPublicBadgeLink } from "./copy-public-badge-link";

export const IssuanceNotification = (input: {
  readonly outcome: IssuanceEmailOutcome;
  readonly publicBadgeUrl: string;
}): HtmlEscapedString | Promise<HtmlEscapedString> => (
  <section aria-label="Email notification" class="ct-stack">
    <h2>Email notification</h2>
    <p>{issuanceEmailOutcomeMessage(input.outcome)}</p>
    {input.outcome === "accepted" ? null : <p>Share this link with the learner.</p>}
    <CopyPublicBadgeLink publicBadgeUrl={input.publicBadgeUrl} />
  </section>
);
