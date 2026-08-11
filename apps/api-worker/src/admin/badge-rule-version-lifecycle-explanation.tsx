import type { HtmlEscapedString } from "hono/utils/html";
import { AdminPanel } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

/** Explains the approval, activation, and issued-badge effects shared by version review pages. */
export const BadgeRuleVersionLifecycleExplanation = (): HonoElement => {
  return (
    <AdminPanel className="ct-admin__rule-version-lifecycle-note">
      <h2>How versions work</h2>
      <p>
        CredTrail can keep multiple saved and approved versions, but only one version can issue new
        badges at a time. Approval preserves a version and makes it eligible for activation;
        approval alone does not replace the active version.
      </p>
      <p>
        Activating a new version replaces the current active version and moves that earlier version
        to Previous. Earlier versions remain read-only and cannot be reactivated directly.
      </p>
      <p>
        Badges already issued keep the rule version recorded when they were awarded and remain
        unchanged. Activating a different rule version never retracts those badges automatically.
      </p>
    </AdminPanel>
  );
};
